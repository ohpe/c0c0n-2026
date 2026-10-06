"""SPF-related attack surface analysis."""
from __future__ import annotations

import ipaddress
import re

import dns.asyncresolver

from mail_tester.analysis.attacks.models import Finding, Posture
from mail_tester.dns_utils import make_resolver, resolve_txt

# Per-service exploitability details.
# verification: "dns" = must add DNS record, "email" = verify via email,
#               "admin" = enterprise admin, "none" = no check.
# shared_ips: True = IPs shared across all customers.
KNOWN_SERVICES: dict[str, dict] = {
    "amazonses.com": {
        "name": "Amazon SES",
        "verification": "dns",
        "shared_ips": True,
        "difficulty": "hard",
        "notes": (
            "Requires domain verification via DNS TXT record (you need DNS access). "
            "However, SES uses SHARED IP pools -- other SES customers' IPs are in the "
            "same SPF range. If an attacker already uses SES for their own domain, their "
            "sending IPs may overlap with the target's SPF include."
        ),
    },
    "_spf.google.com": {
        "name": "Google Workspace",
        "verification": "dns",
        "shared_ips": True,
        "difficulty": "hard",
        "notes": (
            "Requires domain verification (DNS TXT/CNAME). Google's IPs are shared across "
            "all Workspace tenants. Cannot directly spoof, but shared IP ranges mean SPF "
            "passes for any Google-sent email regardless of sender domain."
        ),
    },
    "spf.protection.outlook.com": {
        "name": "Microsoft 365",
        "verification": "dns",
        "shared_ips": True,
        "difficulty": "hard",
        "notes": (
            "Requires domain verification (DNS TXT). M365 uses shared outbound IPs across "
            "tenants. An attacker with any M365 account sends from the same IP pool. "
            "The SPF check (IP-based) passes, but M365 also adds its own DKIM."
        ),
    },
    "sendgrid.net": {
        "name": "SendGrid",
        "verification": "dns",
        "shared_ips": True,
        "difficulty": "medium",
        "notes": (
            "Free tier available (100 emails/day). Requires domain authentication via "
            "CNAME records for full deliverability, BUT emails can be sent without it "
            "(just worse reputation). Shared IPs across free-tier users. "
            "Historically exploited in phishing campaigns."
        ),
    },
    "spf.mtasv.net": {
        "name": "Postmark",
        "verification": "dns",
        "shared_ips": True,
        "difficulty": "hard",
        "notes": (
            "Requires domain verification. Postmark is stricter than most -- they "
            "review accounts and block abuse. Shared IPs but low abuse potential."
        ),
    },
    "mktomail.com": {
        "name": "Marketo",
        "verification": "admin",
        "shared_ips": True,
        "difficulty": "medium",
        "notes": (
            "Enterprise marketing platform. Domain setup requires admin. However, "
            "shared IP pools mean ALL Marketo customers' outbound IPs are in the "
            "SPF range. If an attacker has a Marketo account (or compromises one), "
            "they send from authorized IPs."
        ),
    },
    "cust-spf.exacttarget.com": {
        "name": "Salesforce Marketing Cloud",
        "verification": "admin",
        "shared_ips": True,
        "difficulty": "medium",
        "notes": (
            "Enterprise platform with shared outbound infrastructure. All SFMC "
            "customers share IP pools. Domain setup requires admin access, but "
            "the shared nature means any SFMC customer's emails come from "
            "IPs in this SPF range."
        ),
    },
    "mail.zendesk.com": {
        "name": "Zendesk",
        "verification": "admin",
        "shared_ips": True,
        "difficulty": "low-medium",
        "notes": (
            "Support platform with SHARED outbound IPs across ALL customers. "
            "Zendesk sends emails on behalf of companies using it. Any Zendesk "
            "customer's outbound support emails originate from the same IP pool. "
            "An attacker with a Zendesk trial can send from IPs that pass SPF. "
            "The envelope sender is typically controlled by Zendesk."
        ),
    },
    "mailsenders.netsuite.com": {
        "name": "NetSuite",
        "verification": "admin",
        "shared_ips": True,
        "difficulty": "medium",
        "notes": (
            "Oracle ERP platform with shared outbound IPs. All NetSuite instances "
            "send from the same IP pool. Requires enterprise access."
        ),
    },
}


async def analyze_spf(
    domain: str,
    spf_record: str | None,
    posture: Posture,
) -> list[Finding]:
    """Return SPF-related attack findings for *domain*."""
    findings: list[Finding] = []
    resolver = make_resolver()

    if not spf_record:
        txt_records = await resolve_txt(domain, resolver)
        has_spf = any(r.startswith("v=spf1") for r in txt_records)
        if not has_spf:
            sev = "critical" if not posture.dmarc_enforcing else "medium"
            mitigated = ""
            if posture.dmarc_enforcing:
                mitigated = (
                    f" However, DMARC p={posture.dmarc_policy} may still "
                    f"block delivery if DKIM also fails."
                )
            findings.append(Finding(
                severity=sev,
                title="No SPF record",
                description=(
                    f"{domain} has no SPF record. Anyone can send email from "
                    f"any IP claiming to be this domain.{mitigated}"
                ),
                exploit=(
                    f"Send email with MAIL FROM: <anything@{domain}> from any IP."
                    + (" SPF will not fail (no record), but DMARC may still "
                       "block if DKIM also fails." if posture.dmarc_enforcing else "")
                ),
                remediation=(
                    f'Add a TXT record: {domain} IN TXT '
                    f'"v=spf1 <authorized-sources> -all"'
                ),
            ))
            return findings

    if not spf_record:
        return findings

    _check_all_qualifier(spf_record, posture, findings)
    _check_broad_ip_ranges(spf_record, domain, posture, findings)
    _check_include_count(spf_record, posture, findings)
    await _check_shared_services(spf_record, domain, posture, resolver, findings)

    return findings


# ── Helpers ──────────────────────────────────────────────────────────


def _check_all_qualifier(
    spf_record: str, posture: Posture, findings: list[Finding]
) -> None:
    tail = spf_record.rstrip()
    if tail.endswith("~all"):
        sev = "medium" if not posture.dmarc_enforcing else "low"
        findings.append(Finding(
            severity=sev,
            title="SPF uses ~all (softfail) instead of -all",
            description=(
                "Softfail (~all) means unauthorized IPs get a weak rejection. "
                "Most servers still accept these."
                + (f" DMARC p={posture.dmarc_policy} provides additional enforcement."
                   if posture.dmarc_enforcing else "")
            ),
            exploit=(
                "Send from an unauthorized IP. SPF softfails."
                + (f" With DMARC p={posture.dmarc_policy}, this alone may not "
                   "deliver -- you would also need to bypass DKIM alignment."
                   if posture.dmarc_enforcing else " Most servers accept softfails.")
            ),
            remediation="Change ~all to -all for strict rejection.",
        ))
    elif tail.endswith("?all"):
        sev = "high" if not posture.dmarc_enforcing else "medium"
        findings.append(Finding(
            severity=sev,
            title="SPF uses ?all (neutral) -- effectively no protection",
            description="Neutral means SPF makes no assertion. It's as good as no SPF.",
            exploit="Send from any IP. SPF returns neutral.",
            remediation="Change ?all to -all.",
        ))
    elif tail.endswith("+all"):
        findings.append(Finding(
            severity="critical",
            title="SPF uses +all -- authorizes EVERYONE",
            description="Explicitly authorizes every IP on the internet.",
            exploit=(
                "Send from any IP. SPF passes. Even with DMARC, "
                "SPF alignment will be satisfied."
            ),
            remediation="This is almost certainly a misconfiguration. Change +all to -all.",
        ))


def _check_broad_ip_ranges(
    spf_record: str, domain: str, posture: Posture, findings: list[Finding]
) -> None:
    for token in spf_record.split():
        if token.startswith("ip4:") or token.startswith("+ip4:"):
            cidr = token.split(":", 1)[1]
            if "/" in cidr:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if net.prefixlen <= 16:
                        sev = "high" if not posture.dkim_blocks_spf_abuse else "medium"
                        findings.append(Finding(
                            severity=sev,
                            title=(
                                f"SPF authorizes very large IP range: "
                                f"{cidr} ({net.num_addresses:,} IPs)"
                            ),
                            description=(
                                f"Any server in this range can pass SPF for {domain}."
                            ),
                            exploit=(
                                f"Find a server in {cidr} (VPS, cloud)."
                                + (" DMARC may block if DKIM does not align."
                                   if posture.dmarc_enforcing else "")
                            ),
                            remediation="Narrow to specific IPs (/28 or /32).",
                        ))
                except ValueError:
                    pass


def _check_include_count(
    spf_record: str, posture: Posture, findings: list[Finding]
) -> None:
    includes = re.findall(r"include:(\S+)", spf_record)
    if len(includes) >= 5:
        findings.append(Finding(
            severity="medium",
            title=f"SPF has {len(includes)} include directives -- large attack surface",
            description=(
                "Each include delegates authority to third-party infrastructure. "
                f"Includes: {', '.join(includes)}"
            ),
            exploit=(
                "Send through any included service to pass SPF."
                + (" But with DMARC adkim=s, you also need DKIM signing with "
                   "the domain key -- which limits the attack."
                   if posture.dkim_blocks_spf_abuse else "")
            ),
            remediation="Minimize includes. Remove unused services.",
        ))


async def _check_shared_services(
    spf_record: str,
    domain: str,
    posture: Posture,
    resolver: dns.asyncresolver.Resolver,
    findings: list[Finding],
) -> None:
    all_includes = await _collect_all_includes(spf_record, resolver)
    matched: list[tuple[str, dict]] = []
    for inc_domain in all_includes:
        for pattern, info in KNOWN_SERVICES.items():
            if pattern in inc_domain or inc_domain in pattern:
                matched.append((inc_domain, info))
                break

    if not matched:
        return

    # DMARC context string
    if posture.dkim_blocks_spf_abuse:
        dmarc_ctx = (
            f"DMARC p={posture.dmarc_policy} with adkim=s blocks SPF-only attacks -- "
            "you also need DKIM signing with the target domain key."
        )
        base_sev = "low"
    elif posture.dmarc_enforcing and posture.dmarc_aspf == "s":
        dmarc_ctx = (
            f"DMARC p={posture.dmarc_policy} with aspf=s requires exact domain match "
            "on envelope sender, limiting exploitation through these services."
        )
        base_sev = "low"
    elif posture.dmarc_enforcing and posture.dmarc_aspf == "r":
        dmarc_ctx = (
            f"DMARC p={posture.dmarc_policy} enforces, but aspf=r (relaxed) means "
            "subdomain envelope senders still align -- the key attack path."
        )
        base_sev = "medium"
    else:
        dmarc_ctx = (
            "DMARC is "
            + (f"p={posture.dmarc_policy}" if posture.has_dmarc else "missing")
            + ", so SPF pass alone is sufficient for delivery."
        )
        base_sev = "high"

    for inc_domain, svc in matched:
        difficulty = svc["difficulty"]
        if base_sev == "low":
            sev = "low"
        elif difficulty == "hard" and base_sev == "medium":
            sev = "low"
        elif difficulty == "hard":
            sev = "medium"
        elif difficulty.startswith("low"):
            sev = base_sev
        else:
            sev = base_sev

        verify_note = {
            "dns": "Requires DNS record to verify domain ownership (you need DNS access).",
            "email": "Requires email verification (postmaster@domain or admin@domain).",
            "admin": "Requires admin/enterprise account setup.",
            "none": "No domain verification required.",
        }.get(svc["verification"], "Unknown verification.")

        shared_note = (
            "Yes -- all customers share the same outbound IP pool."
            if svc["shared_ips"]
            else "No -- dedicated IPs."
        )

        exploit_parts = [f"Difficulty: {difficulty.upper()}."]
        if svc["shared_ips"]:
            exploit_parts.append(
                "SPF is IP-based: the include authorizes IP ranges, not domains."
            )
        exploit_parts.append(
            f"Even without registering the target domain on this service, "
            f"any customer sending through {svc['name']} uses IPs in this SPF range."
        )
        if posture.dmarc_aspf == "r" and posture.dmarc_enforcing:
            exploit_parts.append(
                "With aspf=r, a subdomain envelope sender aligns with DMARC."
            )
        if not posture.dmarc_enforcing:
            exploit_parts.append("Without DMARC enforcement, SPF pass is sufficient.")
        if base_sev == "low":
            exploit_parts.append("DMARC strict alignment blocks this path.")

        findings.append(Finding(
            severity=sev,
            title=f"SPF includes {svc['name']} ({inc_domain})",
            description=(
                f"{svc['notes']} "
                f"Verification: {verify_note} "
                f"Shared IPs: {shared_note} "
                f"DMARC context: {dmarc_ctx}"
            ),
            exploit=" ".join(exploit_parts),
            remediation=(
                f"If {svc['name']} is not in use, remove the include. "
                f"If it is used, configure DKIM signing through the service and set "
                f"DMARC to strict alignment (adkim=s, aspf=s). "
                f"Consider dedicated IPs if the service offers them."
            ),
        ))


async def _collect_all_includes(
    spf_record: str,
    resolver: dns.asyncresolver.Resolver,
    depth: int = 0,
    seen: set[str] | None = None,
) -> list[str]:
    if seen is None:
        seen = set()
    if depth > 5:
        return []

    result: list[str] = []
    for token in spf_record.split():
        if token.startswith("include:") or token.startswith("+include:"):
            inc_domain = token.split(":", 1)[1]
            if inc_domain in seen:
                continue
            seen.add(inc_domain)
            result.append(inc_domain)
            try:
                answers = await resolver.resolve(inc_domain, "TXT")
                for rdata in answers:
                    txt = b"".join(rdata.strings).decode("ascii", "replace")
                    if txt.startswith("v=spf1"):
                        result.extend(
                            await _collect_all_includes(txt, resolver, depth + 1, seen)
                        )
                        break
            except Exception:
                pass
    return result
