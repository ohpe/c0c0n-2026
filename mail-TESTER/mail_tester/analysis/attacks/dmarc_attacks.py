"""DMARC-related attack surface analysis."""
from __future__ import annotations

from mail_tester.analysis.attacks.models import Finding, Posture
from mail_tester.models import CheckResult


def analyze_dmarc(
    domain: str,
    dmarc_check: CheckResult | None,
    posture: Posture,
) -> list[Finding]:
    """Return DMARC-related attack findings for *domain*."""
    findings: list[Finding] = []

    if not posture.has_dmarc:
        findings.append(Finding(
            severity="critical",
            title="No DMARC record",
            description=(
                f"{domain} has no DMARC record. Without DMARC, receivers decide "
                "on their own what to do with failed SPF/DKIM -- and many still deliver."
            ),
            exploit=(
                f"Spoof emails from {domain} freely. Even if SPF fails, "
                "there is no policy to reject."
                + (f" SPF {posture.spf_qualifier} provides some signal but "
                   "without DMARC it is advisory only." if posture.has_spf else "")
            ),
            remediation=(
                f'Add: _dmarc.{domain} IN TXT "v=DMARC1; p=reject; adkim=s; '
                f'aspf=s; rua=mailto:dmarc@{domain}"'
            ),
        ))
        return findings

    if posture.dmarc_policy == "none":
        findings.append(Finding(
            severity="high",
            title="DMARC policy is p=none (monitor only)",
            description=(
                "p=none means failed emails are NOT rejected. The domain owner "
                "sees reports but can't stop spoofing."
            ),
            exploit=(
                f"Send spoofed emails from {domain}. Authentication can fail "
                "completely -- p=none won't block delivery."
            ),
            remediation="Move to p=quarantine or p=reject.",
        ))

    if posture.dmarc_policy == "quarantine":
        findings.append(Finding(
            severity="low",
            title="DMARC policy is p=quarantine",
            description="Failed emails go to spam/junk, not outright rejected.",
            exploit=(
                "Spoofed emails land in spam. Social engineering "
                '("check your spam") may still work.'
            ),
            remediation="Upgrade to p=reject.",
        ))

    if posture.dmarc_adkim == "r" and posture.dmarc_enforcing:
        findings.append(Finding(
            severity="medium",
            title="DMARC DKIM alignment is relaxed (adkim=r)",
            description=(
                f"DKIM signed by any subdomain of {domain} satisfies DMARC. "
                f"E.g., d=sub.{domain} aligns with From: @{domain}."
            ),
            exploit=(
                f"If you can get DKIM signing on any subdomain (e.g., via a "
                f"delegated service on sub.{domain}), it passes DMARC for "
                f"the parent domain."
            ),
            remediation="Set adkim=s for strict alignment.",
        ))

    if posture.dmarc_aspf == "r" and posture.dmarc_enforcing:
        findings.append(Finding(
            severity="medium",
            title="DMARC SPF alignment is relaxed (aspf=r)",
            description=(
                f"Envelope sender on any subdomain satisfies SPF alignment. "
                f"Return-Path: @sub.{domain} aligns with From: @{domain}."
            ),
            exploit=(
                "Use a subdomain with permissive SPF as envelope sender. "
                "If it passes SPF, DMARC alignment is satisfied without needing DKIM."
            ),
            remediation="Set aspf=s for strict alignment.",
        ))

    if posture.dmarc_pct < 100:
        bypass_pct = 100 - posture.dmarc_pct
        findings.append(Finding(
            severity="medium",
            title=f"DMARC only applies to {posture.dmarc_pct}% of emails",
            description=(
                f"{bypass_pct}% of failing emails bypass the DMARC policy "
                "entirely (treated as p=none)."
            ),
            exploit=(
                f"Send enough spoofed emails -- {bypass_pct}% get through "
                "without enforcement."
            ),
            remediation="Set pct=100.",
        ))

    if posture.dmarc_sp == "none" and posture.dmarc_policy != "none":
        findings.append(Finding(
            severity="high",
            title=(
                f"Subdomain policy is sp=none while main domain is "
                f"p={posture.dmarc_policy}"
            ),
            description=f"Subdomains of {domain} have NO DMARC enforcement.",
            exploit=f"Spoof from sub.{domain}, anything.{domain}. These have p=none.",
            remediation="Set sp=reject or remove sp= to inherit the main policy.",
        ))

    return findings
