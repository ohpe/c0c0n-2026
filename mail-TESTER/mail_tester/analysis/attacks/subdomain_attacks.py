"""Subdomain spoofing attack surface analysis."""
from __future__ import annotations

from mail_tester.analysis.attacks.models import Finding, Posture
from mail_tester.dns_utils import make_resolver, resolve_txt

PROBE_SUBDOMAINS = ["mail", "email", "newsletter", "notifications", "support", "info"]


async def analyze_subdomain_spoofing(
    domain: str, posture: Posture
) -> list[Finding]:
    """Probe common subdomains for missing SPF + weak subdomain DMARC policy."""
    if not posture.has_dmarc:
        return []  # Already flagged as critical in DMARC analysis

    sp = posture.dmarc_sp
    resolver = make_resolver()
    vulnerable: list[str] = []

    for sub in PROBE_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        txt_records = await resolve_txt(fqdn, resolver)
        has_spf = any(r.startswith("v=spf1") for r in txt_records)
        if not has_spf and sp in ("none", ""):
            vulnerable.append(fqdn)

    if vulnerable:
        return [Finding(
            severity="high" if sp == "none" else "medium",
            title=(
                f"Spoofable subdomains: "
                f"{', '.join(vulnerable[:3])}"
                f"{'...' if len(vulnerable) > 3 else ''}"
            ),
            description=(
                "These subdomains have no SPF record and the DMARC subdomain "
                f"policy (sp={sp}) won't block spoofed emails from them."
            ),
            exploit=(
                f"Send as user@{vulnerable[0]}. No SPF to fail, sp={sp} won't reject."
            ),
            remediation=(
                f"Set sp=reject in the parent DMARC record. "
                f'Add wildcard SPF: *.{domain} IN TXT "v=spf1 -all"'
            ),
        )]

    return []
