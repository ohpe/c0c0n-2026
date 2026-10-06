"""DKIM-related attack surface analysis."""
from __future__ import annotations

from mail_tester.analysis.attacks.models import Finding, Posture


def analyze_dkim(domain: str, posture: Posture) -> list[Finding]:
    """Return DKIM-related attack findings for *domain*."""
    if not posture.has_dkim and not posture.dkim_valid_at_delivery:
        sev = "high" if not posture.dmarc_enforcing else "medium"
        return [Finding(
            severity=sev,
            title="No DKIM signature",
            description=(
                "No DKIM signature found. DMARC can only rely on SPF alignment."
                + (" With DMARC enforcing, this means SPF MUST pass and align "
                   "-- reducing flexibility." if posture.dmarc_enforcing else "")
            ),
            exploit=(
                "Content can be modified in transit without detection. "
                "DMARC relies entirely on SPF."
            ),
            remediation="Configure DKIM signing on all outbound mail servers.",
        )]
    return []
