"""Envelope sender (Return-Path vs From) attack surface analysis."""
from __future__ import annotations

from mail_tester.analysis.attacks.models import Finding, Posture
from mail_tester.models import CheckResult, CheckStatus


def analyze_envelope(
    domain: str,
    envelope_check: CheckResult | None,
    posture: Posture,
) -> list[Finding]:
    """Return envelope-mismatch findings for *domain*."""
    if not envelope_check:
        return []

    findings: list[Finding] = []
    envelope_domain = envelope_check.extra.get("domain", "")

    if (
        envelope_domain
        and envelope_domain.lower() != domain.lower()
        and envelope_check.status == CheckStatus.PASS
    ):
        exploitable = posture.dmarc_aspf == "r"
        findings.append(Finding(
            severity="info" if not exploitable else "medium",
            title=(
                f"Envelope sender ({envelope_domain}) differs from From ({domain})"
            ),
            description=(
                f"Return-Path uses {envelope_domain}, From uses {domain}. "
                + ("With aspf=r, this subdomain envelope sender satisfies DMARC alignment."
                   if exploitable
                   else "With aspf=s, this would NOT satisfy DMARC alignment.")
            ),
            exploit=(
                "Use any subdomain as envelope sender to pass both SPF and DMARC alignment."
                if exploitable
                else "Strict SPF alignment (aspf=s) prevents exploiting this mismatch."
            ),
            remediation=(
                "Set aspf=s for strict alignment."
                if exploitable
                else "aspf=s is already enforced (or should be)."
            ),
        ))

    return findings
