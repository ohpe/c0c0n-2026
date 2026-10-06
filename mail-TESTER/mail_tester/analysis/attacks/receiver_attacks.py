"""Receiving server behavior analysis."""
from __future__ import annotations

from mail_tester.analysis.attacks.models import Finding, Posture, get_check
from mail_tester.models import CheckResult, CheckStatus


def analyze_receiving_server(
    checks: list[CheckResult], posture: Posture
) -> list[Finding]:
    """Check if the receiving server evaluated envelope sender instead of From."""
    orig_spf = get_check(checks, "ORIGINAL_SPF")
    our_spf = get_check(checks, "SPF")
    our_dmarc = get_check(checks, "DMARC")

    if (
        our_spf
        and our_spf.status == CheckStatus.FAIL
        and our_dmarc
        and our_dmarc.status == CheckStatus.FAIL
        and orig_spf
        and orig_spf.status == CheckStatus.PASS
    ):
        aspf_desc = "s (strict)" if posture.dmarc_aspf == "s" else "r (relaxed)"
        would = "would not" if posture.dmarc_aspf == "s" else "does"
        return [Finding(
            severity="info",
            title="Receiving server evaluated envelope sender, not From domain",
            description=(
                f"The MTA checked SPF against the Return-Path domain (passed), "
                f"not the From domain (failed). With aspf={aspf_desc}, "
                f"this {would} satisfy DMARC alignment."
            ),
            exploit=(
                "This gap is exploitable: use a subdomain envelope sender "
                "to pass both SPF and DMARC."
                if posture.dmarc_aspf == "r"
                else "Not exploitable with strict SPF alignment (aspf=s)."
            ),
            remediation="Set aspf=s in DMARC to require exact From-domain SPF match.",
        )]

    return []
