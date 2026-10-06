"""Attack surface analysis orchestrator.

Ties together the individual attack analysis modules and returns a
unified list of findings.  This replaces the old monolithic
``attack_surface.py``.
"""
from __future__ import annotations

from mail_tester.analysis.attacks.models import (
    Finding,
    build_posture,
    get_check,
)
from mail_tester.analysis.attacks.spf_attacks import analyze_spf
from mail_tester.analysis.attacks.dmarc_attacks import analyze_dmarc
from mail_tester.analysis.attacks.dkim_attacks import analyze_dkim
from mail_tester.analysis.attacks.envelope_attacks import analyze_envelope
from mail_tester.analysis.attacks.subdomain_attacks import analyze_subdomain_spoofing
from mail_tester.analysis.attacks.receiver_attacks import analyze_receiving_server
from mail_tester.models import CheckResult


async def analyze_attack_surface(
    sender_domain: str,
    checks: list[CheckResult],
    client_ip: str | None,
) -> list[Finding]:
    """Run all attack-surface analysers and return combined findings."""
    if not sender_domain:
        return []

    posture = build_posture(checks)

    spf_check = get_check(checks, "SPF")
    spf_record = spf_check.record if spf_check else None

    dmarc_check = get_check(checks, "DMARC")
    envelope_check = get_check(checks, "SPF_ENVELOPE")

    findings: list[Finding] = []

    # SPF (async -- does DNS)
    findings.extend(await analyze_spf(sender_domain, spf_record, posture))

    # DMARC (sync)
    findings.extend(analyze_dmarc(sender_domain, dmarc_check, posture))

    # DKIM (sync)
    findings.extend(analyze_dkim(sender_domain, posture))

    # Envelope mismatch (sync)
    findings.extend(analyze_envelope(sender_domain, envelope_check, posture))

    # Subdomain spoofing (async -- does DNS)
    findings.extend(await analyze_subdomain_spoofing(sender_domain, posture))

    # Receiving server behavior (sync)
    findings.extend(analyze_receiving_server(checks, posture))

    return findings
