"""Email analysis pipeline.

Orchestrates all individual checks, computes the overall score,
generates recommendations, and runs the attack-surface analysis.
"""
from __future__ import annotations

import asyncio
import email
import email.policy
import ipaddress
import re
from datetime import datetime, timezone

from mail_tester.email_utils import extract_domain, get_html_body
from mail_tester.models import (
    AnalysisResult,
    AttackFinding,
    CheckResult,
    CheckStatus,
)
from mail_tester.analysis.spf import check_spf
from mail_tester.analysis.dkim import check_dkim
from mail_tester.analysis.dmarc import check_dmarc
from mail_tester.analysis.html_check import check_html
from mail_tester.analysis.link_check import check_links
from mail_tester.analysis.blacklist import check_blacklists
from mail_tester.analysis.spam_score import check_spam_content
from mail_tester.analysis.llm_check import check_llm
from mail_tester.analysis.headers import check_headers
from mail_tester.analysis.rdns import check_rdns
from mail_tester.analysis.auth_results import check_auth_results
from mail_tester.analysis.attacks.orchestrator import analyze_attack_surface
from mail_tester.analysis.domain_intel import gather_domain_intel, format_intel_for_llm
from mail_tester.analysis.technical import analyze_technical, format_technical_for_llm
from mail_tester.llm.base import format_checks_for_llm

# ── Scoring Constants ──────────────────────────────────────────────

BASE_SCORE = 5.0
IP_DEPENDENT_CHECKS = {"SPF", "DNSBL", "RDNS"}

RECOMMENDATIONS: dict[str, dict[CheckStatus, str]] = {
    "SPF": {
        CheckStatus.NONE: "Add an SPF record (TXT) to your domain's DNS: v=spf1 ip4:<your-ip> -all",
        CheckStatus.FAIL: "Your sending IP is not authorized by your SPF record. Add it or send from an authorized server.",
        CheckStatus.SOFTFAIL: "Consider changing ~all (softfail) to -all (hardfail) in your SPF record.",
        CheckStatus.PERMERROR: "Your SPF record has errors (too many lookups or syntax issues). Simplify it.",
    },
    "DKIM": {
        CheckStatus.NONE: "Configure DKIM signing on your mail server and publish the public key in DNS.",
        CheckStatus.FAIL: "Your DKIM signature is invalid. Check your DNS public key and signing configuration.",
    },
    "DMARC": {
        CheckStatus.NONE: 'Add a DMARC record: _dmarc.yourdomain TXT "v=DMARC1; p=reject; adkim=s; aspf=s"',
        CheckStatus.FAIL: "DMARC alignment fails. Ensure SPF or DKIM pass AND align with the From: domain.",
    },
    "SHORTENED_URLS": {
        CheckStatus.FAIL: "Replace shortened URLs (bit.ly, etc.) with full URLs.",
    },
    "LINK_MISMATCH": {
        CheckStatus.FAIL: "Display text shows a different URL than the actual link href. Fix mismatched links.",
    },
    "HTML_TEXT_RATIO": {
        CheckStatus.FAIL: "Add a plain-text alternative part to your HTML email (multipart/alternative).",
    },
    "CONTENT": {
        CheckStatus.FAIL: "Remove spam trigger words, reduce caps and exclamation marks, add missing headers.",
    },
    "DNSBL": {
        CheckStatus.FAIL: "Your sending IP is blacklisted. Request delisting from the relevant DNSBL providers.",
    },
    "FORM_IN_EMAIL": {
        CheckStatus.FAIL: "Remove <form> elements from your email. Most clients block them.",
    },
    "JAVASCRIPT": {
        CheckStatus.FAIL: "Remove <script> tags. Email clients strip JavaScript entirely.",
    },
    "RDNS": {
        CheckStatus.FAIL: "Set up a PTR record for your sending IP that matches your mail server hostname.",
    },
    "HEADER_CHAIN": {
        CheckStatus.FAIL: "Your email's Received header chain looks suspicious or is malformed.",
    },
    "HEADER_XMAILER": {
        CheckStatus.SOFTFAIL: "Your X-Mailer header reveals an unusual or potentially flagged sending tool.",
    },
}


# ── Helpers ────────────────────────────────────────────────────────


def _extract_ip_from_received(msg: email.message.EmailMessage) -> str | None:
    """Try to extract the originating IP from the Received header chain."""
    received_headers = msg.get_all("Received") or []
    # Walk from last (first hop) to first, prefer public IPs
    for header in reversed(received_headers):
        for ip_str in re.findall(r"[\[\(]([\d.]+)[\]\)]", header):
            try:
                addr = ipaddress.ip_address(ip_str)
                if not addr.is_private and not addr.is_loopback:
                    return ip_str
            except ValueError:
                continue
    # Fallback: accept private IPs
    for header in reversed(received_headers):
        for ip_str in re.findall(r"[\[\(]([\d.]+)[\]\)]", header):
            try:
                ipaddress.ip_address(ip_str)
                return ip_str
            except ValueError:
                continue
    return None


def _score_to_rating(score: float) -> str:
    if score >= 9.0:
        return "Excellent"
    if score >= 7.0:
        return "Good"
    if score >= 5.0:
        return "Average"
    if score >= 3.0:
        return "Poor"
    return "Very Poor"


def _compute_score(
    checks: list[CheckResult],
    has_client_ip: bool,
    is_simulation: bool = False,
) -> float:
    """Compute normalized score.

    Accounts for:
    - Missing client IP (skipped IP-dependent checks)
    - Original Authentication-Results from the receiving MTA
    - Simulation mode (original auth headers ignored)
    """
    original_results: dict[str, CheckStatus] = {}
    if not is_simulation:
        for c in checks:
            if c.name.startswith("ORIGINAL_"):
                method = c.name.replace("ORIGINAL_", "")
                original_results[method] = c.status

    active_delta = 0.0
    skipped = 0

    for c in checks:
        if (
            not has_client_ip
            and c.name in IP_DEPENDENT_CHECKS
            and c.status == CheckStatus.NONE
            and c.score_delta == 0.0
        ):
            skipped += 1
            continue

        if (
            c.name in ("SPF", "DKIM", "DMARC")
            and c.score_delta < 0
            and original_results.get(c.name) == CheckStatus.PASS
        ):
            continue

        active_delta += c.score_delta

    raw_score = BASE_SCORE + active_delta

    orig_pass_count = sum(
        1
        for m in ("SPF", "DKIM", "DMARC")
        if original_results.get(m) == CheckStatus.PASS
    )
    if orig_pass_count > 0:
        raw_score += orig_pass_count * 0.8

    if skipped and raw_score > 0:
        raw_score += 1.0

    return round(max(0.0, min(10.0, raw_score)), 1)


def _generate_recommendations(checks: list[CheckResult]) -> list[str]:
    recs: list[str] = []
    for check in checks:
        if check.name in RECOMMENDATIONS:
            rec = RECOMMENDATIONS[check.name].get(check.status)
            if rec:
                recs.append(rec)
    return recs


# ── Main Entry Point ──────────────────────────────────────────────


async def analyze_email(
    raw_eml: bytes,
    client_ip: str | None = None,
    analysis_id: str = "",
    source: str = "upload",
    sender: str | None = None,
    recipients: list[str] | None = None,
    override_from_domain: str | None = None,
    override_ip: str | None = None,
    override_envelope_domain: str | None = None,
) -> AnalysisResult:
    msg = email.message_from_bytes(raw_eml, policy=email.policy.default)

    from_header = msg.get("From", "")
    sender_domain = override_from_domain or extract_domain(from_header)

    effective_ip = override_ip or client_ip
    if not effective_ip:
        effective_ip = _extract_ip_from_received(msg)

    return_path = msg.get("Return-Path", "")
    envelope_domain = override_envelope_domain or extract_domain(return_path)

    # Phase 1: SPF + DKIM in parallel
    spf_tasks = [
        check_spf(sender_domain, effective_ip),
        check_dkim(raw_eml),
    ]
    if envelope_domain and envelope_domain.lower() != sender_domain.lower():
        spf_tasks.append(check_spf(envelope_domain, effective_ip))

    phase1 = await asyncio.gather(*spf_tasks)
    spf_result = phase1[0]
    dkim_result = phase1[1]
    envelope_spf = phase1[2] if len(phase1) > 2 else None

    if envelope_spf:
        envelope_spf = CheckResult(
            name="SPF_ENVELOPE",
            status=envelope_spf.status,
            score_delta=0.0,
            details=f"Envelope sender ({envelope_domain}): {envelope_spf.details}",
            record=envelope_spf.record,
            extra={**envelope_spf.extra, "domain": envelope_domain},
        )

    # Phase 2: DMARC (depends on SPF + DKIM)
    dmarc_result = await check_dmarc(sender_domain, spf_result, dkim_result)

    # Phase 3: Content checks + domain intel in parallel (NO LLM yet)
    (
        html_results,
        link_results,
        blacklist_result,
        spam_result,
        header_results,
        rdns_result,
        auth_results,
        domain_intel,
        technical_report,
    ) = await asyncio.gather(
        check_html(msg),
        check_links(msg),
        check_blacklists(effective_ip),
        check_spam_content(msg),
        check_headers(msg),
        check_rdns(effective_ip),
        check_auth_results(msg),
        gather_domain_intel(
            sender_domain,
            [],  # link checks not done yet, but domain_intel mostly needs the sender domain
            dict(msg.items()),
            get_html_body(msg),
        ),
        asyncio.to_thread(analyze_technical, raw_eml, msg),
    )

    # Assemble pre-LLM checks
    pre_llm_checks: list[CheckResult] = [
        spf_result,
        dkim_result,
        dmarc_result,
        *([] if envelope_spf is None else [envelope_spf]),
        *auth_results,
        *html_results,
        *link_results,
        blacklist_result,
        spam_result,
        *header_results,
        rdns_result,
    ]

    # Phase 4: LLM analysis -- now has full context from all prior checks
    check_summary = format_checks_for_llm(pre_llm_checks)
    intel_text = format_intel_for_llm(domain_intel)
    technical_text = format_technical_for_llm(technical_report)
    (llm_result, llm_analysis) = await check_llm(
        msg,
        check_summary=check_summary,
        domain_intel=intel_text,
        technical_context=technical_text,
    )

    all_checks = pre_llm_checks + [llm_result]

    has_client_ip = effective_ip is not None
    is_simulation = source == "simulate"
    overall_score = _compute_score(all_checks, has_client_ip, is_simulation=is_simulation)
    rating = _score_to_rating(overall_score)
    recommendations = _generate_recommendations(all_checks)

    # Phase 5: Attack surface
    raw_findings = await analyze_attack_surface(sender_domain, all_checks, effective_ip)
    attack_surface = [
        AttackFinding(
            severity=f.severity,
            title=f.title,
            description=f.description,
            exploit=f.exploit,
            remediation=f.remediation,
        )
        for f in raw_findings
    ]

    return AnalysisResult(
        id=analysis_id,
        created_at=datetime.now(timezone.utc).isoformat(),
        sender_address=sender or from_header,
        recipient_address=", ".join(recipients) if recipients else msg.get("To"),
        subject=msg.get("Subject"),
        source=source,
        client_ip=effective_ip or client_ip,
        overall_score=overall_score,
        rating=rating,
        checks=all_checks,
        llm_analysis=llm_analysis,
        technical_report=technical_report,
        simulation_overrides={
            "from_domain": override_from_domain,
            "ip": override_ip,
            "envelope_domain": override_envelope_domain,
        } if is_simulation else {},
        recommendations=recommendations,
        attack_surface=attack_surface,
    )
