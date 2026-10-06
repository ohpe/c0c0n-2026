from __future__ import annotations

from email.message import EmailMessage

from mail_tester.email_utils import extract_domain
from mail_tester.models import CheckResult, CheckStatus

# X-Mailer strings commonly associated with spam or bulk sending tools
SUSPICIOUS_MAILERS = [
    "mass mailer", "bulk mail", "phpmailer", "swiftmailer",
    "king-spam", "turbo mailer", "atomic mail",
]


async def check_headers(msg: EmailMessage) -> list[CheckResult]:
    """Analyze email headers for suspicious patterns."""
    results: list[CheckResult] = []

    # 1. Received header chain analysis
    received = msg.get_all("Received") or []
    if not received:
        results.append(CheckResult(
            name="HEADER_CHAIN",
            status=CheckStatus.FAIL,
            score_delta=-0.3,
            details="No Received headers found. Legitimate emails always have at least one.",
        ))
    elif len(received) == 1:
        # Single Received header is unusual but not necessarily bad
        # (could be direct submission to local MTA)
        pass
    else:
        # Check for timestamp ordering issues
        # (basic check: the chain should exist and have content)
        empty_received = sum(1 for r in received if len(r.strip()) < 10)
        if empty_received:
            results.append(CheckResult(
                name="HEADER_CHAIN",
                status=CheckStatus.SOFTFAIL,
                score_delta=-0.1,
                details=f"{empty_received} Received header(s) appear malformed or empty.",
            ))

    # 2. From/Reply-To mismatch
    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    if reply_to:
        from_domain = extract_domain(from_header)
        reply_domain = extract_domain(reply_to)
        if from_domain and reply_domain and from_domain.lower() != reply_domain.lower():
            results.append(CheckResult(
                name="HEADER_REPLY_TO",
                status=CheckStatus.FAIL,
                score_delta=-0.5,
                details=f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}). Common in phishing.",
            ))
        elif from_domain and reply_domain:
            results.append(CheckResult(
                name="HEADER_REPLY_TO",
                status=CheckStatus.PASS,
                score_delta=0.1,
                details="Reply-To domain matches From domain.",
            ))

    # 3. X-Mailer / User-Agent analysis
    x_mailer = msg.get("X-Mailer", "") or msg.get("User-Agent", "")
    if x_mailer:
        mailer_lower = x_mailer.lower()
        for suspicious in SUSPICIOUS_MAILERS:
            if suspicious in mailer_lower:
                results.append(CheckResult(
                    name="HEADER_XMAILER",
                    status=CheckStatus.SOFTFAIL,
                    score_delta=-0.3,
                    details=f"X-Mailer '{x_mailer}' is associated with bulk/spam sending tools.",
                ))
                break

    # 4. Multiple From addresses (common in spoofing attempts)
    from_all = msg.get_all("From") or []
    if len(from_all) > 1:
        results.append(CheckResult(
            name="HEADER_MULTI_FROM",
            status=CheckStatus.FAIL,
            score_delta=-0.5,
            details=f"Email has {len(from_all)} From headers. This is a spoofing indicator.",
        ))

    # 5. Return-Path vs From mismatch
    return_path = msg.get("Return-Path", "")
    if return_path and from_header:
        rp_domain = extract_domain(return_path)
        from_domain = extract_domain(from_header)
        if rp_domain and from_domain and rp_domain.lower() != from_domain.lower():
            results.append(CheckResult(
                name="HEADER_RETURN_PATH",
                status=CheckStatus.SOFTFAIL,
                score_delta=-0.2,
                details=f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain}).",
            ))

    return results
