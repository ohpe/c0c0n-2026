"""LLM-based email analysis check.

Delegates to the configured ``LLMProvider`` and maps the response to a
``CheckResult`` + optional ``LLMAnalysis``.

Now accepts enriched context (check results + domain intelligence) so the
LLM can make a more informed judgment.
"""
from __future__ import annotations

import logging
from email.message import EmailMessage

from mail_tester.email_utils import get_body_text
from mail_tester.models import CheckResult, CheckStatus, LLMAnalysis
from mail_tester.llm import get_provider

logger = logging.getLogger(__name__)


async def check_llm(
    msg: EmailMessage,
    check_summary: str = "",
    domain_intel: str = "",
    technical_context: str = "",
) -> tuple[CheckResult, LLMAnalysis | None]:
    provider = get_provider()

    if provider is None:
        return (
            CheckResult(
                name="LLM",
                status=CheckStatus.NONE,
                score_delta=0.0,
                details="LLM analysis disabled (provider=none).",
            ),
            None,
        )

    subject = msg.get("Subject", "")
    body = get_body_text(msg)
    headers = dict(msg.items())

    try:
        analysis: LLMAnalysis = await provider.analyze_email(
            subject, body, headers,
            check_summary=check_summary,
            domain_intel=domain_intel,
            technical_context=technical_context,
        )
    except Exception as exc:
        logger.error("LLM analysis failed: %s", exc)
        return (
            CheckResult(
                name="LLM",
                status=CheckStatus.ERROR,
                score_delta=0.0,
                details=f"LLM analysis failed: {exc}",
            ),
            None,
        )

    if analysis.is_suspicious:
        if analysis.confidence >= 0.7:
            score_delta = -1.5
        elif analysis.confidence >= 0.4:
            score_delta = -0.5
        else:
            score_delta = -0.2
        status = CheckStatus.FAIL
    else:
        score_delta = 0.5
        status = CheckStatus.PASS

    analysis.provider = getattr(provider, "provider_name", provider.__class__.__name__.removesuffix("Provider").lower())
    analysis.model = getattr(provider, "model", None)
    indicators_str = ", ".join(analysis.indicators) if analysis.indicators else "none"

    return (
        CheckResult(
            name="LLM",
            status=status,
            score_delta=score_delta,
            details=(
                f"[{analysis.category}] {analysis.reasoning} "
                f"(confidence: {analysis.confidence:.0%}, indicators: {indicators_str})"
            ),
            extra={
                "category": analysis.category,
                "confidence": analysis.confidence,
                "indicators": analysis.indicators,
            },
        ),
        analysis,
    )
