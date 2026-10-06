"""Persistent, analysis-scoped AI questions."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from mail_tester.analysis.network_policy import LINK_ACCESS_NOTICE
from mail_tester.config import settings
from mail_tester.database import (
    get_analysis,
    get_db,
    insert_chat_message,
    list_chat_messages,
)
from mail_tester.llm import get_provider
from mail_tester.models import AnalysisResult

MAX_QUESTION = 2000
MAX_HISTORY = 20


def _version(result: AnalysisResult) -> str:
    return result.created_at


def _context(result: AnalysisResult) -> str:
    checks = "\n".join(
        f"- [{index}] {check.name}: {check.status.value} ({check.score_delta:+.1f}) {check.details[:500]}"
        for index, check in enumerate(result.checks, start=1)
        if check.name != "LLM"
    )
    report = result.technical_report
    if report:
        inventory = "\n".join(
            f"- OBSERVED HEADER {item.name} (occurrence {item.occurrence}): {item.value}"
            for item in report.header_inventory
        ) or "- OBSERVED HEADER Cc: (absent from stored message)\n- OBSERVED HEADER Bcc: (absent from stored message)"
        hops = "\n".join(
            f"- hop {hop.position}: from={hop.from_value or '?'} by={hop.by_value or '?'} "
            f"with={hop.with_value or '?'} ip={hop.from_ip or '?'} time={hop.timestamp or '?'} "
            f"anomalies={', '.join(hop.anomalies) or 'none'}"
            for hop in report.received_hops
        ) or "- No Received hops were parsed."
        technical = report.model_dump_json()[:12000]
    else:
        inventory = "- No header inventory is available."
        hops = "- No Received hop data is available."
        technical = "none"
    ai_interpretation = result.llm_analysis.model_dump_json()[:3000] if result.llm_analysis else "none"
    return (
        f"Analysis ID: {result.id}\nScore: {result.overall_score}/10 ({result.rating})\n"
        f"From: {result.sender_address or '-'}\nTo: {result.recipient_address or '-'}\n"
        f"Subject: {result.subject or '-'}\n\n"
        "HEADER INVENTORY (observed data; not inferred):\n"
        f"{inventory[:12000]}\n\nRECEIVED HOP TABLE (newest first):\n{hops[:8000]}\n\n"
        f"AUTOMATED CHECKS (deterministic):\n{checks[:12000]}\n\n"
        f"SOC EVASION INDICATORS (offline heuristics; not proof):\n{technical}\n\n"
        f"AI INTERPRETATION (not fact):\n{ai_interpretation}\n\n"
        f"NETWORK POLICY: {LINK_ACCESS_NOTICE}"
    )


async def get_chat(analysis_id: str) -> tuple[AnalysisResult, list[dict]]:
    async with get_db(settings.db_path) as conn:
        row = await get_analysis(conn, analysis_id)
        if row is None:
            raise KeyError(analysis_id)
        result = AnalysisResult.model_validate_json(row["results_json"])
        messages = await list_chat_messages(conn, analysis_id, _version(result), MAX_HISTORY)
    return result, messages


async def ask_question(analysis_id: str, question: str) -> list[dict]:
    question = question.strip()
    if not question or len(question) > MAX_QUESTION:
        raise ValueError(f"Question must be between 1 and {MAX_QUESTION} characters")

    result, history = await get_chat(analysis_id)
    provider = get_provider()
    if provider is None or settings.llm_provider.lower() == "malwarebytes":
        raise RuntimeError("Chat requires a supported LLM provider")

    created_at = datetime.now(timezone.utc).isoformat()
    history_for_llm = [{"role": item["role"], "content": item["content"]} for item in history]
    try:
        answer = await asyncio.wait_for(
            provider.answer_question(question, _context(result), history_for_llm),
            timeout=settings.chat_timeout,
        )
    except asyncio.TimeoutError as exc:
        raise RuntimeError("The AI provider timed out. Check the provider and try again.") from exc
    except Exception as exc:
        raise RuntimeError("The AI provider could not answer right now. Check its logs and try again.") from exc
    answer = answer.strip()[:10000]
    if not answer:
        raise RuntimeError("The LLM returned an empty answer")

    async with get_db(settings.db_path) as conn:
        await insert_chat_message(conn, analysis_id, _version(result), "user", question, created_at)
        await insert_chat_message(conn, analysis_id, _version(result), "assistant", answer, datetime.now(timezone.utc).isoformat())
        return await list_chat_messages(conn, analysis_id, _version(result), MAX_HISTORY)
