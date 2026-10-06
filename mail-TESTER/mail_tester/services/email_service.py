"""Email analysis service.

Single entry-point for the persist → analyze → store workflow.  Both the
SMTP handler and the HTTP routes delegate to this service so the logic
lives in one place instead of being duplicated across ``main.py`` and
``routes/api.py``.
"""
from __future__ import annotations

import logging
import uuid
from pathlib import Path

from mail_tester.analysis.pipeline import analyze_email
from mail_tester.config import settings
from mail_tester.database import (
    delete_all_analyses,
    delete_analysis as delete_analysis_row,
    get_analysis,
    get_db,
    insert_analysis,
    update_analysis,
)
from mail_tester.models import AnalysisResult

logger = logging.getLogger(__name__)


async def process_email(
    raw_eml: bytes,
    *,
    client_ip: str | None = None,
    sender: str | None = None,
    recipients: list[str] | None = None,
    source: str = "upload",
    # Simulation overrides
    override_from_domain: str | None = None,
    override_ip: str | None = None,
    override_envelope_domain: str | None = None,
) -> str:
    """Save ``.eml``, run the full analysis pipeline, store the result.

    Returns the analysis ID (a UUID string).
    """
    analysis_id = str(uuid.uuid4())

    # Persist raw email
    settings.eml_dir.mkdir(parents=True, exist_ok=True)
    eml_path = settings.eml_dir / f"{analysis_id}.eml"
    eml_path.write_bytes(raw_eml)

    # Clean domain overrides (strip user@ portion if present)
    clean_from = _clean_domain(override_from_domain)
    clean_envelope = _clean_domain(override_envelope_domain)

    result = await analyze_email(
        raw_eml=raw_eml,
        client_ip=override_ip or client_ip,
        analysis_id=analysis_id,
        source=source,
        sender=sender,
        recipients=recipients or [],
        override_from_domain=clean_from,
        override_ip=override_ip,
        override_envelope_domain=clean_envelope,
    )

    # Build DB row
    row = {
        "id": analysis_id,
        "created_at": result.created_at,
        "sender_address": result.sender_address,
        "recipient_address": result.recipient_address,
        "subject": result.subject,
        "source": source,
        "client_ip": override_ip or client_ip,
        "eml_path": str(eml_path.relative_to(settings.data_dir)),
        "overall_score": result.overall_score,
        "rating": result.rating,
        "results_json": result.model_dump_json(),
    }

    # Simulation cosmetics
    if source == "simulate":
        if override_from_domain:
            row["sender_address"] = f"simulated@{override_from_domain}"
        row["subject"] = f"[SIM] {result.subject or ''}"
        row["client_ip"] = override_ip or result.client_ip

    async with get_db(settings.db_path) as conn:
        await insert_analysis(conn, row)

    logger.info(
        "Analysis complete: id=%s score=%s rating=%s source=%s",
        analysis_id,
        result.overall_score,
        result.rating,
        source,
    )
    return analysis_id


def _clean_domain(value: str | None) -> str | None:
    """Extract domain from input like ``admin@google.com`` → ``google.com``."""
    if not value:
        return None
    value = value.strip()
    if "@" in value:
        value = value.split("@", 1)[1]
    return value or None


def _stored_eml_path(eml_path: str) -> Path:
    """Resolve a stored relative EML path without allowing traversal."""
    data_root = settings.data_dir.resolve()
    path = (settings.data_dir / eml_path).resolve()
    if path != data_root and data_root not in path.parents:
        raise ValueError("Stored email path escapes the data directory")
    return path


def _rescan_override(result: AnalysisResult, name: str) -> str | None:
    """Preserve simulation overrides recorded in the previous result."""
    if result.source != "simulate":
        return None
    value = result.simulation_overrides.get(name)
    return value if isinstance(value, str) and value else None


def _row_to_analysis_data(result: AnalysisResult, row: dict) -> dict:
    """Build the database fields used when replacing a rescanned result."""
    return {
        "id": result.id,
        "created_at": result.created_at,
        "sender_address": result.sender_address,
        "recipient_address": result.recipient_address,
        "subject": result.subject,
        "source": row["source"],
        "client_ip": row.get("client_ip"),
        "overall_score": result.overall_score,
        "rating": result.rating,
        "results_json": result.model_dump_json(),
    }


async def rescan_analysis(analysis_id: str) -> AnalysisResult:
    """Re-run an existing analysis against its stored raw EML file."""
    async with get_db(settings.db_path) as conn:
        row = await get_analysis(conn, analysis_id)

    if row is None:
        raise KeyError(f"Analysis not found: {analysis_id}")

    eml_path = _stored_eml_path(row["eml_path"])
    if not eml_path.is_file():
        raise FileNotFoundError("Stored email file not found")

    raw_eml = eml_path.read_bytes()
    previous = AnalysisResult.model_validate_json(row["results_json"])
    result = await analyze_email(
        raw_eml=raw_eml,
        client_ip=row.get("client_ip"),
        analysis_id=analysis_id,
        source=row["source"],
        sender=row.get("sender_address"),
        recipients=[row["recipient_address"]] if row.get("recipient_address") else [],
        override_from_domain=_rescan_override(previous, "from_domain"),
        override_ip=_rescan_override(previous, "ip"),
        override_envelope_domain=_rescan_override(previous, "envelope_domain"),
    )

    async with get_db(settings.db_path) as conn:
        await update_analysis(conn, _row_to_analysis_data(result, row))
        from mail_tester.database import clear_chat_messages
        await clear_chat_messages(conn, analysis_id)
    logger.info("Analysis rescanned: id=%s score=%s", analysis_id, result.overall_score)
    return result


async def delete_analysis(analysis_id: str) -> bool:
    """Delete one analysis and its associated EML, if present."""
    async with get_db(settings.db_path) as conn:
        row = await get_analysis(conn, analysis_id)
        if row is None:
            return False
        _stored_eml_path(row["eml_path"])
        deleted = await delete_analysis_row(conn, analysis_id)

    if deleted:
        try:
            eml_path = _stored_eml_path(deleted["eml_path"])
            if eml_path.is_file():
                eml_path.unlink()
        except OSError:
            logger.exception("Could not remove EML file for deleted analysis %s", analysis_id)
    logger.info("Analysis deleted: id=%s", analysis_id)
    return deleted is not None


async def clear_history() -> int:
    """Delete all analysis rows and their stored EML files."""
    async with get_db(settings.db_path) as conn:
        rows = await delete_all_analyses(conn)

    removed = 0
    for row in rows:
        try:
            eml_path = _stored_eml_path(row["eml_path"])
            if eml_path.is_file():
                eml_path.unlink()
                removed += 1
        except (OSError, ValueError):
            logger.exception("Could not remove EML file for deleted analysis %s", row["id"])
    logger.info("Analysis history cleared: rows=%d files=%d", len(rows), removed)
    return len(rows)
