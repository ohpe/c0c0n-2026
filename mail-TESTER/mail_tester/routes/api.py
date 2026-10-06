"""JSON API routes.

Thin handlers that validate input and delegate to the service layer.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Form, UploadFile, File, HTTPException, Request
from fastapi.responses import RedirectResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from mail_tester.config import settings
from mail_tester.database import get_db, get_analysis, list_analyses
from mail_tester.models import AnalysisResult
from mail_tester.services.chat_service import ask_question, get_chat
from mail_tester.services.email_service import (
    clear_history,
    delete_analysis,
    process_email,
    rescan_analysis,
)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def _validate_eml(file: UploadFile, raw: bytes) -> None:
    """Shared validation for uploaded .eml files."""
    if not file.filename or not file.filename.endswith(".eml"):
        raise HTTPException(400, "Only .eml files are accepted")
    if len(raw) > MAX_FILE_SIZE:
        raise HTTPException(413, "File too large (max 10 MB)")


@router.post("/upload")
@limiter.limit("10/minute")
async def upload_eml(request: Request, file: UploadFile = File(...)):
    raw_eml = await file.read()
    _validate_eml(file, raw_eml)

    analysis_id = await process_email(raw_eml=raw_eml, source="upload")
    return {"analysis_id": analysis_id, "url": f"/result/{analysis_id}"}


@router.post("/upload-redirect")
@limiter.limit("10/minute")
async def upload_eml_redirect(request: Request, file: UploadFile = File(...)):
    """Upload and redirect to the result page (for HTML form submission)."""
    raw_eml = await file.read()
    _validate_eml(file, raw_eml)

    analysis_id = await process_email(raw_eml=raw_eml, source="upload")
    return RedirectResponse(url=f"/result/{analysis_id}", status_code=303)


@router.get("/result/{analysis_id}")
async def get_result_json(analysis_id: str):
    async with get_db(settings.db_path) as conn:
        row = await get_analysis(conn, analysis_id)
    if not row:
        raise HTTPException(404, "Analysis not found")
    return AnalysisResult.model_validate_json(row["results_json"])


@router.get("/results")
async def list_results(limit: int = 20, offset: int = 0):
    async with get_db(settings.db_path) as conn:
        analyses = await list_analyses(conn, limit=limit, offset=offset)
    return analyses


@router.get("/result/{analysis_id}/chat")
async def get_chat_result(analysis_id: str):
    try:
        _, messages = await get_chat(analysis_id)
    except KeyError:
        raise HTTPException(404, "Analysis not found")
    return {"analysis_id": analysis_id, "messages": messages}


@router.post("/result/{analysis_id}/chat")
@limiter.limit("10/minute")
async def ask_chat_result(
    request: Request,
    analysis_id: str,
    question: str = Body("", embed=True),
):
    try:
        messages = await ask_question(analysis_id, question)
    except KeyError:
        raise HTTPException(404, "Analysis not found")
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    return {"analysis_id": analysis_id, "messages": messages}


@router.post("/result/{analysis_id}/rescan")
@limiter.limit("5/minute")
async def rescan_result(request: Request, analysis_id: str):
    try:
        result = await rescan_analysis(analysis_id)
    except KeyError:
        raise HTTPException(404, "Analysis not found")
    except FileNotFoundError:
        raise HTTPException(404, "Stored email file not found")
    except ValueError:
        raise HTTPException(403, "Stored email path is invalid")
    return result


@router.delete("/result/{analysis_id}")
@limiter.limit("5/minute")
async def delete_result(
    request: Request,
    analysis_id: str,
    confirm: bool = Body(False, embed=True),
):
    if not confirm:
        raise HTTPException(400, "Deletion requires confirm=true")
    if not await delete_analysis(analysis_id):
        raise HTTPException(404, "Analysis not found")
    return {"deleted": True, "analysis_id": analysis_id}


@router.post("/history/clear")
@limiter.limit("2/minute")
async def clear_results(
    request: Request,
    confirm: str = Body("", embed=True),
):
    if confirm != "CLEAR HISTORY":
        raise HTTPException(400, "Type CLEAR HISTORY to delete all analyses")
    count = await clear_history()
    return {"deleted": count}


@router.post("/simulate")
@limiter.limit("5/minute")
async def simulate_email(
    request: Request,
    file: UploadFile = File(...),
    from_domain: str = Form(""),
    sending_ip: str = Form(""),
    envelope_domain: str = Form(""),
):
    """Simulate: analyze an email as if sent from a different domain/IP."""
    raw_eml = await file.read()
    _validate_eml(file, raw_eml)

    analysis_id = await process_email(
        raw_eml=raw_eml,
        source="simulate",
        override_from_domain=from_domain or None,
        override_ip=sending_ip or None,
        override_envelope_domain=envelope_domain or None,
    )
    return {"analysis_id": analysis_id, "url": f"/result/{analysis_id}"}
