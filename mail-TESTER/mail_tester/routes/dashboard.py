from __future__ import annotations

from fastapi import APIRouter, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jinja2 import select_autoescape
from pathlib import Path

from mail_tester.config import settings
from mail_tester.database import get_db, get_analysis, list_analyses
from mail_tester.models import AnalysisResult
from mail_tester.services.email_service import clear_history, delete_analysis, rescan_analysis

router = APIRouter()
_template_dir = str(Path(__file__).resolve().parent.parent / "templates")
templates = Jinja2Templates(directory=_template_dir)
# Explicitly enable autoescape for all HTML templates
templates.env.autoescape = select_autoescape(["html", "htm", "xml"])

# Common context passed to every template
def _ctx(**extra) -> dict:
    return {
        "smtp_domain": settings.smtp_domain,
        "smtp_port": settings.smtp_port,
        **extra,
    }


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    async with get_db(settings.db_path) as conn:
        recent = await list_analyses(conn, limit=20)
    return templates.TemplateResponse(request, "index.html", _ctx(
        recent_analyses=recent,
    ))


@router.get("/result/{analysis_id}", response_class=HTMLResponse)
async def result_page(request: Request, analysis_id: str, rescanned: int = 0):
    async with get_db(settings.db_path) as conn:
        row = await get_analysis(conn, analysis_id)
    if not row:
        raise HTTPException(404, "Analysis not found")

    result = AnalysisResult.model_validate_json(row["results_json"])
    return templates.TemplateResponse(request, "result.html", _ctx(
        analysis=row, result=result, rescanned=bool(rescanned),
    ))


@router.post("/result/{analysis_id}/rescan")
async def rescan_result_page(request: Request, analysis_id: str):
    try:
        await rescan_analysis(analysis_id)
    except KeyError:
        raise HTTPException(404, "Analysis not found")
    except FileNotFoundError:
        raise HTTPException(404, "Stored email file not found")
    except ValueError:
        raise HTTPException(403, "Stored email path is invalid")
    return RedirectResponse(url=f"/result/{analysis_id}?rescanned=1", status_code=303)


@router.post("/result/{analysis_id}/delete")
async def delete_result_page(request: Request, analysis_id: str, confirm: str = Form("")):
    if confirm != analysis_id:
        raise HTTPException(400, "Type the analysis ID to confirm deletion")
    if not await delete_analysis(analysis_id):
        raise HTTPException(404, "Analysis not found")
    return RedirectResponse(url="/history?deleted=1", status_code=303)


@router.post("/history/clear")
async def clear_history_page(request: Request, confirm: str = Form("")):
    if confirm != "CLEAR HISTORY":
        raise HTTPException(400, "Type CLEAR HISTORY to delete all analyses")
    await clear_history()
    return RedirectResponse(url="/history?cleared=1", status_code=303)


@router.get("/download/{analysis_id}")
async def download_eml(analysis_id: str):
    """Download the raw .eml file for an analysis."""
    async with get_db(settings.db_path) as conn:
        row = await get_analysis(conn, analysis_id)
    if not row:
        raise HTTPException(404, "Analysis not found")

    eml_path = (settings.data_dir / row["eml_path"]).resolve()
    # Prevent path traversal
    if not str(eml_path).startswith(str(settings.data_dir.resolve())):
        raise HTTPException(403, "Access denied")
    if not eml_path.exists():
        raise HTTPException(404, "Email file not found")

    # Sanitize filename for Content-Disposition header
    raw_subject = row.get("subject") or "email"
    safe_name = "".join(c for c in raw_subject[:50] if c.isalnum() or c in " -_") + ".eml"
    return FileResponse(
        path=str(eml_path),
        media_type="message/rfc822",
        filename=safe_name,
    )


@router.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    return templates.TemplateResponse(request, "upload.html", _ctx())


@router.get("/simulate", response_class=HTMLResponse)
async def simulate_page(request: Request):
    return templates.TemplateResponse(request, "simulate.html", _ctx())


@router.get("/history", response_class=HTMLResponse)
async def history_page(
    request: Request,
    page: int = 1,
    deleted: int = 0,
    cleared: int = 0,
):
    limit = 20
    page = max(1, page)
    offset = (page - 1) * limit
    async with get_db(settings.db_path) as conn:
        analyses = await list_analyses(conn, limit=limit, offset=offset)
    return templates.TemplateResponse(request, "history.html", _ctx(
        analyses=analyses,
        page=max(1, page),
        deleted=bool(deleted),
        cleared=bool(cleared),
    ))
