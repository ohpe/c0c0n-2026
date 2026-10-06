"""FastAPI application entry point.

Uses an app-factory approach: ``create_app()`` builds and configures the
FastAPI instance so it's testable and decoupled from the global module
scope.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from mail_tester.config import settings
from mail_tester.database import init_db
from mail_tester.services.email_service import process_email
from mail_tester.smtp_server import start_smtp_server

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

_PKG_DIR = Path(__file__).resolve().parent


# ── Lifespan ──────────────────────────────────────────────────────


def _log_web_server_startup(host: str, port: int) -> None:
    """Log the web endpoint, accounting for an OS-assigned port."""
    if port == 0:
        logger.info(
            "Web server will bind to an available port on %s; "
            "Uvicorn will log the URL once it is ready",
            host,
        )
    else:
        logger.info("Web server at http://%s:%s", host, port)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.eml_dir.mkdir(parents=True, exist_ok=True)
    await init_db(settings.db_path)

    main_loop = asyncio.get_running_loop()
    smtp_controller = start_smtp_server(
        host=settings.smtp_host,
        port=settings.smtp_port,
        main_loop=main_loop,
        analyze_callback=process_email,
    )
    logger.info("SMTP server listening on %s:%s", settings.smtp_host, settings.smtp_port)
    _log_web_server_startup(settings.web_host, settings.web_port)
    logger.info("LLM provider: %s", settings.llm_provider)

    yield

    smtp_controller.stop()
    logger.info("SMTP server stopped")


# ── App Factory ───────────────────────────────────────────────────


def create_app() -> FastAPI:
    application = FastAPI(title="Mail Tester", lifespan=lifespan)

    # Rate limiting
    limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
    application.state.limiter = limiter

    @application.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Try again later."},
        )

    # Static files
    application.mount(
        "/static",
        StaticFiles(directory=str(_PKG_DIR / "static")),
        name="static",
    )

    # Routes
    from mail_tester.routes.api import router as api_router
    from mail_tester.routes.dashboard import router as dashboard_router

    application.include_router(api_router, prefix="/api")
    application.include_router(dashboard_router)

    return application


app = create_app()


# ── CLI ───────────────────────────────────────────────────────────


def cli_entry():
    from mail_tester.port_utils import choose_web_port

    selected_port = choose_web_port(settings.web_host, settings.web_port)
    if selected_port is None:
        raise SystemExit(1)

    uvicorn.run(
        "mail_tester.main:app",
        host=settings.web_host,
        port=selected_port,
        reload=True,
    )


if __name__ == "__main__":
    cli_entry()
