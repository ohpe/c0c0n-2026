from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from typing import Callable, Coroutine, Any

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session, SMTP

logger = logging.getLogger(__name__)

# Max email size: 10 MB
MAX_MESSAGE_SIZE = 10 * 1024 * 1024

# Simple per-IP rate limiter for SMTP
_smtp_rate: dict[str, list[float]] = defaultdict(list)
_SMTP_MAX_PER_MINUTE = 10


def _check_smtp_rate(ip: str) -> bool:
    """Returns True if the IP is within rate limits."""
    now = time.monotonic()
    # Prune old entries
    _smtp_rate[ip] = [t for t in _smtp_rate[ip] if now - t < 60]
    if len(_smtp_rate[ip]) >= _SMTP_MAX_PER_MINUTE:
        return False
    _smtp_rate[ip].append(now)
    return True


class MailTesterHandler:
    """aiosmtpd handler that receives emails and dispatches analysis."""

    def __init__(
        self,
        main_loop: asyncio.AbstractEventLoop,
        analyze_callback: Callable[..., Coroutine[Any, Any, str]],
    ) -> None:
        self.main_loop = main_loop
        self.analyze_callback = analyze_callback

    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        # Limit recipients per message
        if len(envelope.rcpt_tos) >= 5:
            return "452 Too many recipients"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(
        self, server: SMTP, session: Session, envelope: Envelope
    ) -> str:
        raw_eml: bytes = envelope.content  # type: ignore[assignment]
        client_ip = session.peer[0] if session.peer else None

        # Rate limit per IP
        if client_ip and not _check_smtp_rate(client_ip):
            logger.warning("SMTP rate limit exceeded for %s", client_ip)
            return "421 Rate limit exceeded, try again later"

        # Size limit
        if len(raw_eml) > MAX_MESSAGE_SIZE:
            return "552 Message too large (max 10 MB)"

        sender = envelope.mail_from
        recipients = list(envelope.rcpt_tos)

        logger.info(
            "SMTP received email from=%s to=%s client_ip=%s size=%d",
            sender, recipients, client_ip, len(raw_eml),
        )

        # Schedule analysis on the main FastAPI event loop
        asyncio.run_coroutine_threadsafe(
            self.analyze_callback(
                raw_eml=raw_eml,
                client_ip=client_ip,
                sender=sender,
                recipients=recipients,
                source="smtp",
            ),
            self.main_loop,
        )

        return "250 Message accepted for analysis"


def start_smtp_server(
    host: str,
    port: int,
    main_loop: asyncio.AbstractEventLoop,
    analyze_callback: Callable[..., Coroutine[Any, Any, str]],
) -> Controller:
    handler = MailTesterHandler(main_loop, analyze_callback)
    controller = Controller(
        handler,
        hostname=host,
        port=port,
        data_size_limit=MAX_MESSAGE_SIZE,
    )
    controller.start()
    return controller
