"""Shared email parsing utilities.

Functions here are used by multiple analysis modules.  Centralizing them
avoids the duplicate ``_get_body_text`` / ``_extract_domain`` helpers that
were previously copy-pasted across ``llm_check``, ``spam_score``,
``headers``, ``pipeline``, and ``link_check``.
"""
from __future__ import annotations

import re
from email.message import EmailMessage

from bs4 import BeautifulSoup


def extract_domain(header_value: str) -> str:
    """Extract the domain portion from an email address or header value.

    >>> extract_domain("Alice <alice@example.com>")
    'example.com'
    """
    match = re.search(r"@([\w.-]+)", header_value or "")
    return match.group(1) if match else ""


def get_body_text(msg: EmailMessage) -> str:
    """Return the plain-text body of *msg*, falling back to stripped HTML."""
    text_body = msg.get_body(preferencelist=("plain",))
    if text_body is not None:
        content = text_body.get_content()
        if isinstance(content, str) and content.strip():
            return content

    html_body = msg.get_body(preferencelist=("html",))
    if html_body is not None:
        content = html_body.get_content()
        if isinstance(content, str) and content.strip():
            return BeautifulSoup(content, "html.parser").get_text()

    return ""


def get_html_body(msg: EmailMessage) -> str | None:
    """Return the raw HTML body, or ``None`` if the message has none."""
    body = msg.get_body(preferencelist=("html",))
    if body is not None:
        payload = body.get_content()
        if isinstance(payload, str) and payload.strip():
            return payload
    return None


def get_text_body(msg: EmailMessage) -> str | None:
    """Return the plain-text body, or ``None`` if the message has none."""
    body = msg.get_body(preferencelist=("plain",))
    if body is not None:
        payload = body.get_content()
        if isinstance(payload, str) and payload.strip():
            return payload
    return None
