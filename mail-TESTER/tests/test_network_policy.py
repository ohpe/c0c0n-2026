from __future__ import annotations

import email
import email.policy

import pytest

from mail_tester.analysis.domain_intel import gather_domain_intel
from mail_tester.analysis.link_check import check_links
from mail_tester.llm.malwarebytes import MalwarebytesProvider
from mail_tester.models import CheckStatus


@pytest.mark.asyncio
async def test_link_check_never_fetches_email_urls(monkeypatch):
    class ForbiddenClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("email URLs must never be fetched")

    monkeypatch.setattr("httpx.AsyncClient", ForbiddenClient)
    msg = email.message_from_string(
        "Content-Type: text/html\n\n<a href='https://attacker.invalid/payload'>link</a>",
        policy=email.policy.default,
    )
    results = await check_links(msg)
    skipped = next(result for result in results if result.name == "LINK_REACHABILITY_SKIPPED")
    assert skipped.status == CheckStatus.NONE
    assert "disabled" in skipped.details.lower()


@pytest.mark.asyncio
async def test_domain_intel_does_not_browse_sender_or_link_domains(monkeypatch):
    class ForbiddenClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("domain redirects must never be fetched")

    monkeypatch.setattr("httpx.AsyncClient", ForbiddenClient)
    intel = await gather_domain_intel(
        "sender.invalid", [], {"From": "sender@sender.invalid"},
        "<a href='https://attacker.invalid/x'>x</a>",
    )
    assert any("redirect check skipped" in item.lower() for item in intel["domain_relationships"])


@pytest.mark.asyncio
async def test_malwarebytes_provider_never_calls_external_api(monkeypatch):
    class ForbiddenClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("Malwarebytes must not receive hostile content")

    monkeypatch.setattr("httpx.AsyncClient", ForbiddenClient)
    provider = MalwarebytesProvider()
    result = await provider.analyze_email(
        "subject", "https://attacker.invalid/payload", {},
    )
    assert result.confidence == 0.0
    assert "skipped" in result.reasoning.lower()
