from __future__ import annotations

import asyncio

import pytest

from mail_tester import database
from mail_tester.config import settings
from mail_tester.models import AnalysisResult
from mail_tester.services import chat_service


@pytest.fixture
def analysis_payload():
    return AnalysisResult(
        id="chat-analysis",
        created_at="2026-01-01T00:00:00+00:00",
        source="upload",
        overall_score=5.0,
        rating="Average",
        checks=[],
        recommendations=[],
    )


@pytest.mark.asyncio
async def test_chat_persists_bounded_messages(tmp_path, monkeypatch, analysis_payload):
    monkeypatch.setenv("MAILTESTER_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "llm_provider", "fake")
    db_path = tmp_path / "mail_tester.db"
    await database.init_db(db_path)
    async with database.get_db(db_path) as conn:
        await database.insert_analysis(conn, {
            "id": analysis_payload.id,
            "created_at": analysis_payload.created_at,
            "sender_address": None,
            "recipient_address": None,
            "subject": None,
            "source": "upload",
            "client_ip": None,
            "eml_path": "emails/chat-analysis.eml",
            "overall_score": 5.0,
            "rating": "Average",
            "results_json": analysis_payload.model_dump_json(),
        })

    class FakeProvider:
        async def answer_question(self, question, analysis_context, history):
            assert "NETWORK POLICY" in analysis_context
            assert "https://" not in analysis_context
            return f"answer: {question}"

    monkeypatch.setattr(chat_service, "get_provider", lambda: FakeProvider())
    messages = await chat_service.ask_question(analysis_payload.id, "Why is this suspicious?")
    assert [message["role"] for message in messages] == ["user", "assistant"]
    assert messages[-1]["content"] == "answer: Why is this suspicious?"


@pytest.mark.asyncio
async def test_chat_rejects_when_provider_is_disabled(tmp_path, monkeypatch, analysis_payload):
    monkeypatch.setenv("MAILTESTER_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "llm_provider", "none")
    db_path = tmp_path / "mail_tester.db"
    await database.init_db(db_path)
    async with database.get_db(db_path) as conn:
        await database.insert_analysis(conn, {
            "id": analysis_payload.id,
            "created_at": analysis_payload.created_at,
            "source": "upload",
            "eml_path": "emails/chat-analysis.eml",
            "overall_score": 5.0,
            "rating": "Average",
            "results_json": analysis_payload.model_dump_json(),
        })

    with pytest.raises(RuntimeError, match="supported LLM"):
        await chat_service.ask_question(analysis_payload.id, "hello")


@pytest.mark.asyncio
async def test_chat_history_is_isolated_by_analysis_and_version(tmp_path):
    db_path = tmp_path / "mail_tester.db"
    await database.init_db(db_path)
    async with database.get_db(db_path) as conn:
        await database.insert_chat_message(conn, "one", "v1", "user", "one", "now")
        await database.insert_chat_message(conn, "two", "v1", "user", "two", "now")
        messages = await database.list_chat_messages(conn, "one", "v1")
    assert messages == [{"role": "user", "content": "one", "created_at": "now"}]


@pytest.mark.asyncio
async def test_question_length_is_bounded(tmp_path, monkeypatch, analysis_payload):
    monkeypatch.setenv("MAILTESTER_DATA_DIR", str(tmp_path))
    db_path = tmp_path / "mail_tester.db"
    await database.init_db(db_path)
    async with database.get_db(db_path) as conn:
        await database.insert_analysis(conn, {
            "id": analysis_payload.id,
            "created_at": analysis_payload.created_at,
            "source": "upload",
            "eml_path": "emails/chat-analysis.eml",
            "overall_score": 5.0,
            "rating": "Average",
            "results_json": analysis_payload.model_dump_json(),
        })
    with pytest.raises(ValueError):
        await chat_service.ask_question(analysis_payload.id, "x" * 2001)


@pytest.mark.asyncio
async def test_chat_provider_timeout_returns_actionable_error(tmp_path, monkeypatch, analysis_payload):
    monkeypatch.setenv("MAILTESTER_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "llm_provider", "fake")
    monkeypatch.setattr(settings, "chat_timeout", 0.01)
    db_path = tmp_path / "mail_tester.db"
    await database.init_db(db_path)
    async with database.get_db(db_path) as conn:
        await database.insert_analysis(conn, {
            "id": analysis_payload.id,
            "created_at": analysis_payload.created_at,
            "source": "upload",
            "eml_path": "emails/chat-analysis.eml",
            "overall_score": 5.0,
            "rating": "Average",
            "results_json": analysis_payload.model_dump_json(),
        })

    class SlowProvider:
        async def answer_question(self, question, analysis_context, history):
            await asyncio.sleep(1)
            return "late answer"

    monkeypatch.setattr(chat_service, "get_provider", lambda: SlowProvider())
    with pytest.raises(RuntimeError, match="timed out"):
        await chat_service.ask_question(analysis_payload.id, "hello")
