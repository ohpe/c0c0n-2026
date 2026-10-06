from __future__ import annotations

import pytest

from mail_tester.database import (
    delete_analysis as delete_analysis_row,
    get_analysis,
    get_db,
    init_db,
    insert_analysis,
    update_analysis,
)
from mail_tester.services.email_service import delete_analysis, _stored_eml_path


@pytest.mark.asyncio
async def test_database_delete_and_update(tmp_path):
    db_path = tmp_path / "mail_tester.db"
    await init_db(db_path)
    row = {
        "id": "analysis-1",
        "created_at": "2026-01-01T00:00:00Z",
        "sender_address": "sender@example.com",
        "recipient_address": "recipient@example.net",
        "subject": "Before",
        "source": "upload",
        "client_ip": None,
        "eml_path": "emails/analysis-1.eml",
        "overall_score": 5.0,
        "rating": "Average",
        "results_json": "{}",
    }

    async with get_db(db_path) as conn:
        await insert_analysis(conn, row)
        row["subject"] = "After"
        await update_analysis(conn, row)
        assert (await get_analysis(conn, "analysis-1"))["subject"] == "After"
        deleted = await delete_analysis_row(conn, "analysis-1")
        assert deleted["id"] == "analysis-1"
        assert await get_analysis(conn, "analysis-1") is None
        assert await delete_analysis_row(conn, "analysis-1") is None


@pytest.mark.asyncio
async def test_service_delete_removes_only_linked_eml(tmp_path, monkeypatch):
    monkeypatch.setenv("MAILTESTER_DATA_DIR", str(tmp_path))
    await init_db(tmp_path / "mail_tester.db")
    email_dir = tmp_path / "emails"
    email_dir.mkdir()
    target = email_dir / "analysis-1.eml"
    unrelated = email_dir / "unrelated.eml"
    target.write_bytes(b"From: sender@example.com\n\nbody")
    unrelated.write_bytes(b"keep")

    row = {
        "id": "analysis-1",
        "created_at": "2026-01-01T00:00:00Z",
        "sender_address": "sender@example.com",
        "recipient_address": None,
        "subject": "Test",
        "source": "upload",
        "client_ip": None,
        "eml_path": "emails/analysis-1.eml",
        "overall_score": 5.0,
        "rating": "Average",
        "results_json": "{}",
    }
    async with get_db(tmp_path / "mail_tester.db") as conn:
        await insert_analysis(conn, row)

    assert await delete_analysis("analysis-1") is True
    assert not target.exists()
    assert unrelated.exists()
    assert await delete_analysis("analysis-1") is False


def test_stored_path_rejects_traversal(tmp_path, monkeypatch):
    monkeypatch.setenv("MAILTESTER_DATA_DIR", str(tmp_path))
    with pytest.raises(ValueError):
        _stored_eml_path("../outside.eml")
