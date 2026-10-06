from __future__ import annotations

from mail_tester.llm.base import SYSTEM_PROMPT, build_user_prompt
from mail_tester.models import HeaderEvidence, TechnicalReport
from mail_tester.services.chat_service import _context
from mail_tester.models import AnalysisResult


def test_system_prompt_explains_cc_and_header_answer_structure():
    assert "Cc is a visible carbon-copy recipient" in SYSTEM_PROMPT
    assert "OBSERVED VALUE" in SYSTEM_PROMPT
    assert "If Cc/Bcc is absent" in SYSTEM_PROMPT


def test_initial_prompt_preserves_cc_and_authentication_headers():
    prompt = build_user_prompt(
        "Subject", "body", {
            "From": "a@example.com",
            "Cc": "copy@example.net",
            "Authentication-Results": "mx; dkim=pass",
            "Received": "from mx.example by local.example; timestamp",
        }
    )
    assert "Cc: copy@example.net" in prompt
    assert "Authentication-Results: mx; dkim=pass" in prompt
    assert "Received: from mx.example" in prompt


def test_chat_context_contains_header_inventory_and_absence_marker():
    result = AnalysisResult(
        id="header-chat",
        created_at="2026-01-01T00:00:00Z",
        source="upload",
        overall_score=5,
        rating="Average",
        checks=[],
        recommendations=[],
        technical_report=TechnicalReport(
            header_inventory=[HeaderEvidence(name="Cc", value="copy@example.net")]
        ),
    )
    context = _context(result)
    assert "OBSERVED HEADER Cc" in context
    assert "copy@example.net" in context
    assert "RECEIVED HOP TABLE" in context
