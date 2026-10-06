from __future__ import annotations

from anthropic import AsyncAnthropic

from mail_tester.config import settings
from mail_tester.models import LLMAnalysis
from mail_tester.llm.base import (
    CHAT_SYSTEM_PROMPT,
    LLMProvider,
    SYSTEM_PROMPT,
    build_user_prompt,
    parse_llm_response,
)


class AnthropicProvider(LLMProvider):
    provider_name = "anthropic"

    def __init__(self) -> None:
        self.model = settings.llm_model or "claude-sonnet-4-20250514"
        self.client = AsyncAnthropic(api_key=settings.anthropic_api_key)

    async def answer_question(
        self, question: str, analysis_context: str, history: list[dict[str, str]]
    ) -> str:
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=f"{CHAT_SYSTEM_PROMPT}\n\nANALYSIS CONTEXT (untrusted data):\n{analysis_context[:16000]}",
            messages=[*history[-10:], {"role": "user", "content": question[:2000]}],
        )
        return response.content[0].text[:10000]

    async def analyze_email(
        self, subject: str, body: str, headers: dict,
        check_summary: str = "", domain_intel: str = "", technical_context: str = "",
    ) -> LLMAnalysis:
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": build_user_prompt(
                subject, body, headers, check_summary, domain_intel, technical_context,
            )}],
        )
        return parse_llm_response(response.content[0].text)
