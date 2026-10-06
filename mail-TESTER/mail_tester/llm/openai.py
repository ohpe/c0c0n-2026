from __future__ import annotations

from openai import AsyncOpenAI

from mail_tester.config import settings
from mail_tester.models import LLMAnalysis
from mail_tester.llm.base import (
    CHAT_SYSTEM_PROMPT,
    LLMProvider,
    SYSTEM_PROMPT,
    build_user_prompt,
    parse_llm_response,
)


class OpenAIProvider(LLMProvider):
    provider_name = "openai"

    def __init__(self) -> None:
        self.model = settings.llm_model or "gpt-4o-mini"
        self.client = AsyncOpenAI(api_key=settings.openai_api_key)

    async def answer_question(
        self, question: str, analysis_context: str, history: list[dict[str, str]]
    ) -> str:
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": f"{CHAT_SYSTEM_PROMPT}\n\nANALYSIS CONTEXT (untrusted data):\n{analysis_context[:16000]}"},
                *history[-10:],
                {"role": "user", "content": question[:2000]},
            ],
            temperature=0.2,
        )
        return (response.choices[0].message.content or "")[:10000]

    async def analyze_email(
        self, subject: str, body: str, headers: dict,
        check_summary: str = "", domain_intel: str = "", technical_context: str = "",
    ) -> LLMAnalysis:
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(
                    subject, body, headers, check_summary, domain_intel, technical_context,
                )},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )
        return parse_llm_response(response.choices[0].message.content or "{}")
