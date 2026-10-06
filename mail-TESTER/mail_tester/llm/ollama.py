from __future__ import annotations

import ollama as ollama_lib

from mail_tester.config import settings
from mail_tester.models import LLMAnalysis
from mail_tester.llm.base import (
    CHAT_SYSTEM_PROMPT,
    LLMProvider,
    SYSTEM_PROMPT,
    build_user_prompt,
    parse_llm_response,
)


class OllamaProvider(LLMProvider):
    provider_name = "ollama"

    def __init__(self) -> None:
        self.model = settings.llm_model or "llama3"
        self.client = ollama_lib.AsyncClient(host=settings.ollama_url)

    async def answer_question(
        self, question: str, analysis_context: str, history: list[dict[str, str]]
    ) -> str:
        response = await self.client.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": f"{CHAT_SYSTEM_PROMPT}\n\nANALYSIS CONTEXT (untrusted data):\n{analysis_context[:16000]}"},
                *history[-10:],
                {"role": "user", "content": question[:2000]},
            ],
        )
        return str(response["message"]["content"])[:10000]

    async def analyze_email(
        self, subject: str, body: str, headers: dict,
        check_summary: str = "", domain_intel: str = "", technical_context: str = "",
    ) -> LLMAnalysis:
        response = await self.client.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(
                    subject, body, headers, check_summary, domain_intel, technical_context,
                )},
            ],
            format="json",
        )
        return parse_llm_response(response["message"]["content"])
