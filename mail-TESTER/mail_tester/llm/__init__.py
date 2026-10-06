"""LLM provider package.

The ``get_provider`` factory returns the configured ``LLMProvider``
implementation (or ``None`` when LLM analysis is disabled).  Providers
are lazy-imported to avoid pulling in optional dependencies at import
time.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from mail_tester.config import settings

if TYPE_CHECKING:
    from mail_tester.llm.base import LLMProvider

logger = logging.getLogger(__name__)

_REGISTRY: dict[str, str] = {
    "ollama": "mail_tester.llm.ollama.OllamaProvider",
    "openai": "mail_tester.llm.openai.OpenAIProvider",
    "anthropic": "mail_tester.llm.anthropic.AnthropicProvider",
    "malwarebytes": "mail_tester.llm.malwarebytes.MalwarebytesProvider",
}


def get_provider() -> LLMProvider | None:
    """Return the configured LLM provider instance, or ``None``."""
    name = settings.llm_provider.lower()
    if name in ("none", ""):
        return None

    dotted_path = _REGISTRY.get(name)
    if dotted_path is None:
        logger.warning("Unknown LLM provider: %s, skipping LLM analysis", name)
        return None

    module_path, class_name = dotted_path.rsplit(".", 1)
    import importlib
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls()
