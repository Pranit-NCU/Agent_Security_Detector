"""Shared live-judge factory — the single source of truth for provider selection.

Before this module, ``_build_judges`` was copy-pasted into experiments B, C, D
and E. Adding a provider (e.g. Together AI) meant editing four near-identical
blocks. This module centralises the priority chain so a provider is wired **once**.

Analogy: think of it as a **hiring panel**. ``build_real_judges`` walks a fixed
priority list of candidates (providers), hires whoever has valid credentials
(an API key), and returns the panel. Each experiment then decides what to do if
the panel is empty (fall back to its own mock judges).

Priority chain (architectural-diversity design for Fleiss kappa)
----------------------------------------------------------------
    1. OpenRouter (Cohere)   -- cohere/north-mini-code:free   (Cohere family)
    2. OpenRouter (Poolside) -- poolside/laguna-xs-2.1:free   (Poolside family)
    3. Mistral               -- open-mistral-nemo             (Mistral family)
    4. Groq                  -- llama-3.1-8b-instant          (Meta family; 4th judge, ADR-001 Option D)
    5. HuggingFace Router    -- Google Gemma 3 27B     (optional; quota often exhausted)
    6. Cerebras              -- gpt-oss-120b            (optional; requires payment on file)
    7. Together AI           -- Llama 3.3 70B (Free)    (optional, opt-in)
    8. SambaNova             -- Llama 3.3 70B           (optional; fallback if no Cerebras)
    9. Gemini                -- gemini-1.5-flash        (emergency, only if empty)

Providers 1–4 form the intended 4-family payment-free panel and are the
**only** providers that require zero payment method or credit card across the
board (OpenRouter's :free-suffixed models, Mistral's free "Experiment" plan,
and Groq's free tier -- verified 30 req/min, 14,400 req/day, no card, at
console.groq.com/docs/rate-limits). Providers 5–9 are kept for backward
compatibility and optional extra judges, but HuggingFace's free quota is
frequently exhausted and Cerebras requires a payment method on file, so
neither is part of the payment-free default panel.
"""

from __future__ import annotations

import os
from typing import List

from .base_judge import BaseLLMJudge, JudgeConfig


def _add(judges: List[BaseLLMJudge], tag: str, provider: str, builder) -> None:
    """Attempt to build one provider's judges; log success/failure uniformly."""
    try:
        added = builder()
        judges.extend(added)
        names = [j.config.model_name for j in added]
        print(f"[{tag}] Using {provider} judges: {names}")
    except Exception as exc:  # noqa: BLE001 — provider errors must never crash a run
        print(f"[{tag}] {provider} judges unavailable ({exc})")


def build_real_judges(
    force_mock: bool,
    *,
    tag: str = "Exp",
    include_gemini_fallback: bool = True,
) -> List[BaseLLMJudge]:
    """Return the list of live LLM judges available from the current environment.

    Parameters
    ----------
    force_mock:
        If True, returns an empty list immediately (caller supplies mocks).
    tag:
        Log prefix, e.g. ``"Exp D"``.
    include_gemini_fallback:
        If True and no other judge was built, try Gemini as a last resort.

    Returns
    -------
    list[BaseLLMJudge]
        Possibly empty. The caller is responsible for the mock fallback.
    """
    judges: List[BaseLLMJudge] = []
    if force_mock:
        return judges

    # 1-2. OpenRouter (Cohere North Mini Code + Poolside Laguna XS 2.1)
    # Both genuinely free, no credit card required. Primary payment-free panel.
    if os.getenv("OPENROUTER_API_KEY", "").strip():
        def _openrouter():
            from .openrouter_judge import OPENROUTER_RECOMMENDED_MODELS, make_openrouter_judge
            return [make_openrouter_judge(m) for m in OPENROUTER_RECOMMENDED_MODELS]
        _add(judges, tag, "OpenRouter", _openrouter)

    # 3. Mistral (open-mistral-nemo — Mistral family, direct API)
    if os.getenv("MISTRAL_API_KEY", "").strip():
        def _mistral():
            from .mistral_judge import MISTRAL_RECOMMENDED_MODELS, make_mistral_judge
            return [make_mistral_judge(m) for m in MISTRAL_RECOMMENDED_MODELS]
        _add(judges, tag, "Mistral", _mistral)

    # 4. Groq (llama-3.1-8b-instant — Meta family, 4th judge; ADR-001 Option D)
    if os.getenv("GROQ_API_KEY", "").strip():
        def _groq():
            from .groq_judge import GROQ_RECOMMENDED_MODELS, make_groq_judge
            return [make_groq_judge(m) for m in GROQ_RECOMMENDED_MODELS]
        _add(judges, tag, "Groq", _groq)

    # 5. HuggingFace Router (Gemma 3 27B — Google family; optional, quota-risk)
    if (os.getenv("HF_API_KEY", "").strip()
            or os.getenv("HUGGINGFACE_API_KEY", "").strip()):
        def _hf():
            from .huggingface_judge import RECOMMENDED_MODELS, make_hf_judge
            return [make_hf_judge(m) for m in RECOMMENDED_MODELS]
        _add(judges, tag, "HF", _hf)

    # 6. Cerebras (gpt-oss-120b — OpenAI family; optional, requires payment on file)
    cerebras_key = os.getenv("CEREBRAS_API_KEY", "").strip()
    if cerebras_key:
        def _cerebras():
            from .cerebras_judge import CEREBRAS_RECOMMENDED_MODELS, make_cerebras_judge
            return [make_cerebras_judge(m) for m in CEREBRAS_RECOMMENDED_MODELS]
        _add(judges, tag, "Cerebras", _cerebras)

    # 7. Together AI (Llama 3.3 70B Free — Meta family, opt-in via key presence)
    if os.getenv("TOGETHER_API_KEY", "").strip():
        def _together():
            from .together_judge import TOGETHER_RECOMMENDED_MODELS, make_together_judge
            return [make_together_judge(m) for m in TOGETHER_RECOMMENDED_MODELS]
        _add(judges, tag, "Together", _together)

    # 8. SambaNova (Llama 3.3 70B — fallback only when Cerebras absent)
    if not cerebras_key and os.getenv("SAMBANOVA_API_KEY", "").strip():
        def _sambanova():
            from .sambanova_judge import SAMBANOVA_RECOMMENDED_MODELS, make_sambanova_judge
            return [make_sambanova_judge(m) for m in SAMBANOVA_RECOMMENDED_MODELS]
        _add(judges, tag, "SambaNova (Cerebras fallback)", _sambanova)

    # 9. Gemini (emergency — only if nothing else was built)
    if include_gemini_fallback and not judges and os.getenv("GEMINI_API_KEY", "").strip():
        def _gemini():
            from .gemini_judge import GeminiJudge
            return [GeminiJudge(JudgeConfig(model_name="gemini-1.5-flash"))]
        _add(judges, tag, "Gemini", _gemini)

    return judges
