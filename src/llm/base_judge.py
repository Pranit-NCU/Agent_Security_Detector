"""Base abstractions for semantic vulnerability judges backed by LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import json
import logging
import time
from typing import Any, Mapping, Optional, Sequence, TypedDict

from .prompt_builder import build_security_validation_prompt
from .response_parser import parse_model_json


LOGGER = logging.getLogger(__name__)


class LLMResponseSchema(TypedDict):
    """Standardized JSON output expected from all LLM judges."""

    is_vulnerable: bool
    cwe: str
    severity: str
    confidence: float
    reasoning: str
    exploitability: str
    recommended_fix: str
    false_positive_probability: float


@dataclass(frozen=True)
class JudgeConfig:
    """Common judge configuration used by all provider implementations."""

    model_name: str
    timeout_seconds: float = 30.0
    max_retries: int = 2
    retry_backoff_seconds: float = 0.75
    temperature: float = 0.0

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0.0:
            raise ValueError("timeout_seconds must be greater than 0")
        if self.max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if self.retry_backoff_seconds < 0.0:
            raise ValueError("retry_backoff_seconds must be >= 0")
        if not 0.0 <= self.temperature <= 2.0:
            raise ValueError("temperature must be in range [0.0, 2.0]")


@dataclass(frozen=True)
class JudgeResult:
    """Structured output returned by one judge for one candidate vulnerability."""

    model_name: str
    is_vulnerable: bool
    vulnerability_type: str
    cwe: str
    severity: str
    confidence: float
    reasoning: str
    exploitability: str
    remediation: str
    raw_response: str
    latency_ms: float

    def __post_init__(self) -> None:
        if not self.model_name:
            raise ValueError("model_name must not be empty")
        if not self.cwe:
            raise ValueError("cwe must not be empty")
        if not self.vulnerability_type:
            raise ValueError("vulnerability_type must not be empty")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in range [0.0, 1.0]")
        if self.latency_ms < 0.0:
            raise ValueError("latency_ms must be >= 0")


class BaseLLMJudge(ABC):
    """Provider-agnostic base class for semantic vulnerability judges."""

    def __init__(self, config: JudgeConfig) -> None:
        self.config = config

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name used for logging and metrics."""

    @abstractmethod
    def _invoke_model(self, prompt: str) -> str:
        """Invoke provider with prompt and return the model textual response."""

    def analyze_code(
        self,
        code_snippet: str,
        sast_findings: Sequence[Mapping[str, Any]],
        *,
        security_policy: Optional[str] = None,
    ) -> JudgeResult:
        """Build prompt, invoke model, parse JSON output, and return JudgeResult."""
        prompt = self.build_prompt(
            code_snippet=code_snippet,
            sast_findings=sast_findings,
            security_policy=security_policy,
        )

        start = time.perf_counter()
        raw_response = self._invoke_model(prompt)
        latency_ms = (time.perf_counter() - start) * 1000.0

        parsed = self.parse_response(raw_response)
        self.validate_output(parsed)

        vulnerability_type = "UNKNOWN"
        if isinstance(sast_findings, Sequence) and len(sast_findings) > 0:
            first_finding = sast_findings[0]
            vulnerability_type = str(first_finding.get("type", "UNKNOWN"))

        return JudgeResult(
            model_name=self.config.model_name,
            is_vulnerable=bool(parsed["is_vulnerable"]),
            vulnerability_type=vulnerability_type,
            cwe=str(parsed["cwe"]),
            severity=str(parsed["severity"]),
            confidence=float(parsed["confidence"]),
            reasoning=str(parsed["reasoning"]),
            exploitability=str(parsed["exploitability"]),
            remediation=str(parsed["recommended_fix"]),
            raw_response=raw_response,
            latency_ms=latency_ms,
        )

    def build_prompt(
        self,
        code_snippet: str,
        sast_findings: Sequence[Mapping[str, Any]],
        *,
        security_policy: Optional[str] = None,
    ) -> str:
        """Create a standardized and reproducible security judging prompt."""
        return build_security_validation_prompt(
            code_snippet=code_snippet,
            sast_findings=sast_findings,
            security_policy=security_policy,
        )

    def parse_response(self, raw_response: str) -> LLMResponseSchema:
        """Parse and normalize raw model output into the canonical schema."""
        return parse_model_json(raw_response)

    def validate_output(self, output: dict[str, Any]) -> None:
        """Defensively validate schema correctness before conversion to JudgeResult."""
        required_keys = {
            "is_vulnerable",
            "cwe",
            "severity",
            "confidence",
            "reasoning",
            "exploitability",
            "recommended_fix",
            "false_positive_probability",
        }

        missing = required_keys.difference(output.keys())
        if missing:
            raise ValueError(f"Missing required output keys: {sorted(missing)}")

        confidence = float(output["confidence"])
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be in range [0.0, 1.0]")

        false_positive_probability = float(output["false_positive_probability"])
        if not 0.0 <= false_positive_probability <= 1.0:
            raise ValueError("false_positive_probability must be in range [0.0, 1.0]")

    def _parse_json_response(self, raw_payload: str) -> Any:
        """Helper for providers that need to inspect provider wrapper payloads."""
        try:
            parsed = json.loads(raw_payload)
            return parsed
        except json.JSONDecodeError as exc:
            LOGGER.error(
                "Provider payload is not valid JSON for model=%s provider=%s",
                self.config.model_name,
                self.provider_name,
            )
            raise ValueError("Provider payload is not valid JSON") from exc
