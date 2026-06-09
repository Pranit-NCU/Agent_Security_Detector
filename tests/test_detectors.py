"""Comprehensive unit tests for all security detectors.

This test suite includes:
- Positive tests (vulnerable code should be detected)
- Negative tests (secure code should not be detected)
- Detection quality metrics (TP/FP/TN/FN, precision, recall, F1)
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

import pytest

from src.detectors import CWECategory, Vulnerability, VulnerabilitySeverity
from tests.test_data.secure_code import (
    AUTH_SECURE_SAMPLES,
    SECRETS_SECURE_SAMPLES,
    SQL_INJECTION_SECURE_SAMPLES,
)
from tests.test_data.vulnerable_code import (
    AUTH_VULNERABLE_SAMPLES,
    SECRETS_VULNERABLE_SAMPLES,
    SQL_INJECTION_VULNERABLE_SAMPLES,
)


def _compute_metrics(
    vulnerable_results: Iterable[List[Vulnerability]],
    secure_results: Iterable[List[Vulnerability]],
) -> Dict[str, float]:
    """Compute TP/FP/TN/FN and derived metrics from detector outputs.

    Args:
        vulnerable_results: Detector outputs for vulnerable samples.
        secure_results: Detector outputs for secure samples.

    Returns:
        Dict[str, float]: Metrics including counts and precision/recall/F1.
    """
    vulnerable_results_list = list(vulnerable_results)
    secure_results_list = list(secure_results)

    tp = sum(1 for vulns in vulnerable_results_list if len(vulns) > 0)
    fn = sum(1 for vulns in vulnerable_results_list if len(vulns) == 0)
    fp = sum(1 for vulns in secure_results_list if len(vulns) > 0)
    tn = sum(1 for vulns in secure_results_list if len(vulns) == 0)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "tp": float(tp),
        "fp": float(fp),
        "tn": float(tn),
        "fn": float(fn),
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


class TestSQLInjectionDetector:
    """Tests for SQLInjectionDetector (CWE-89)."""

    @pytest.mark.parametrize(
        "sample",
        SQL_INJECTION_VULNERABLE_SAMPLES[:5],
        ids=[sample["name"] for sample in SQL_INJECTION_VULNERABLE_SAMPLES[:5]],
    )
    def test_positive_detects_sql_injection(self, sql_detector, sample: Dict[str, str]) -> None:
        """Detector should flag vulnerable SQL patterns."""
        vulns = sql_detector.detect(sample["code"])
        assert len(vulns) >= 1, f"Expected vulnerability for sample: {sample['name']}"
        assert vulns[0].cwe == CWECategory.SQL_INJECTION
        assert vulns[0].severity == VulnerabilitySeverity.CRITICAL

    @pytest.mark.parametrize(
        "sample",
        SQL_INJECTION_SECURE_SAMPLES[:5],
        ids=[sample["name"] for sample in SQL_INJECTION_SECURE_SAMPLES[:5]],
    )
    def test_negative_allows_parameterized_sql(self, sql_detector, sample: Dict[str, str]) -> None:
        """Detector should not flag secure parameterized SQL patterns."""
        vulns = sql_detector.detect(sample["code"])
        assert len(vulns) == 0, f"Unexpected vulnerability for safe sample: {sample['name']}"

    def test_metrics_sql_detector(self, sql_detector) -> None:
        """SQL detector should achieve expected TP/FP/TN/FN on curated data."""
        vulnerable_results = [sql_detector.detect(s["code"]) for s in SQL_INJECTION_VULNERABLE_SAMPLES]
        secure_results = [sql_detector.detect(s["code"]) for s in SQL_INJECTION_SECURE_SAMPLES]

        metrics = _compute_metrics(vulnerable_results, secure_results)

        assert metrics["tp"] == float(len(SQL_INJECTION_VULNERABLE_SAMPLES))
        assert metrics["fp"] == 0.0
        assert metrics["tn"] == float(len(SQL_INJECTION_SECURE_SAMPLES))
        assert metrics["fn"] == 0.0
        assert metrics["precision"] == pytest.approx(1.0)
        assert metrics["recall"] == pytest.approx(1.0)
        assert metrics["f1"] == pytest.approx(1.0)


class TestSecretsDetector:
    """Tests for SecretsDetector (CWE-798)."""

    @pytest.mark.parametrize(
        "sample",
        SECRETS_VULNERABLE_SAMPLES[:5],
        ids=[sample["name"] for sample in SECRETS_VULNERABLE_SAMPLES[:5]],
    )
    def test_positive_detects_hardcoded_secrets(self, secrets_detector, sample: Dict[str, str]) -> None:
        """Detector should flag hardcoded secrets and tokens."""
        vulns = secrets_detector.detect(sample["code"])
        assert len(vulns) >= 1, f"Expected vulnerability for sample: {sample['name']}"
        assert vulns[0].cwe == CWECategory.HARDCODED_SECRETS
        assert vulns[0].severity == VulnerabilitySeverity.CRITICAL

    @pytest.mark.parametrize(
        "sample",
        SECRETS_SECURE_SAMPLES[:5],
        ids=[sample["name"] for sample in SECRETS_SECURE_SAMPLES[:5]],
    )
    def test_negative_allows_safe_secret_loading(self, secrets_detector, sample: Dict[str, str]) -> None:
        """Detector should not flag environment/config/vault based loading."""
        vulns = secrets_detector.detect(sample["code"])
        assert len(vulns) == 0, f"Unexpected vulnerability for safe sample: {sample['name']}"

    def test_metrics_secrets_detector(self, secrets_detector) -> None:
        """Secrets detector should achieve expected TP/FP/TN/FN on curated data."""
        vulnerable_results = [secrets_detector.detect(s["code"]) for s in SECRETS_VULNERABLE_SAMPLES]
        secure_results = [secrets_detector.detect(s["code"]) for s in SECRETS_SECURE_SAMPLES]

        metrics = _compute_metrics(vulnerable_results, secure_results)

        assert metrics["tp"] == float(len(SECRETS_VULNERABLE_SAMPLES))
        assert metrics["fp"] == 0.0
        assert metrics["tn"] == float(len(SECRETS_SECURE_SAMPLES))
        assert metrics["fn"] == 0.0
        assert metrics["precision"] == pytest.approx(1.0)
        assert metrics["recall"] == pytest.approx(1.0)
        assert metrics["f1"] == pytest.approx(1.0)


class TestAuthDetector:
    """Tests for AuthDetector (CWE-287)."""

    @pytest.mark.parametrize(
        "sample",
        AUTH_VULNERABLE_SAMPLES[:5],
        ids=[sample["name"] for sample in AUTH_VULNERABLE_SAMPLES[:5]],
    )
    def test_positive_detects_unprotected_routes(self, auth_detector, sample: Dict[str, str]) -> None:
        """Detector should flag protected endpoints missing auth decorators."""
        vulns = auth_detector.detect(sample["code"])
        assert len(vulns) >= 1, f"Expected vulnerability for sample: {sample['name']}"
        assert vulns[0].cwe == CWECategory.AUTH_BYPASS
        assert vulns[0].severity in (VulnerabilitySeverity.HIGH, VulnerabilitySeverity.INFO)

    @pytest.mark.parametrize(
        "sample",
        AUTH_SECURE_SAMPLES[:5],
        ids=[sample["name"] for sample in AUTH_SECURE_SAMPLES[:5]],
    )
    def test_negative_allows_protected_routes(self, auth_detector, sample: Dict[str, str]) -> None:
        """Detector should not flag routes with explicit auth mechanisms."""
        vulns = auth_detector.detect(sample["code"])
        assert len(vulns) == 0, f"Unexpected vulnerability for safe sample: {sample['name']}"

    def test_metrics_auth_detector(self, auth_detector) -> None:
        """Auth detector should achieve expected TP/FP/TN/FN on curated data."""
        vulnerable_results = [auth_detector.detect(s["code"]) for s in AUTH_VULNERABLE_SAMPLES]
        secure_results = [auth_detector.detect(s["code"]) for s in AUTH_SECURE_SAMPLES]

        metrics = _compute_metrics(vulnerable_results, secure_results)

        assert metrics["tp"] == float(len(AUTH_VULNERABLE_SAMPLES))
        assert metrics["fp"] == 0.0
        assert metrics["tn"] == float(len(AUTH_SECURE_SAMPLES))
        assert metrics["fn"] == 0.0
        assert metrics["precision"] == pytest.approx(1.0)
        assert metrics["recall"] == pytest.approx(1.0)
        assert metrics["f1"] == pytest.approx(1.0)


class TestDetectorContracts:
    """Cross-detector contract tests for result shape and ordering expectations."""

    @pytest.mark.parametrize(
        "detector_fixture_name,sample,expected_cwe",
        [
            ("sql_detector", SQL_INJECTION_VULNERABLE_SAMPLES[0], CWECategory.SQL_INJECTION),
            ("secrets_detector", SECRETS_VULNERABLE_SAMPLES[0], CWECategory.HARDCODED_SECRETS),
            ("auth_detector", AUTH_VULNERABLE_SAMPLES[0], CWECategory.AUTH_BYPASS),
        ],
        ids=["sql_contract", "secrets_contract", "auth_contract"],
    )
    def test_vulnerability_contract_fields(
        self,
        request: pytest.FixtureRequest,
        detector_fixture_name: str,
        sample: Dict[str, str],
        expected_cwe: CWECategory,
    ) -> None:
        """Detected vulnerabilities should expose valid dataclass fields."""
        detector = request.getfixturevalue(detector_fixture_name)
        vulns = detector.detect(sample["code"])

        assert vulns, f"Expected vulnerability for sample: {sample['name']}"
        vuln = vulns[0]
        assert vuln.cwe == expected_cwe
        assert isinstance(vuln.line_number, int)
        assert 0.0 <= vuln.confidence <= 1.0
        assert vuln.detection_method == "SAST"
        assert isinstance(vuln.remediation, str) and vuln.remediation
