"""Pytest fixtures for security detector tests."""

from __future__ import annotations

from typing import Dict, List

import pytest

from src.detectors import AuthDetector, SecretsDetector, SQLInjectionDetector
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


@pytest.fixture
def sql_detector() -> SQLInjectionDetector:
    """Provide a SQLInjectionDetector instance."""
    return SQLInjectionDetector()


@pytest.fixture
def secrets_detector() -> SecretsDetector:
    """Provide a SecretsDetector instance."""
    return SecretsDetector()


@pytest.fixture
def auth_detector() -> AuthDetector:
    """Provide an AuthDetector instance."""
    return AuthDetector()


@pytest.fixture
def vulnerable_samples() -> Dict[str, List[Dict[str, str]]]:
    """Provide vulnerable code sample sets grouped by detector."""
    return {
        "sql": SQL_INJECTION_VULNERABLE_SAMPLES,
        "secrets": SECRETS_VULNERABLE_SAMPLES,
        "auth": AUTH_VULNERABLE_SAMPLES,
    }


@pytest.fixture
def secure_samples() -> Dict[str, List[Dict[str, str]]]:
    """Provide secure code sample sets grouped by detector."""
    return {
        "sql": SQL_INJECTION_SECURE_SAMPLES,
        "secrets": SECRETS_SECURE_SAMPLES,
        "auth": AUTH_SECURE_SAMPLES,
    }
