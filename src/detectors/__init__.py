"""
Security detection framework for analyzing vulnerabilities in AI-generated code.

This module provides the foundational classes and enums for building a modular
security vulnerability detection system. Each detector class can inherit from
SecurityDetector to implement specific vulnerability checks.

The framework follows OWASP and CWE Top 25 standards for classification and
supports multiple detection methods (SAST, Pattern matching, LLM-based analysis).

Classes:
    VulnerabilitySeverity: Enum defining severity levels (CRITICAL to INFO)
    CWECategory: Enum for CWE classification standards
    Vulnerability: Dataclass representing a single detected vulnerability
    SecurityScore: Dataclass containing aggregated security analysis results
    SecurityDetector: Abstract base class for implementing specific detectors

Example:
    Basic usage of the security detection framework:
    
    >>> detector = MySecurityDetector("detector_name")
    >>> results = detector.analyze_file("code.py")
    >>> print(results.summary())
    >>> for rec in results.recommendations:
    ...     print(f"- {rec}")
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
import math
import re
from typing import List, Dict, Any
from pathlib import Path


class VulnerabilitySeverity(Enum):
    """
    Enumeration of vulnerability severity levels.

    Severity levels are ordered from highest to lowest risk. Each level has
    an associated numeric value for scoring calculations, enabling quantitative
    risk assessment.

    Attributes:
        CRITICAL (int): Highest risk level, immediate remediation required (value: 4)
        HIGH (int): Significant security risk, address promptly (value: 3)
        MEDIUM (int): Moderate risk, should be addressed (value: 2)
        LOW (int): Minor security issue, lower priority (value: 1)
        INFO (int): Informational finding, no immediate action (value: 0)
    """

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


class CWECategory(Enum):
    """
    Enumeration of Common Weakness Enumeration (CWE) categories.

    Maps CWE identifiers to their standardized descriptions. Used for
    categorizing detected vulnerabilities according to OWASP and CWE Top 25
    standards, enabling consistent vulnerability classification across
    different detection methods.

    Attributes:
        CWE_89: SQL Injection vulnerabilities
        CWE_79: Cross-Site Scripting (XSS) vulnerabilities
        CWE_120: Buffer Overflow/Buffer Over-read vulnerabilities
        CWE_798: Hardcoded credentials and secrets
        CWE_327: Use of weak cryptographic algorithms
        CWE_287: Improper Authentication mechanisms
        CWE_20: Improper Input Validation
        CWE_209: Information Exposure in Error Messages
    """

    CWE_89 = "CWE-89"  # SQL Injection
    SQL_INJECTION = "CWE-89"  # Alias for SQL Injection
    CWE_79 = "CWE-79"  # Cross-Site Scripting (XSS)
    CWE_120 = "CWE-120"  # Buffer Overflow
    CWE_798 = "CWE-798"  # Hardcoded Secrets
    HARDCODED_SECRETS = "CWE-798"  # Alias for Hardcoded Secrets
    CWE_327 = "CWE-327"  # Weak Cryptography
    CWE_287 = "CWE-287"  # Authentication Bypass
    AUTH_BYPASS = "CWE-287"  # Alias for Authentication Bypass
    CWE_20 = "CWE-20"  # Improper Input Validation
    CWE_209 = "CWE-209"  # Information Exposure in Error Messages


@dataclass
class Vulnerability:
    """
    Represents a single detected security vulnerability.

    This dataclass encapsulates all information about a detected vulnerability,
    including its classification, location, remediation guidance, and detection
    confidence. Objects are JSON-serializable for reporting and persistence.

    Attributes:
        cwe: The CWE category this vulnerability belongs to
        severity: The severity level of the vulnerability
        line_number: The line number in the source code where vulnerability detected
        description: Human-readable explanation of the vulnerability and its impact
        code_snippet: The exact code snippet from the source containing the issue
        remediation: Suggested fix steps or remediation guidance
        confidence: Confidence score (0.0-1.0) indicating detection certainty
        detection_method: Detection technique used (e.g., "SAST", "Pattern", "LLM")

    Raises:
        ValueError: If confidence is not in range [0.0, 1.0] or line_number < 1
    """

    cwe: CWECategory
    severity: VulnerabilitySeverity
    line_number: int
    description: str
    code_snippet: str
    remediation: str
    confidence: float
    detection_method: str

    def __post_init__(self) -> None:
        """
        Validate vulnerability data after initialization.

        Ensures that confidence scores are in valid range and line numbers
        are positive integers, raising ValueError for invalid data.

        Raises:
            ValueError: If validation checks fail
        """
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"Confidence must be between 0.0 and 1.0, got {self.confidence}"
            )
        if self.line_number < 1:
            raise ValueError(f"Line number must be >= 1, got {self.line_number}")

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert vulnerability to dictionary for JSON serialization.

        Transforms the dataclass instance into a dictionary with serializable
        values, converting enums to their string representations.

        Returns:
            Dict[str, Any]: Dictionary representation ready for JSON serialization
        """
        return {
            "cwe": self.cwe.value,
            "severity": self.severity.name,
            "line_number": self.line_number,
            "description": self.description,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "confidence": round(self.confidence, 2),
            "detection_method": self.detection_method,
        }

    def __repr__(self) -> str:
        """
        Return a readable string representation of the vulnerability.

        Provides a compact, human-readable format useful for logging and
        debugging, showing the most critical information at a glance.

        Returns:
            str: Formatted vulnerability representation
        """
        return (
            f"Vulnerability("
            f"cwe={self.cwe.value}, "
            f"severity={self.severity.name}, "
            f"line={self.line_number}, "
            f"confidence={self.confidence:.2f}, "
            f"method={self.detection_method})"
        )


@dataclass
class SecurityScore:
    """
    Aggregated security analysis results for a code file or project.

    This dataclass summarizes the complete security assessment including
    detailed vulnerability counts, computed risk score, pass/fail status,
    and actionable remediation recommendations.

    Attributes:
        vulnerabilities: List of all detected Vulnerability objects
        critical_count: Number of CRITICAL severity vulnerabilities found
        high_count: Number of HIGH severity vulnerabilities found
        medium_count: Number of MEDIUM severity vulnerabilities found
        low_count: Number of LOW severity vulnerabilities found
        overall_score: Computed security score from 0.0 to 100.0 (higher is better)
        passed: Boolean indicating analysis passed (no CRITICAL or HIGH issues)
        recommendations: List of remediation recommendations grouped by CWE type
    """

    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    overall_score: float = 100.0
    passed: bool = True
    recommendations: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """
        Generate a brief summary of the security analysis.

        Creates a concise, human-readable summary suitable for reports,
        logs, or console output, indicating pass/fail status and key metrics.

        Returns:
            str: Concise summary string with status, vulnerability counts, and score
        """
        status = "✓ PASSED" if self.passed else "✗ FAILED"
        total = len(self.vulnerabilities)

        if total == 0:
            return (
                f"{status}: No vulnerabilities detected. "
                f"Score: {self.overall_score:.1f}/100"
            )

        return (
            f"{status}: Found {total} vulnerability(ies) "
            f"(Critical: {self.critical_count}, High: {self.high_count}, "
            f"Medium: {self.medium_count}, Low: {self.low_count}). "
            f"Score: {self.overall_score:.1f}/100"
        )


class SecurityDetector(ABC):
    """
    Abstract base class for security vulnerability detectors.

    This class provides a framework for implementing specific vulnerability
    detection strategies. Subclasses must implement the detect() method and
    may override other methods for custom behavior. The class handles file I/O,
    scoring calculations, and recommendation generation.

    Attributes:
        detector_name: Name of the detector for identification in logging/reports

    Example:
        Implementing a specific detector by subclassing:

        >>> class SQLInjectionDetector(SecurityDetector):
        ...     def detect(self, code: str) -> List[Vulnerability]:
        ...         # Implement SQL injection detection logic
        ...         pass
        ...
        >>> detector = SQLInjectionDetector("sql_detector")
        >>> results = detector.analyze_file("script.py")
    """

    def __init__(self, detector_name: str = "SecurityDetector") -> None:
        """
        Initialize the security detector.

        Args:
            detector_name: Name for this detector instance used in reporting
        """
        self.detector_name = detector_name

    @abstractmethod
    def detect(self, code: str) -> List[Vulnerability]:
        """
        Detect vulnerabilities in the provided code.

        This method must be implemented by subclasses to perform specific
        vulnerability detection logic. The method receives source code as
        a string and returns a list of detected vulnerabilities.

        Args:
            code: Source code string to analyze for vulnerabilities

        Returns:
            List[Vulnerability]: List of detected vulnerabilities, or empty list
                if no vulnerabilities found

        Example:
            >>> code = "query = 'SELECT * FROM users WHERE id=' + user_id"
            >>> vulns = detector.detect(code)
            >>> print(len(vulns))  # 1 or more vulnerabilities
        """
        pass

    def analyze_file(self, filepath: str) -> SecurityScore:
        """
        Analyze a Python file for security vulnerabilities.

        Reads the specified file, runs vulnerability detection, calculates
        the overall security score, and generates recommendations. This is
        the main entry point for analyzing complete files.

        Args:
            filepath: Path to the Python file to analyze (absolute or relative)

        Returns:
            SecurityScore: Aggregated security analysis results with
                vulnerabilities, counts, score, pass/fail status, and recommendations

        Raises:
            FileNotFoundError: If the specified file does not exist
            IOError: If the file cannot be read (permission issues, encoding, etc.)

        Example:
            >>> detector = MyDetector("detector")
            >>> try:
            ...     results = detector.analyze_file("vulnerable.py")
            ...     print(results.summary())
            ... except FileNotFoundError as e:
            ...     print(f"File error: {e}")
        """
        try:
            file_path = Path(filepath)
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {filepath}")

            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
        except (FileNotFoundError, IOError) as e:
            raise IOError(f"Failed to read file {filepath}: {str(e)}") from e

        # Run detection
        vulnerabilities = self.detect(code)

        # Calculate score and recommendations
        overall_score = self._calculate_score(vulnerabilities)
        recommendations = self._generate_recommendations(vulnerabilities)

        # Count vulnerabilities by severity
        critical_count = sum(
            1
            for v in vulnerabilities
            if v.severity == VulnerabilitySeverity.CRITICAL
        )
        high_count = sum(
            1 for v in vulnerabilities if v.severity == VulnerabilitySeverity.HIGH
        )
        medium_count = sum(
            1
            for v in vulnerabilities
            if v.severity == VulnerabilitySeverity.MEDIUM
        )
        low_count = sum(
            1 for v in vulnerabilities if v.severity == VulnerabilitySeverity.LOW
        )

        # Determine if analysis passed (no critical or high severity issues)
        passed = critical_count == 0 and high_count == 0

        return SecurityScore(
            vulnerabilities=vulnerabilities,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            overall_score=overall_score,
            passed=passed,
            recommendations=recommendations,
        )

    def _calculate_score(self, vulnerabilities: List[Vulnerability]) -> float:
        """
        Calculate overall security score based on detected vulnerabilities.

        Uses a point-deduction scoring system where each vulnerability reduces
        the score by a severity-based amount. Score is clamped to [0.0, 100.0].

        Scoring formula:
            - Start with 100.0 points
            - Deduct 20 points for each CRITICAL vulnerability
            - Deduct 10 points for each HIGH vulnerability
            - Deduct 5 points for each MEDIUM vulnerability
            - Deduct 2 points for each LOW vulnerability
            - Clamp result to [0.0, 100.0] range

        Args:
            vulnerabilities: List of detected vulnerabilities to score

        Returns:
            float: Security score from 0.0 (unsafe) to 100.0 (no issues)

        Example:
            >>> vulns = [Vulnerability(..., severity=VulnerabilitySeverity.HIGH)]
            >>> score = detector._calculate_score(vulns)
            >>> print(score)  # 90.0
        """
        score = 100.0

        for vuln in vulnerabilities:
            if vuln.severity == VulnerabilitySeverity.CRITICAL:
                score -= 20
            elif vuln.severity == VulnerabilitySeverity.HIGH:
                score -= 10
            elif vuln.severity == VulnerabilitySeverity.MEDIUM:
                score -= 5
            elif vuln.severity == VulnerabilitySeverity.LOW:
                score -= 2

        # Clamp score between 0 and 100
        return max(0.0, min(100.0, score))

    def _generate_recommendations(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[str]:
        """
        Generate remediation recommendations from detected vulnerabilities.

        Groups vulnerabilities by CWE category and returns one recommendation
        per unique CWE type. When multiple vulnerabilities of the same CWE
        exist, uses the remediation from the highest severity occurrence.

        Args:
            vulnerabilities: List of detected vulnerabilities to process

        Returns:
            List[str]: Remediation recommendations, one per unique CWE type.
                Empty list if no vulnerabilities provided.

        Example:
            >>> vulns = [
            ...     Vulnerability(..., cwe=CWECategory.CWE_89, severity=HIGH),
            ...     Vulnerability(..., cwe=CWECategory.CWE_79, severity=MEDIUM),
            ... ]
            >>> recs = detector._generate_recommendations(vulns)
            >>> print(len(recs))  # 2
        """
        cwe_recommendations: Dict[str, tuple] = {}

        for vuln in vulnerabilities:
            cwe_key = vuln.cwe.value
            current_severity = vuln.severity.value

            # Keep the remediation for the highest severity of each CWE
            if (
                cwe_key not in cwe_recommendations
                or current_severity > cwe_recommendations[cwe_key][1]
            ):
                cwe_recommendations[cwe_key] = (vuln.remediation, current_severity)

        return [remediation for remediation, _ in cwe_recommendations.values()]


class SQLInjectionDetector(SecurityDetector):
    """Detect SQL injection vulnerabilities (CWE-89) in Python source code.

    This detector identifies unsafe SQL query construction patterns commonly
    seen in AI-generated code, including f-string interpolation, string
    concatenation, and use of ``.format()`` on SQL query strings.

    Detection strategy:
        1. Parse source code line by line.
        2. Skip comment-only and empty lines.
        3. Check SQL keyword presence.
        4. Check for vulnerable construction patterns.
        5. Suppress likely false positives when nearby execution appears
           parameterized.

    All findings are emitted as CRITICAL severity with high confidence because
    the patterns represent direct user-input interpolation into SQL commands.
    """

    _SQL_KEYWORDS = re.compile(
        r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b",
        re.IGNORECASE,
    )
    _VULNERABLE_FSTRING = re.compile(
        r"\bf[\"'][^\n]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b[^\n]*\{[^}]+}",
        re.IGNORECASE,
    )
    _VULNERABLE_CONCAT = re.compile(
        r"[\"'][^\n]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b[^\n]*[\"']\s*\+",
        re.IGNORECASE,
    )
    _VULNERABLE_FORMAT = re.compile(
        r"[\"'][^\n]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b[^\n]*[\"']\s*\.format\(",
        re.IGNORECASE,
    )
    _SAFE_EXECUTE_PLACEHOLDER = re.compile(
        r"execute\(\s*[\"'][^\"']*(?:\?|%s|:[A-Za-z_][A-Za-z0-9_]*)[^\"']*[\"']",
        re.IGNORECASE,
    )
    _SAFE_EXECUTE_LIST_ARGS = re.compile(r"execute\([^\n]*\[[^\]]+\]", re.IGNORECASE)
    _SAFE_EXECUTE_TUPLE_ARGS = re.compile(r"execute\([^\n]*\([^\)]*\)", re.IGNORECASE)

    _REMEDIATION = (
        "Use parameterized queries to prevent SQL injection. Example: "
        "execute('SELECT * FROM users WHERE email = ?', [email])"
    )

    def __init__(self, detector_name: str = "SQLInjectionDetector") -> None:
        """Initialize the SQL injection detector.

        Args:
            detector_name: Optional detector name for reporting and logging.
        """
        super().__init__(detector_name=detector_name)

    def detect(self, code: str) -> List[Vulnerability]:
        """Detect SQL injection vulnerabilities in source code.

        Args:
            code: Python source code to analyze.

        Returns:
            List[Vulnerability]: Detected CWE-89 findings.
        """
        vulnerabilities: List[Vulnerability] = []
        lines = code.splitlines()

        for index, raw_line in enumerate(lines):
            line_number = index + 1
            stripped = raw_line.strip()

            # Skip empty lines and comment-only lines.
            if not stripped or stripped.startswith("#"):
                continue

            if not self._is_sql_query(raw_line):
                continue

            if not self._has_vulnerable_pattern(raw_line):
                continue

            # Reduce false positives: skip if nearby execution appears parameterized.
            if self._has_nearby_parameterized_usage(lines, index):
                continue

            vulnerabilities.append(
                Vulnerability(
                    cwe=CWECategory.SQL_INJECTION,
                    severity=VulnerabilitySeverity.CRITICAL,
                    line_number=line_number,
                    description=(
                        "Potential SQL injection: SQL command is built using "
                        "string interpolation/concatenation instead of "
                        "parameterized execution."
                    ),
                    code_snippet=stripped,
                    remediation=self._REMEDIATION,
                    confidence=0.95,
                    detection_method="SAST",
                )
            )

        return vulnerabilities

    def _is_sql_query(self, line: str) -> bool:
        """Return whether a line appears to contain SQL query text.

        Args:
            line: Source code line.

        Returns:
            bool: True when a SQL keyword is present and the line likely
                represents SQL text.
        """
        if not self._SQL_KEYWORDS.search(line):
            return False

        # Ignore clear SQL schema/comment strings to reduce noise.
        lowered = line.lower()
        if "schema" in lowered and "select" not in lowered:
            return False
        if "--" in line and "execute(" not in lowered:
            return False

        return True

    def _is_parameterized(self, line: str) -> bool:
        """Return whether a line appears to use parameterized execution.

        Args:
            line: Source code line.

        Returns:
            bool: True when parameter placeholders and/or execute arguments are
                detected.
        """
        return any(
            pattern.search(line)
            for pattern in (
                self._SAFE_EXECUTE_PLACEHOLDER,
                self._SAFE_EXECUTE_LIST_ARGS,
                self._SAFE_EXECUTE_TUPLE_ARGS,
            )
        )

    def _has_vulnerable_pattern(self, line: str) -> bool:
        """Return whether a line matches SQL injection-prone patterns.

        Args:
            line: Source code line.

        Returns:
            bool: True if the line matches f-string, concatenation, or format()
                SQL construction patterns.
        """
        return any(
            pattern.search(line)
            for pattern in (
                self._VULNERABLE_FSTRING,
                self._VULNERABLE_CONCAT,
                self._VULNERABLE_FORMAT,
            )
        )

    def _has_nearby_parameterized_usage(
        self, lines: List[str], current_index: int, window: int = 2
    ) -> bool:
        """Check nearby lines for parameterized execute usage.

        Args:
            lines: Full source code lines.
            current_index: Index of the currently analyzed line.
            window: Number of lines before/after to inspect.

        Returns:
            bool: True if a nearby line appears parameterized.
        """
        start = max(0, current_index - window)
        end = min(len(lines), current_index + window + 1)

        for nearby_index in range(start, end):
            if nearby_index == current_index:
                continue
            if self._is_parameterized(lines[nearby_index]):
                return True

        return False


class SecretsDetector(SecurityDetector):
    """Detect hardcoded secrets and credentials (CWE-798) in Python source code.

    This detector identifies API keys, passwords, tokens, AWS credentials, and
    private keys embedded directly in source code. It uses a combination of:

        1. **Variable name analysis**: Detects common secret variable patterns
           (api_key, password, token, secret, etc.)
        2. **Entropy analysis**: Identifies high-randomness strings using Shannon
           entropy calculation (threshold: >3.5 bits/character)
        3. **Pattern matching**: Detects specific formats (AWS keys, JWT, private
           keys, etc.)
        4. **Safe pattern detection**: Suppresses false positives when secrets are
           loaded from environment variables or secrets managers

    All findings are emitted as CRITICAL severity with high confidence.
    """

    # Variable name patterns that suggest secrets
    _SECRET_VAR_NAMES = re.compile(
        r"^(api_?key|token|secret|password|passwd|pwd|api_secret|"
        r"aws_key|aws_secret|access_key|secret_key|signing_key|private_key|"
        r"db_password|database_password|auth_token|csrf_token|session_token)$",
        re.IGNORECASE,
    )

    # Specific secret format patterns
    _AWS_ACCESS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
    _PRIVATE_KEY_START = re.compile(
        r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", re.IGNORECASE
    )
    _JWT_PATTERN = re.compile(
        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    )
    _BCRYPT_HASH = re.compile(r"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}")

    # Safe patterns for loading secrets from external sources
    _SAFE_PATTERNS = re.compile(
        r"(?:os\.getenv|os\.environ\.get|config\.get|app\.config\.get|"
        r"vault\.get|secrets\.get|getpass\.getpass|environment\.get|"
        r"load_env|dotenv\.load)",
        re.IGNORECASE,
    )

    _REMEDIATION = (
        "Move secrets to environment variables or secrets management system: "
        "api_key = os.getenv('API_KEY')"
    )

    def __init__(self, detector_name: str = "SecretsDetector") -> None:
        """Initialize the secrets detector.

        Args:
            detector_name: Optional detector name for reporting and logging.
        """
        super().__init__(detector_name=detector_name)

    def detect(self, code: str) -> List[Vulnerability]:
        """Detect hardcoded secrets in source code.

        Args:
            code: Python source code to analyze.

        Returns:
            List[Vulnerability]: Detected CWE-798 findings.
        """
        vulnerabilities: List[Vulnerability] = []
        lines = code.splitlines()

        for index, raw_line in enumerate(lines):
            line_number = index + 1
            stripped = raw_line.strip()

            # Skip empty lines and comment-only lines
            if not stripped or stripped.startswith("#"):
                continue

            # Look for assignment patterns
            if "=" not in stripped:
                continue

            # Extract variable name and value
            var_name, value = self._extract_assignment(stripped)
            if not var_name or not value:
                continue

            # Skip if using safe patterns (environment variables, config, vault)
            if self._is_safe_pattern(stripped):
                continue

            # Check if this looks like a secret
            is_suspicious_var = self._is_secret_variable(var_name)
            is_suspicious_value = self._is_secret_value(value)

            if not (is_suspicious_var or is_suspicious_value):
                continue

            # Skip test data (test_password = "test123" is acceptable)
            if self._is_test_data(var_name, value):
                continue

            # Skip encrypted/hashed values (bcrypt hashes, for example)
            if self._is_encrypted_or_hashed(value):
                continue

            vulnerabilities.append(
                Vulnerability(
                    cwe=CWECategory.HARDCODED_SECRETS,
                    severity=VulnerabilitySeverity.CRITICAL,
                    line_number=line_number,
                    description=(
                        "Hardcoded secret detected: Credentials, API keys, or tokens "
                        "should not be embedded in source code."
                    ),
                    code_snippet=stripped,
                    remediation=self._REMEDIATION,
                    confidence=0.98,
                    detection_method="SAST",
                )
            )

        return vulnerabilities

    def _extract_assignment(self, line: str) -> tuple[str, str]:
        """Extract variable name and value from an assignment statement.

        Args:
            line: A source code line containing an assignment.

        Returns:
            Tuple of (variable_name, value_string) or ("", "") if not found.
        """
        if "=" not in line:
            return "", ""

        # Simple assignment extraction (var = value)
        parts = line.split("=", 1)
        if len(parts) != 2:
            return "", ""

        var_name = parts[0].strip()
        value_part = parts[1].strip()

        # Extract variable name (handle simple cases, skip complex expressions)
        if not var_name.isidentifier():
            return "", ""

        # Extract string value from quotes
        value = self._extract_string_value(value_part)
        return var_name, value

    def _extract_string_value(self, value_part: str) -> str:
        """Extract string literal from a value expression.

        Handles single quotes, double quotes, and triple quotes.

        Args:
            value_part: The right-hand side of an assignment.

        Returns:
            Extracted string content or empty string if not a literal.
        """
        value_part = value_part.strip()

        # Check for triple-quoted strings
        if value_part.startswith('"""') or value_part.startswith("'''"):
            quote = value_part[:3]
            content = value_part[3:]
            if quote in content:
                return content.split(quote)[0]
            return content

        # Check for single and double quoted strings
        for quote in ['"', "'"]:
            if value_part.startswith(quote):
                content = value_part[1:]
                if quote in content:
                    return content.split(quote)[0]
                return content

        return ""

    def _is_secret_variable(self, var_name: str) -> bool:
        """Return whether a variable name suggests a secret.

        Args:
            var_name: Variable name to check.

        Returns:
            bool: True if variable name matches known secret patterns.
        """
        return bool(self._SECRET_VAR_NAMES.match(var_name))

    def _is_secret_value(self, value: str) -> bool:
        """Return whether a string value appears to be a secret.

        Uses entropy analysis and pattern matching to identify secrets.

        Args:
            value: String value to analyze.

        Returns:
            bool: True if value matches known secret patterns or has
                high entropy (appears random).
        """
        if not value:
            return False

        # Check for specific secret formats
        if self._AWS_ACCESS_KEY.search(value):
            return True
        if self._PRIVATE_KEY_START.search(value):
            return True
        if self._JWT_PATTERN.search(value):
            return True

        # Check entropy for random-looking strings
        # (min length 16 to avoid false positives on short strings)
        if len(value) >= 16:
            entropy = self._entropy(value)
            if entropy > 3.5:
                return True

        return False

    def _is_safe_pattern(self, line: str) -> bool:
        """Return whether a line uses safe secret-loading patterns.

        Args:
            line: Source code line.

        Returns:
            bool: True if the line loads secrets from environment variables,
                configuration, or secrets management systems.
        """
        return bool(self._SAFE_PATTERNS.search(line))

    def _is_test_data(self, var_name: str, value: str) -> bool:
        """Return whether a value appears to be test data (not a real secret).

        Args:
            var_name: Variable name.
            value: String value.

        Returns:
            bool: True if this appears to be test/dummy data.
        """
        # Flag variables with "test" in the name as non-secret
        if "test" in var_name.lower():
            return True

        # Simple test values like "test123", "demo", "example"
        if value.lower() in ("test", "demo", "example", "password", "secret"):
            return True

        # Obviously weak/simple test values
        if value in ("123", "1234", "12345", "123456"):
            return True

        return False

    def _is_encrypted_or_hashed(self, value: str) -> bool:
        """Return whether a value appears to be encrypted or hashed.

        These are not secrets to be moved but rather output of secure processes.

        Args:
            value: String value to check.

        Returns:
            bool: True if value looks like a hash or encrypted data.
        """
        # bcrypt hashes (start with $2a$, $2b$, or $2y$)
        if self._BCRYPT_HASH.match(value):
            return True

        # scrypt hashes (start with $7$)
        if value.startswith("$7$"):
            return True

        # argon2 hashes (start with $argon2)
        if value.startswith("$argon2"):
            return True

        return False

    def _entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string.

        Shannon entropy measures the randomness/uncertainty in a string.
        Higher values indicate more random/unexpected characters.

        Formula: H = -sum(p_i * log2(p_i)) for each character probability

        Args:
            s: String to analyze.

        Returns:
            float: Entropy score (0-8 bits). Typical secrets have entropy >3.5.

        Example:
            "aaaa" -> ~0 (very predictable)
            "test" -> ~1.5 (somewhat predictable)
            "sk-1234567890abcdefghijk" -> ~4.2 (high entropy = likely secret)
        """
        if not s:
            return 0.0

        # Count character frequencies
        char_counts: Dict[str, int] = {}
        for char in s:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate Shannon entropy
        entropy_val = 0.0
        string_len = len(s)

        for count in char_counts.values():
            probability = count / string_len
            entropy_val -= probability * math.log2(probability)

        return entropy_val


class AuthDetector(SecurityDetector):
    """Detect authentication/authorization gaps on protected routes (CWE-287).

    The detector scans Flask, FastAPI, and Django-style code for route or view
    definitions that expose protected operations such as admin, delete, update,
    sensitive, private, secure, or secret endpoints without an adjacent auth
    mechanism.

    Detection strategy:
        1. Find route definitions or endpoint decorators.
        2. Classify the endpoint as protected when route text suggests a
           sensitive operation.
        3. Inspect a small context window around the route for auth decorators
           or dependency injection.
        4. Emit a HIGH-severity finding when auth is missing.

    If the detector cannot determine safety with sufficient confidence, it will
    return an INFO-severity finding instead of HIGH.
    """

    _ROUTE_PATTERNS = re.compile(
        r"(?:@(?:app|router)\.(?:route|get|post|put|delete|patch|options|head)\b|"
        r"@(?:bp|blueprint)\.(?:route|get|post|put|delete|patch)\b|"
        r"(?:path|re_path)\s*\()",
        re.IGNORECASE,
    )
    _PROTECTED_KEYWORDS = re.compile(
        r"(?:/admin|/delete|/update|/modify|/patch|/sensitive|/private|/secure|"
        r"/secret|\badmin\b|\bstaff\b|\bsuperuser\b|/api/admin|/user/)",
        re.IGNORECASE,
    )
    _PUBLIC_KEYWORDS = re.compile(
        r"(?:/login|/signup|/register|/healthz?|/status|/docs|/openapi|/redoc|/ping)\b",
        re.IGNORECASE,
    )
    _AUTH_DECORATORS = re.compile(
        r"(?:@(?:login_required|require_auth|require_login|jwt_required|token_required|auth_required)\b|"
        r"Depends\s*\(\s*(?:verify_token|Oauth2PasswordBearer|OAuth2PasswordBearer|"
        r"get_current_user|oauth2_scheme)\s*\)|"
        r"@permission_required\b|@require_http_methods\b)",
        re.IGNORECASE,
    )
    _AUTH_DECORATOR_TYPES = [
        (re.compile(r"@login_required\b", re.IGNORECASE), "login_required"),
        (re.compile(r"@require_auth\b", re.IGNORECASE), "require_auth"),
        (re.compile(r"@require_login\b", re.IGNORECASE), "require_login"),
        (re.compile(r"@jwt_required\s*\(?\)?", re.IGNORECASE), "jwt_required"),
        (re.compile(r"@token_required\b", re.IGNORECASE), "token_required"),
        (re.compile(r"@auth_required\b", re.IGNORECASE), "auth_required"),
        (
            re.compile(
                r"Depends\s*\(\s*(verify_token|Oauth2PasswordBearer|OAuth2PasswordBearer|get_current_user|oauth2_scheme)\s*\)",
                re.IGNORECASE,
            ),
            "Depends(token/auth dependency)",
        ),
        (re.compile(r"@permission_required\b", re.IGNORECASE), "permission_required"),
        (re.compile(r"@require_http_methods\b", re.IGNORECASE), "require_http_methods"),
    ]
    _REMEDIATION = (
        "Add authentication check to protected endpoint. Example: "
        "@app.route('/admin/delete')\n@require_auth\ndef delete():"
    )

    def __init__(self, detector_name: str = "AuthDetector") -> None:
        """Initialize the auth detector.

        Args:
            detector_name: Optional detector name for reporting and logging.
        """
        super().__init__(detector_name=detector_name)

    def detect(self, code: str) -> List[Vulnerability]:
        """Detect missing authentication on protected endpoints.

        Args:
            code: Python source code to analyze.

        Returns:
            List[Vulnerability]: Findings for protected routes missing auth.
        """
        vulnerabilities: List[Vulnerability] = []
        lines = code.splitlines()

        for index, raw_line in enumerate(lines):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if not self._is_route_definition(stripped):
                continue

            if self._is_public_route(stripped):
                continue

            if not self._is_protected_route(stripped):
                continue

            context = self._get_route_context(lines, index + 1)
            auth_type = self._get_auth_decorator_type(context)

            if self._has_auth_decorator(context):
                continue

            severity = VulnerabilitySeverity.HIGH
            description = (
                "Protected endpoint appears to be missing authentication or "
                "authorization checks."
            )

            # If the code looks ambiguous, downgrade to INFO rather than HIGH.
            if self._looks_ambiguous(context):
                severity = VulnerabilitySeverity.INFO
                description = (
                    "Potential authentication gap on a protected endpoint, but "
                    "the detector could not confirm missing auth with high confidence."
                )

            vulnerabilities.append(
                Vulnerability(
                    cwe=CWECategory.AUTH_BYPASS,
                    severity=severity,
                    line_number=index + 1,
                    description=description,
                    code_snippet=stripped,
                    remediation=self._REMEDIATION,
                    confidence=0.85,
                    detection_method="SAST",
                )
            )

        return vulnerabilities

    def _is_route_definition(self, line: str) -> bool:
        """Return whether a line defines a route or endpoint.

        Args:
            line: Source code line.

        Returns:
            bool: True when the line appears to define a route/endpoint.
        """
        return bool(self._ROUTE_PATTERNS.search(line))

    def _is_protected_route(self, line: str) -> bool:
        """Return whether a route appears to be protected or sensitive.

        Args:
            line: Source code line.

        Returns:
            bool: True when route text suggests admin/sensitive operations.
        """
        return bool(self._PROTECTED_KEYWORDS.search(line))

    def _is_public_route(self, line: str) -> bool:
        """Return whether a route is likely intentionally public.

        Args:
            line: Source code line.

        Returns:
            bool: True for routes like login, docs, health, or root endpoints.
        """
        return bool(self._PUBLIC_KEYWORDS.search(line))

    def _get_route_context(self, lines: List[str], line_num: int) -> str:
        """Return a small context window around the given line number.

        Args:
            lines: Full source code lines.
            line_num: 1-based line number of the route definition.

        Returns:
            str: Context string including three lines before and after.
        """
        index = max(0, line_num - 1)
        start = max(0, index - 3)
        end = min(len(lines), index + 4)
        return "\n".join(lines[start:end])

    def _has_auth_decorator(self, context: str) -> bool:
        """Return whether the context contains an auth decorator or dependency.

        Args:
            context: Route context window.

        Returns:
            bool: True if an auth-related decorator or dependency is present.
        """
        return bool(self._AUTH_DECORATORS.search(context))

    def _get_auth_decorator_type(self, context: str) -> str:
        """Return the detected auth decorator type from route context.

        Args:
            context: Route context window.

        Returns:
            str: Human-readable auth mechanism name or "unknown".
        """
        for pattern, label in self._AUTH_DECORATOR_TYPES:
            if pattern.search(context):
                return label
        return "unknown"

    def _looks_ambiguous(self, context: str) -> bool:
        """Return whether the route context is ambiguous enough to downgrade.

        Args:
            context: Route context window.

        Returns:
            bool: True if auth is likely applied indirectly or globally.
        """
        ambiguous_markers = (
            "middleware",
            "dependency_overrides",
            "Depends(",
            "class",
            "permission_required",
            "global",
        )
        lowered = context.lower()
        return any(marker.lower() in lowered for marker in ambiguous_markers)


# ============================================================================
# EXAMPLE USAGE AND INTEGRATION PATTERNS
# ============================================================================

"""
Example 1: Implementing a SQL Injection Detector
-------------------------------------------------

class SQLInjectionDetector(SecurityDetector):
    '''Detects potential SQL injection vulnerabilities.'''
    
    def detect(self, code: str) -> List[Vulnerability]:
        vulnerabilities = []
        patterns = ['sql_query +=', 'query +=', '.format(']
        
        for line_num, line in enumerate(code.split('\\n'), 1):
            for pattern in patterns:
                if pattern in line and any(x in line for x in ['user_', 'input']):
                    vuln = Vulnerability(
                        cwe=CWECategory.CWE_89,
                        severity=VulnerabilitySeverity.CRITICAL,
                        line_number=line_num,
                        description="Potential SQL injection via string concatenation",
                        code_snippet=line.strip(),
                        remediation="Use parameterized queries with placeholders",
                        confidence=0.85,
                        detection_method="Pattern"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities


Example 2: Using the Detector and Generating Reports
-----------------------------------------------------

import json

# Initialize detector
detector = SQLInjectionDetector("sql_detector")

# Analyze a file
try:
    results = detector.analyze_file("database_handler.py")
    
    # Print summary
    print(results.summary())
    # Output: FAILED: Found 2 vulnerability(ies) (Critical: 2, ...). Score: 60.0/100
    
    # Print recommendations
    print("\\nRemediations:")
    for rec in results.recommendations:
        print(f"  - {rec}")
    
    # Serialize to JSON for reporting
    report = {
        "detector": detector.detector_name,
        "summary": results.summary(),
        "score": results.overall_score,
        "passed": results.passed,
        "vulnerabilities": [v.to_dict() for v in results.vulnerabilities],
        "recommendations": results.recommendations
    }
    
    with open("security_report.json", "w") as f:
        json.dump(report, f, indent=2)
        
except FileNotFoundError as e:
    print(f"Error: {e}")


Example 3: Creating a Multi-Detector System
--------------------------------------------

class HardcodedSecretsDetector(SecurityDetector):
    '''Detects hardcoded credentials and API keys.'''
    
    def detect(self, code: str) -> List[Vulnerability]:
        vulnerabilities = []
        secret_patterns = ['password =', 'api_key =', 'SECRET =']
        
        for line_num, line in enumerate(code.split('\\n'), 1):
            for pattern in secret_patterns:
                if pattern in line and '"' in line:
                    vuln = Vulnerability(
                        cwe=CWECategory.CWE_798,
                        severity=VulnerabilitySeverity.CRITICAL,
                        line_number=line_num,
                        description="Hardcoded credentials detected",
                        code_snippet=line.strip(),
                        remediation="Use environment variables or secrets management",
                        confidence=0.95,
                        detection_method="Pattern"
                    )
                    vulnerabilities.append(vuln)
        
        return vulnerabilities


# Run multiple detectors
detectors = [
    SQLInjectionDetector("sql"),
    HardcodedSecretsDetector("secrets"),
]

all_results = []
for detector in detectors:
    results = detector.analyze_file("target.py")
    all_results.append(results)

# Aggregate results
total_vulns = sum(len(r.vulnerabilities) for r in all_results)
print(f"Total vulnerabilities found across all detectors: {total_vulns}")


Example 4: Custom Scoring and Filtering
----------------------------------------

results = detector.analyze_file("code.py")

# Filter by severity
critical_only = [v for v in results.vulnerabilities 
                 if v.severity == VulnerabilitySeverity.CRITICAL]

print(f"Critical vulnerabilities: {len(critical_only)}")

# Filter by confidence
high_confidence = [v for v in results.vulnerabilities 
                   if v.confidence >= 0.8]

print(f"High-confidence findings: {len(high_confidence)}")
"""
