"""CLI and orchestration layer for the security detection system.

This module provides:
- CombinedSecurityDetector: orchestrates multiple detectors
- ReportGenerator: renders results in JSON, table, CSV, and HTML formats
- Click CLI commands for scanning files, directories, and git repositories

The implementation is designed for Python 3.9+ and production usage.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
from io import StringIO
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import click

try:
    from .detectors import (
        AuthDetector,
        SQLInjectionDetector,
        SecretsDetector,
        Vulnerability,
        VulnerabilitySeverity,
    )
except ImportError:  # pragma: no cover - fallback for direct execution
    from src.detectors import (  # type: ignore
        AuthDetector,
        SQLInjectionDetector,
        SecretsDetector,
        Vulnerability,
        VulnerabilitySeverity,
    )


class SecurityScanError(Exception):
    """Raised when a scan cannot be completed due to operational errors."""


class CombinedSecurityDetector:
    """Orchestrate all detectors and aggregate scan results.

    This class is responsible for loading all detector implementations,
    running detectors in sequence, deduplicating findings, sorting by severity,
    and building scan-wide statistics.
    """

    def __init__(self) -> None:
        """Initialize all supported detector instances."""
        self.detectors = [
            SQLInjectionDetector(),
            SecretsDetector(),
            AuthDetector(),
        ]

    def analyze_file(self, filepath: str) -> Dict[str, Any]:
        """Analyze a single file and return a comprehensive scan result.

        Args:
            filepath: Path to the source file.

        Returns:
            Dict[str, Any]: Aggregated scan result for one file.

        Raises:
            SecurityScanError: If the path is invalid or cannot be read.
        """
        file_path = Path(filepath)
        if not file_path.exists() or not file_path.is_file():
            raise SecurityScanError(f"File not found: {filepath}")

        try:
            file_result = self._analyze_file_detail(file_path)
        except OSError as exc:
            raise SecurityScanError(f"Failed to analyze file {filepath}: {exc}") from exc

        return self._aggregate_results(
            [file_result],
            scan_type="file",
            target=str(file_path),
        )

    def analyze_directory(self, directory: str) -> Dict[str, Any]:
        """Analyze all Python files recursively in a directory.

        Args:
            directory: Path to the directory to scan.

        Returns:
            Dict[str, Any]: Aggregated scan result for the directory.

        Raises:
            SecurityScanError: If directory is invalid or contains no Python files.
        """
        directory_path = Path(directory)
        if not directory_path.exists() or not directory_path.is_dir():
            raise SecurityScanError(f"Directory not found: {directory}")

        python_files = self._discover_python_files(directory_path)
        if not python_files:
            raise SecurityScanError(f"No Python files found in directory: {directory}")

        results: List[Dict[str, Any]] = []
        for file_path in python_files:
            try:
                results.append(self._analyze_file_detail(file_path))
            except OSError:
                # Skip unreadable files but continue scanning.
                continue

        return self._aggregate_results(
            results,
            scan_type="directory",
            target=str(directory_path),
        )

    def _analyze_file_detail(self, filepath: Path) -> Dict[str, Any]:
        """Analyze one file and return per-file detail used for aggregation.

        Args:
            filepath: File path object.

        Returns:
            Dict[str, Any]: Per-file analysis detail.
        """
        code = filepath.read_text(encoding="utf-8")
        all_vulnerabilities: List[Vulnerability] = []

        for detector in self.detectors:
            detector_vulns = detector.detect(code)
            all_vulnerabilities.extend(detector_vulns)

        unique_vulns = self._deduplicate_vulnerabilities(all_vulnerabilities)
        sorted_vulns = self._sort_vulnerabilities(unique_vulns)

        critical_count = sum(
            1 for vuln in sorted_vulns if vuln.severity == VulnerabilitySeverity.CRITICAL
        )
        high_count = sum(
            1 for vuln in sorted_vulns if vuln.severity == VulnerabilitySeverity.HIGH
        )
        medium_count = sum(
            1 for vuln in sorted_vulns if vuln.severity == VulnerabilitySeverity.MEDIUM
        )
        low_count = sum(
            1 for vuln in sorted_vulns if vuln.severity == VulnerabilitySeverity.LOW
        )
        info_count = sum(
            1 for vuln in sorted_vulns if vuln.severity == VulnerabilitySeverity.INFO
        )

        score = self._calculate_overall_score(sorted_vulns)

        return {
            "file": str(filepath),
            "score": score,
            "passed": critical_count == 0 and high_count == 0,
            "vulnerabilities": [v.to_dict() for v in sorted_vulns],
            "_vulnerability_objects": sorted_vulns,
            "stats": {
                "total": len(sorted_vulns),
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "info": info_count,
            },
        }

    def _discover_python_files(self, directory: Path) -> List[Path]:
        """Discover Python files recursively.

        Args:
            directory: Directory root.

        Returns:
            List[Path]: Sorted Python file paths.
        """
        return sorted(path for path in directory.rglob("*.py") if path.is_file())

    def _aggregate_results(
        self,
        results: List[Dict[str, Any]],
        scan_type: str = "directory",
        target: str = "",
    ) -> Dict[str, Any]:
        """Combine per-file results and calculate scan-level statistics.

        Args:
            results: Per-file result entries.
            scan_type: Type of scan (file/directory/repository).
            target: User-provided target scanned.

        Returns:
            Dict[str, Any]: Aggregated report payload.
        """
        all_vulns: List[Vulnerability] = []
        files_with_issues = 0
        cwe_breakdown: Dict[str, int] = {}
        scores: List[float] = []

        for file_result in results:
            vulns = file_result.get("_vulnerability_objects", [])
            all_vulns.extend(vulns)
            scores.append(float(file_result.get("score", 100.0)))

            if file_result.get("stats", {}).get("total", 0) > 0:
                files_with_issues += 1

            for vuln_dict in file_result.get("vulnerabilities", []):
                cwe_key = str(vuln_dict.get("cwe", "UNKNOWN"))
                cwe_breakdown[cwe_key] = cwe_breakdown.get(cwe_key, 0) + 1

        critical_count = sum(
            1 for vuln in all_vulns if vuln.severity == VulnerabilitySeverity.CRITICAL
        )
        high_count = sum(
            1 for vuln in all_vulns if vuln.severity == VulnerabilitySeverity.HIGH
        )
        medium_count = sum(
            1 for vuln in all_vulns if vuln.severity == VulnerabilitySeverity.MEDIUM
        )
        low_count = sum(
            1 for vuln in all_vulns if vuln.severity == VulnerabilitySeverity.LOW
        )
        info_count = sum(
            1 for vuln in all_vulns if vuln.severity == VulnerabilitySeverity.INFO
        )

        overall_score = self._calculate_overall_score(all_vulns)
        average_score = sum(scores) / len(scores) if scores else 100.0

        visible_results: List[Dict[str, Any]] = []
        for file_result in results:
            visible_results.append(
                {
                    "file": file_result.get("file", ""),
                    "score": file_result.get("score", 100.0),
                    "passed": file_result.get("passed", True),
                    "vulnerabilities": file_result.get("vulnerabilities", []),
                    "stats": file_result.get("stats", {}),
                }
            )

        return {
            "timestamp": _utc_timestamp(),
            "scan_type": scan_type,
            "target": target,
            "files_scanned": len(results),
            "files_with_issues": files_with_issues,
            "vulnerabilities": {
                "total": len(all_vulns),
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
                "info": info_count,
            },
            "cwe_breakdown": cwe_breakdown,
            "score_distribution": {
                "overall": round(overall_score, 2),
                "average": round(average_score, 2),
                "min": round(min(scores), 2) if scores else 100.0,
                "max": round(max(scores), 2) if scores else 100.0,
            },
            "overall_score": round(overall_score, 2),
            "passed": critical_count == 0 and high_count == 0,
            "results": visible_results,
            "_all_vulnerability_objects": all_vulns,
        }

    def _calculate_overall_score(self, all_vulns: List[Vulnerability]) -> float:
        """Calculate scan score from all vulnerabilities.

        Scoring model:
            - Start at 100
            - CRITICAL: -20 each
            - HIGH: -10 each
            - MEDIUM: -5 each
            - LOW: -2 each
            - INFO: 0

        Args:
            all_vulns: Vulnerability objects across scanned files.

        Returns:
            float: Score clamped to [0, 100].
        """
        score = 100.0
        for vuln in all_vulns:
            if vuln.severity == VulnerabilitySeverity.CRITICAL:
                score -= 20.0
            elif vuln.severity == VulnerabilitySeverity.HIGH:
                score -= 10.0
            elif vuln.severity == VulnerabilitySeverity.MEDIUM:
                score -= 5.0
            elif vuln.severity == VulnerabilitySeverity.LOW:
                score -= 2.0

        return max(0.0, min(100.0, score))

    def _deduplicate_vulnerabilities(
        self, vulnerabilities: Sequence[Vulnerability]
    ) -> List[Vulnerability]:
        """Remove duplicate vulnerabilities while preserving semantics.

        Args:
            vulnerabilities: Vulnerabilities from all detectors for a file.

        Returns:
            List[Vulnerability]: Deduplicated vulnerabilities.
        """
        seen: set[Tuple[str, str, int, str, str]] = set()
        unique: List[Vulnerability] = []

        for vuln in vulnerabilities:
            signature = (
                vuln.cwe.value,
                vuln.severity.name,
                vuln.line_number,
                vuln.description.strip(),
                vuln.code_snippet.strip(),
            )
            if signature in seen:
                continue
            seen.add(signature)
            unique.append(vuln)

        return unique

    def _sort_vulnerabilities(
        self, vulnerabilities: Sequence[Vulnerability]
    ) -> List[Vulnerability]:
        """Sort vulnerabilities by severity and line number.

        Args:
            vulnerabilities: Vulnerabilities to sort.

        Returns:
            List[Vulnerability]: Sorted vulnerabilities.
        """
        return sorted(
            vulnerabilities,
            key=lambda item: (
                -item.severity.value,
                item.line_number,
                item.cwe.value,
            ),
        )


class ReportGenerator:
    """Generate output reports for scan results."""

    def to_json(self, results: Dict[str, Any]) -> str:
        """Render result payload to JSON.

        Args:
            results: Scan result payload.

        Returns:
            str: Pretty-formatted JSON string.
        """
        sanitized = self._sanitize_for_output(results)
        return json.dumps(sanitized, indent=2)

    def to_table(self, results: Dict[str, Any]) -> str:
        """Render result payload as an ASCII table for terminal output.

        Args:
            results: Scan result payload.

        Returns:
            str: Human-readable table output.
        """
        rows: List[Tuple[str, str, str, str, str, str, str]] = []
        for item in results.get("results", []):
            file_name = Path(str(item.get("file", ""))).name or str(item.get("file", ""))
            stats = item.get("stats", {})
            rows.append(
                (
                    file_name,
                    self._format_score(float(item.get("score", 100.0))),
                    str(stats.get("critical", 0)),
                    str(stats.get("high", 0)),
                    str(stats.get("medium", 0)),
                    str(stats.get("low", 0)),
                    str(stats.get("info", 0)),
                )
            )

        headers = ["File", "Score", "Critical", "High", "Medium", "Low", "Info"]
        totals = results.get("vulnerabilities", {})
        total_row = (
            "TOTAL",
            self._format_score(float(results.get("overall_score", 100.0))),
            str(totals.get("critical", 0)),
            str(totals.get("high", 0)),
            str(totals.get("medium", 0)),
            str(totals.get("low", 0)),
            str(totals.get("info", 0)),
        )

        all_rows = rows + [total_row]
        widths = [len(column) for column in headers]
        for row in all_rows:
            for idx, value in enumerate(row):
                widths[idx] = max(widths[idx], len(value))

        divider = "-+-".join("-" * width for width in widths)
        table_lines = [
            "Security Scan Results",
            "=" * len("Security Scan Results"),
            self._format_row(tuple(headers), widths),
            divider,
        ]
        for row in rows:
            table_lines.append(self._format_row(row, widths))

        table_lines.append(divider)
        table_lines.append(self._format_row(total_row, widths))

        status_text = "PASSED" if results.get("passed", False) else "FAILED"
        table_lines.extend(
            [
                "=" * len("Security Scan Results"),
                f"Status: {status_text}",
                (
                    "Summary: "
                    f"{totals.get('critical', 0)} critical, "
                    f"{totals.get('high', 0)} high, "
                    f"{totals.get('medium', 0)} medium, "
                    f"{totals.get('low', 0)} low"
                ),
            ]
        )

        return "\n".join(table_lines)

    def to_csv(self, results: Dict[str, Any]) -> str:
        """Render result payload as CSV text.

        Args:
            results: Scan result payload.

        Returns:
            str: CSV formatted text.
        """
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["file", "score", "critical", "high", "medium", "low", "info"])

        for item in results.get("results", []):
            stats = item.get("stats", {})
            writer.writerow(
                [
                    item.get("file", ""),
                    item.get("score", 100.0),
                    stats.get("critical", 0),
                    stats.get("high", 0),
                    stats.get("medium", 0),
                    stats.get("low", 0),
                    stats.get("info", 0),
                ]
            )

        return output.getvalue().strip()

    def to_html(self, results: Dict[str, Any]) -> str:
        """Render result payload as a minimal HTML report.

        Args:
            results: Scan result payload.

        Returns:
            str: HTML document string.
        """
        rows_html: List[str] = []
        for item in results.get("results", []):
            stats = item.get("stats", {})
            rows_html.append(
                "<tr>"
                f"<td>{self._escape_html(str(item.get('file', '')))}</td>"
                f"<td>{float(item.get('score', 100.0)):.1f}</td>"
                f"<td>{stats.get('critical', 0)}</td>"
                f"<td>{stats.get('high', 0)}</td>"
                f"<td>{stats.get('medium', 0)}</td>"
                f"<td>{stats.get('low', 0)}</td>"
                f"<td>{stats.get('info', 0)}</td>"
                "</tr>"
            )

        status = "PASSED" if results.get("passed", False) else "FAILED"
        status_color = "#1a7f37" if status == "PASSED" else "#b42318"

        return (
            "<!doctype html>"
            "<html><head><meta charset='utf-8'><title>Security Scan Report</title>"
            "<style>"
            "body{font-family:Arial,sans-serif;margin:24px;}"
            "table{border-collapse:collapse;width:100%;margin-top:16px;}"
            "th,td{border:1px solid #ccc;padding:8px;text-align:left;}"
            "th{background:#f5f5f5;}"
            "</style></head><body>"
            "<h1>Security Scan Report</h1>"
            f"<p><strong>Status:</strong> <span style='color:{status_color}'>{status}</span></p>"
            f"<p><strong>Target:</strong> {self._escape_html(str(results.get('target', '')))}</p>"
            f"<p><strong>Overall Score:</strong> {float(results.get('overall_score', 100.0)):.1f}/100</p>"
            "<table><thead><tr>"
            "<th>File</th><th>Score</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th>"
            "</tr></thead><tbody>"
            + "".join(rows_html)
            + "</tbody></table></body></html>"
        )

    def _sanitize_for_output(self, payload: Any) -> Any:
        """Remove private/internal keys from result payload recursively."""
        if isinstance(payload, dict):
            sanitized: Dict[str, Any] = {}
            for key, value in payload.items():
                if str(key).startswith("_"):
                    continue
                sanitized[key] = self._sanitize_for_output(value)
            return sanitized
        if isinstance(payload, list):
            return [self._sanitize_for_output(item) for item in payload]
        return payload

    def _format_row(self, row: Tuple[str, ...], widths: List[int]) -> str:
        """Format one row with left/right alignment for table rendering."""
        cells: List[str] = []
        for idx, value in enumerate(row):
            if idx == 1:
                cells.append(value.rjust(widths[idx]))
            else:
                cells.append(value.ljust(widths[idx]))
        return " | ".join(cells)

    def _format_score(self, score: float) -> str:
        """Format numeric score for tabular display."""
        return f"{score:.1f}/100"

    def _escape_html(self, value: str) -> str:
        """Escape minimal HTML entities for safe rendering."""
        return (
            value.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )


@click.group()
def cli() -> None:
    """Security scanning for AI-generated code."""


def _apply_min_severity_filter(
    scan_results: Dict[str, Any],
    min_severity: VulnerabilitySeverity,
) -> Dict[str, Any]:
    """Filter vulnerabilities below minimum severity and recompute summary.

    Args:
        scan_results: Original aggregated result payload.
        min_severity: Minimum severity to keep.

    Returns:
        Dict[str, Any]: Filtered and recomputed scan results.
    """
    filtered_file_results: List[Dict[str, Any]] = []
    severity_order = {
        "CRITICAL": VulnerabilitySeverity.CRITICAL.value,
        "HIGH": VulnerabilitySeverity.HIGH.value,
        "MEDIUM": VulnerabilitySeverity.MEDIUM.value,
        "LOW": VulnerabilitySeverity.LOW.value,
        "INFO": VulnerabilitySeverity.INFO.value,
    }

    for file_result in scan_results.get("results", []):
        vulns = file_result.get("vulnerabilities", [])
        kept = [
            vuln
            for vuln in vulns
            if severity_order.get(str(vuln.get("severity", "INFO")), 0)
            >= min_severity.value
        ]

        stats = {
            "total": len(kept),
            "critical": sum(1 for vuln in kept if vuln.get("severity") == "CRITICAL"),
            "high": sum(1 for vuln in kept if vuln.get("severity") == "HIGH"),
            "medium": sum(1 for vuln in kept if vuln.get("severity") == "MEDIUM"),
            "low": sum(1 for vuln in kept if vuln.get("severity") == "LOW"),
            "info": sum(1 for vuln in kept if vuln.get("severity") == "INFO"),
        }

        filtered_file_results.append(
            {
                "file": file_result.get("file", ""),
                "score": _score_from_vuln_dicts(kept),
                "passed": stats["critical"] == 0 and stats["high"] == 0,
                "vulnerabilities": kept,
                "stats": stats,
            }
        )

    return _aggregate_dict_results(
        filtered_file_results,
        scan_type=str(scan_results.get("scan_type", "directory")),
        target=str(scan_results.get("target", "")),
    )


def _aggregate_dict_results(
    file_results: List[Dict[str, Any]],
    scan_type: str,
    target: str,
) -> Dict[str, Any]:
    """Aggregate already-serialized vulnerability dictionaries."""
    all_vulns: List[Dict[str, Any]] = []
    cwe_breakdown: Dict[str, int] = {}
    files_with_issues = 0
    scores: List[float] = []

    for file_result in file_results:
        vulns = file_result.get("vulnerabilities", [])
        all_vulns.extend(vulns)
        scores.append(float(file_result.get("score", 100.0)))
        if file_result.get("stats", {}).get("total", 0) > 0:
            files_with_issues += 1
        for vuln in vulns:
            cwe_key = str(vuln.get("cwe", "UNKNOWN"))
            cwe_breakdown[cwe_key] = cwe_breakdown.get(cwe_key, 0) + 1

    critical = sum(1 for vuln in all_vulns if vuln.get("severity") == "CRITICAL")
    high = sum(1 for vuln in all_vulns if vuln.get("severity") == "HIGH")
    medium = sum(1 for vuln in all_vulns if vuln.get("severity") == "MEDIUM")
    low = sum(1 for vuln in all_vulns if vuln.get("severity") == "LOW")
    info = sum(1 for vuln in all_vulns if vuln.get("severity") == "INFO")

    overall_score = _score_from_vuln_dicts(all_vulns)
    average_score = sum(scores) / len(scores) if scores else 100.0

    return {
        "timestamp": _utc_timestamp(),
        "scan_type": scan_type,
        "target": target,
        "files_scanned": len(file_results),
        "files_with_issues": files_with_issues,
        "vulnerabilities": {
            "total": len(all_vulns),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        },
        "cwe_breakdown": cwe_breakdown,
        "score_distribution": {
            "overall": round(overall_score, 2),
            "average": round(average_score, 2),
            "min": round(min(scores), 2) if scores else 100.0,
            "max": round(max(scores), 2) if scores else 100.0,
        },
        "overall_score": round(overall_score, 2),
        "passed": critical == 0 and high == 0,
        "results": file_results,
    }


def _score_from_vuln_dicts(vulns: Iterable[Dict[str, Any]]) -> float:
    """Calculate score from serialized vulnerability dictionaries."""
    score = 100.0
    for vuln in vulns:
        severity = str(vuln.get("severity", "INFO"))
        if severity == "CRITICAL":
            score -= 20.0
        elif severity == "HIGH":
            score -= 10.0
        elif severity == "MEDIUM":
            score -= 5.0
        elif severity == "LOW":
            score -= 2.0
    return max(0.0, min(100.0, score))


def _severity_from_string(value: str) -> VulnerabilitySeverity:
    """Convert user-provided severity string to enum."""
    normalized = value.strip().upper()
    try:
        return VulnerabilitySeverity[normalized]
    except KeyError as exc:
        choices = ", ".join(level.name for level in VulnerabilitySeverity)
        raise click.BadParameter(
            f"Invalid severity '{value}'. Expected one of: {choices}"
        ) from exc


def _render_output(
    report_generator: ReportGenerator,
    results: Dict[str, Any],
    output_format: str,
) -> str:
    """Render results in the selected format."""
    if output_format == "json":
        return report_generator.to_json(results)
    if output_format == "csv":
        return report_generator.to_csv(results)
    if output_format == "html":
        return report_generator.to_html(results)
    return report_generator.to_table(results)


def _print_status(results: Dict[str, Any]) -> None:
    """Print colored PASS/FAIL status line."""
    vuln_stats = results.get("vulnerabilities", {})
    status = "PASSED" if results.get("passed", False) else "FAILED"

    if status == "PASSED":
        click.secho(
            f"Status: {status} | Score: {results.get('overall_score', 100.0):.1f}/100",
            fg="green",
        )
    else:
        click.secho(
            (
                f"Status: {status} | Score: {results.get('overall_score', 100.0):.1f}/100 | "
                f"Critical: {vuln_stats.get('critical', 0)}, "
                f"High: {vuln_stats.get('high', 0)}"
            ),
            fg="red",
        )


@cli.command("scan")
@click.argument("filepath", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "csv", "html"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--quiet", is_flag=True, help="Only set exit code, no output.")
@click.option("--verbose", is_flag=True, help="Show extra scan details.")
@click.option(
    "--min-severity",
    type=click.Choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="INFO",
    show_default=True,
    help="Minimum severity to include in output.",
)
def scan_command(
    filepath: Path,
    output_format: str,
    quiet: bool,
    verbose: bool,
    min_severity: str,
) -> None:
    """Scan a single Python file."""
    detector = CombinedSecurityDetector()
    reporter = ReportGenerator()

    try:
        results = detector.analyze_file(str(filepath))
        results = _apply_min_severity_filter(
            results,
            min_severity=_severity_from_string(min_severity),
        )
    except SecurityScanError as exc:
        click.secho(f"Scan error: {exc}", fg="red", err=True)
        raise SystemExit(2) from exc

    if not quiet:
        rendered = _render_output(reporter, results, output_format.lower())
        click.echo(rendered)
        _print_status(results)
        if verbose:
            click.echo(
                f"Scanned files: {results.get('files_scanned', 0)} | "
                f"Files with issues: {results.get('files_with_issues', 0)}"
            )


@cli.command("scan-dir")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "csv", "html"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--quiet", is_flag=True, help="Only set exit code, no output.")
@click.option("--verbose", is_flag=True, help="Show extra scan details.")
@click.option(
    "--min-severity",
    type=click.Choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="INFO",
    show_default=True,
    help="Minimum severity to include in output.",
)
def scan_directory_command(
    directory: Path,
    output_format: str,
    quiet: bool,
    verbose: bool,
    min_severity: str,
) -> None:
    """Scan all Python files in a directory recursively."""
    detector = CombinedSecurityDetector()
    reporter = ReportGenerator()

    try:
        python_files = detector._discover_python_files(directory)
        if not python_files:
            raise SecurityScanError(f"No Python files found in directory: {directory}")

        file_results: List[Dict[str, Any]] = []
        if len(python_files) >= 10 and not quiet:
            with click.progressbar(
                python_files,
                label="Scanning Python files",
                show_eta=True,
            ) as progress_bar:
                for file_path in progress_bar:
                    try:
                        file_results.append(detector._analyze_file_detail(file_path))
                    except OSError:
                        continue
        else:
            for file_path in python_files:
                try:
                    file_results.append(detector._analyze_file_detail(file_path))
                except OSError:
                    continue

        results = detector._aggregate_results(
            file_results,
            scan_type="directory",
            target=str(directory),
        )
        results = _apply_min_severity_filter(
            results,
            min_severity=_severity_from_string(min_severity),
        )
    except SecurityScanError as exc:
        click.secho(f"Scan error: {exc}", fg="red", err=True)
        raise SystemExit(2) from exc

    if not quiet:
        rendered = _render_output(reporter, results, output_format.lower())
        click.echo(rendered)
        _print_status(results)
        if verbose:
            click.echo(
                f"Scanned files: {results.get('files_scanned', 0)} | "
                f"Files with issues: {results.get('files_with_issues', 0)}"
            )


@cli.command("scan-repo")
@click.argument("git_repo", type=str)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "csv", "html"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--quiet", is_flag=True, help="Only set exit code, no output.")
@click.option("--verbose", is_flag=True, help="Show extra scan details.")
@click.option(
    "--min-severity",
    type=click.Choice(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    default="INFO",
    show_default=True,
    help="Minimum severity to include in output.",
)
def scan_repo_command(
    git_repo: str,
    output_format: str,
    quiet: bool,
    verbose: bool,
    min_severity: str,
) -> None:
    """Clone and scan a git repository."""
    detector = CombinedSecurityDetector()
    reporter = ReportGenerator()

    tmp_dir = tempfile.mkdtemp(prefix="security_scan_")
    clone_target = Path(tmp_dir) / "repo"

    try:
        completed = subprocess.run(
            ["git", "clone", "--depth", "1", git_repo, str(clone_target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or "git clone failed"
            raise SecurityScanError(f"Unable to clone repository: {stderr}")

        results = detector.analyze_directory(str(clone_target))
        results["scan_type"] = "repository"
        results["target"] = git_repo
        results = _apply_min_severity_filter(
            results,
            min_severity=_severity_from_string(min_severity),
        )
    except SecurityScanError as exc:
        click.secho(f"Scan error: {exc}", fg="red", err=True)
        raise SystemExit(2) from exc
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    if not quiet:
        rendered = _render_output(reporter, results, output_format.lower())
        click.echo(rendered)
        _print_status(results)
        if verbose:
            click.echo(
                f"Scanned files: {results.get('files_scanned', 0)} | "
                f"Files with issues: {results.get('files_with_issues', 0)}"
            )


@cli.command("check-ci")
@click.option("--file", "file_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--directory",
    "directory_path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option("--repo", "repo_url", type=str)
@click.option(
    "--fail-on-medium",
    is_flag=True,
    help="Fail CI when medium vulnerabilities are present.",
)
@click.option("--quiet", is_flag=True, help="Suppress output and return exit code only.")
def check_ci_command(
    file_path: Optional[Path],
    directory_path: Optional[Path],
    repo_url: Optional[str],
    fail_on_medium: bool,
    quiet: bool,
) -> None:
    """Run CI policy checks and return standardized exit codes.

    Exit codes:
        0: no HIGH/CRITICAL issues (and no MEDIUM when fail-on-medium is enabled)
        1: policy violation
        2: operational scan error
    """
    selected = [file_path is not None, directory_path is not None, repo_url is not None]
    if sum(selected) != 1:
        raise click.UsageError(
            "Specify exactly one of --file, --directory, or --repo for check-ci."
        )

    detector = CombinedSecurityDetector()
    reporter = ReportGenerator()

    try:
        if file_path is not None:
            results = detector.analyze_file(str(file_path))
        elif directory_path is not None:
            results = detector.analyze_directory(str(directory_path))
        else:
            tmp_dir = tempfile.mkdtemp(prefix="security_ci_")
            clone_target = Path(tmp_dir) / "repo"
            try:
                completed = subprocess.run(
                    ["git", "clone", "--depth", "1", str(repo_url), str(clone_target)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if completed.returncode != 0:
                    stderr = completed.stderr.strip() or "git clone failed"
                    raise SecurityScanError(f"Unable to clone repository: {stderr}")
                results = detector.analyze_directory(str(clone_target))
                results["scan_type"] = "repository"
                results["target"] = str(repo_url)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)

    except SecurityScanError as exc:
        if not quiet:
            click.secho(f"CI scan error: {exc}", fg="red", err=True)
        raise SystemExit(2) from exc

    vuln_stats = results.get("vulnerabilities", {})
    critical = int(vuln_stats.get("critical", 0))
    high = int(vuln_stats.get("high", 0))
    medium = int(vuln_stats.get("medium", 0))

    fail = critical > 0 or high > 0 or (fail_on_medium and medium > 0)

    if not quiet:
        click.echo(reporter.to_table(results))
        _print_status(results)
        if fail:
            click.secho("CI policy: FAIL", fg="red")
        else:
            click.secho("CI policy: PASS", fg="green")

    raise SystemExit(1 if fail else 0)


def _utc_timestamp() -> str:
    """Return UTC timestamp in ISO 8601 format with Z suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def main() -> None:
    """CLI entry point."""
    cli()


if __name__ == "__main__":
    main()
