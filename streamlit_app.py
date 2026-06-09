from __future__ import annotations

import json
from pathlib import Path
import tempfile
from typing import Any, Dict, List

import streamlit as st

from src.cli import (
    CombinedSecurityDetector,
    ReportGenerator,
    SecurityScanError,
    _apply_min_severity_filter,
    _severity_from_string,
)


st.set_page_config(
    page_title="AI Security Scanner",
    page_icon="🛡",
    layout="wide",
)


def _inject_styles() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&display=swap');

        :root {
            --bg-1: #f9f5e9;
            --bg-2: #e4f2f0;
            --ink: #102a43;
            --card: rgba(255, 255, 255, 0.78);
            --accent: #0f766e;
            --accent-2: #d97706;
            --danger: #b91c1c;
        }

        .stApp {
            background:
                radial-gradient(circle at 20% 15%, #fff9dd 0%, transparent 40%),
                radial-gradient(circle at 85% 10%, #d7f2ef 0%, transparent 35%),
                linear-gradient(160deg, var(--bg-1), var(--bg-2));
            color: var(--ink);
            font-family: 'Space Grotesk', sans-serif;
        }

        h1, h2, h3 {
            letter-spacing: 0.01em;
            color: var(--ink);
        }

        .panel {
            background: var(--card);
            border: 1px solid rgba(16, 42, 67, 0.15);
            border-radius: 14px;
            padding: 16px;
            box-shadow: 0 10px 30px rgba(16, 42, 67, 0.08);
        }

        .status-pass {
            color: #0f766e;
            font-weight: 700;
        }

        .status-fail {
            color: var(--danger);
            font-weight: 700;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _flatten_vulnerabilities(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for file_result in results.get("results", []):
        file_path = str(file_result.get("file", ""))
        for vuln in file_result.get("vulnerabilities", []):
            rows.append(
                {
                    "file": file_path,
                    "severity": vuln.get("severity", ""),
                    "cwe": vuln.get("cwe", ""),
                    "line": vuln.get("line_number", ""),
                    "method": vuln.get("detection_method", ""),
                    "confidence": vuln.get("confidence", ""),
                    "description": vuln.get("description", ""),
                    "remediation": vuln.get("remediation", ""),
                }
            )
    return rows


def _scan_uploaded_file(
    detector: CombinedSecurityDetector,
    uploaded_name: str,
    uploaded_bytes: bytes,
) -> Dict[str, Any]:
    suffix = Path(uploaded_name).suffix or ".py"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
        tmp_file.write(uploaded_bytes)
        temp_path = Path(tmp_file.name)

    try:
        results = detector.analyze_file(str(temp_path))
        results["target"] = uploaded_name
        for file_result in results.get("results", []):
            file_result["file"] = uploaded_name
        return results
    finally:
        temp_path.unlink(missing_ok=True)


def _render_results(results: Dict[str, Any], reporter: ReportGenerator) -> None:
    vuln_stats = results.get("vulnerabilities", {})
    passed = bool(results.get("passed", False))

    st.markdown("<div class='panel'>", unsafe_allow_html=True)
    status_class = "status-pass" if passed else "status-fail"
    status_text = "PASSED" if passed else "FAILED"
    st.markdown(
        f"<h3>Scan Status: <span class='{status_class}'>{status_text}</span></h3>",
        unsafe_allow_html=True,
    )

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Overall Score", f"{results.get('overall_score', 100.0):.1f}/100")
    m2.metric("Files Scanned", int(results.get("files_scanned", 0)))
    m3.metric("Files With Issues", int(results.get("files_with_issues", 0)))
    m4.metric("Total Findings", int(vuln_stats.get("total", 0)))

    severity_cols = st.columns(5)
    severity_cols[0].metric("Critical", int(vuln_stats.get("critical", 0)))
    severity_cols[1].metric("High", int(vuln_stats.get("high", 0)))
    severity_cols[2].metric("Medium", int(vuln_stats.get("medium", 0)))
    severity_cols[3].metric("Low", int(vuln_stats.get("low", 0)))
    severity_cols[4].metric("Info", int(vuln_stats.get("info", 0)))

    st.markdown("</div>", unsafe_allow_html=True)

    st.subheader("Per-File Summary")
    file_rows = []
    for item in results.get("results", []):
        stats = item.get("stats", {})
        file_rows.append(
            {
                "file": item.get("file", ""),
                "score": item.get("score", 100.0),
                "critical": stats.get("critical", 0),
                "high": stats.get("high", 0),
                "medium": stats.get("medium", 0),
                "low": stats.get("low", 0),
                "info": stats.get("info", 0),
            }
        )
    st.dataframe(file_rows, use_container_width=True, hide_index=True)

    st.subheader("Vulnerabilities")
    vuln_rows = _flatten_vulnerabilities(results)
    if vuln_rows:
        st.dataframe(vuln_rows, use_container_width=True, hide_index=True)
    else:
        st.success("No vulnerabilities found with the current severity filter.")

    st.subheader("Export")
    json_data = reporter.to_json(results)
    csv_data = reporter.to_csv(results)
    html_data = reporter.to_html(results)

    d1, d2, d3 = st.columns(3)
    d1.download_button(
        label="Download JSON",
        data=json_data,
        file_name="security_scan_report.json",
        mime="application/json",
        use_container_width=True,
    )
    d2.download_button(
        label="Download CSV",
        data=csv_data,
        file_name="security_scan_report.csv",
        mime="text/csv",
        use_container_width=True,
    )
    d3.download_button(
        label="Download HTML",
        data=html_data,
        file_name="security_scan_report.html",
        mime="text/html",
        use_container_width=True,
    )


_inject_styles()

st.title("AI Code Security Scanner")
st.caption("Interactive UI for SQL injection, hardcoded secrets, and auth bypass checks.")

view = st.radio(
    "Scan target",
    options=["Single File", "Directory"],
    horizontal=True,
)

severity = st.selectbox(
    "Minimum severity",
    options=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
    index=0,
)

scanner = CombinedSecurityDetector()
reporter = ReportGenerator()

try:
    if view == "Single File":
        uploaded = st.file_uploader(
            "Upload a source/text file",
            type=["py", "txt", "cs", "js"],
            help="Supported: .py, .txt, .cs, .js",
        )
        if st.button("Run File Scan", type="primary", use_container_width=True):
            if not uploaded:
                st.warning("Please upload a supported file (.py, .txt, .cs, .js) before scanning.")
            else:
                with st.spinner("Scanning file..."):
                    raw_results = _scan_uploaded_file(
                        scanner,
                        uploaded_name=uploaded.name,
                        uploaded_bytes=uploaded.read(),
                    )
                    filtered = _apply_min_severity_filter(
                        raw_results,
                        min_severity=_severity_from_string(severity),
                    )
                _render_results(filtered, reporter)

    else:
        default_dir = str(Path.cwd())
        directory = st.text_input(
            "Directory path",
            value=default_dir,
            placeholder="C:/path/to/project",
        )
        if st.button("Run Directory Scan", type="primary", use_container_width=True):
            with st.spinner("Scanning directory..."):
                raw_results = scanner.analyze_directory(directory)
                filtered = _apply_min_severity_filter(
                    raw_results,
                    min_severity=_severity_from_string(severity),
                )
            _render_results(filtered, reporter)

except SecurityScanError as exc:
    st.error(f"Scan failed: {exc}")
except Exception as exc:  # pragma: no cover - defensive UI guard
    st.exception(exc)
