"""Pattern-based static analysis for IEC 61131-3 Structured Text (PLC code).

Why this module exists
----------------------
The detectors in :mod:`src.detectors` are Python-specific: they match
``cursor.execute()``, Python string quoting, Python assignment. Pointed at a
PLC program written in Structured Text (ST) they fire on *nothing*.

That matters more than it sounds. The headline Python finding of this project
is that a **hybrid** of SAST + LLM beats either alone. If we carried that
hybrid to PLC code without an ST-aware static layer, the "SAST" half would
contribute zero detections and the hybrid would silently degrade into
"LLM-only" — we would be reporting a hybrid result that was never a hybrid.
This module exists so that the PLC comparison is honest.

Scope (deliberately narrow)
---------------------------
Five PLC weakness classes, mirroring the intentional narrowness of the Python
detectors (3 of 69 CWEs). Narrow coverage is a *finding*, not an oversight: it
is what makes Experiment A's 9% recall meaningful.

===========  ==========================================================
CWE          Weakness
===========  ==========================================================
CWE-798      Hard-coded credential / secret in a ``VAR`` declaration
CWE-835      Unbounded ``WHILE`` loop (PLC scan-cycle overrun)
CWE-369      Division by a variable with no zero guard
CWE-129      Array write through an index with no upper-bound check
CWE-306      Physical output energised with no interlock / authorisation
===========  ==========================================================

Known blind spot (documented, not accidental)
---------------------------------------------
Purely *relational* faults — an inverted or off-by-one comparison in a limit
check — are invisible to pattern matching, because the mutant is syntactically
as well-formed as the original. That is precisely the fault class mutation
testing generates most often, and precisely where the LLM half of the hybrid
has to carry the detection. On the STMutants corpus this ceiling shows up as a
kill rate of roughly 0.10.

References
----------
* Rrushi, J. et al. (2023). Walking under the ladder logic: PLC-VBS, a PLC
  control logic vulnerability scanning tool. *Computers & Security*, 103195.
* MITRE (2024). Common Weakness Enumeration. https://cwe.mitre.org/

Usage
-----
    from src.detectors.st_detectors import run_sast_st

    result = run_sast_st(structured_text_source)
    result["is_vulnerable"]   # bool
    result["findings"]        # list of {cwe, severity, description}
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

__all__ = ["run_sast_st", "st_findings", "ST_CWE_COVERAGE"]

# CWEs this module can, in principle, detect. Used for coverage reporting.
ST_CWE_COVERAGE = ("CWE-798", "CWE-835", "CWE-369", "CWE-129", "CWE-306")


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
# CWE-798 — hard-coded credentials. ST assigns with ``:=`` and quotes STRING
# literals with single quotes. The optional ``: TYPE`` group is essential: a
# declaration reads ``sPassword : STRING := 'abc'``, not ``sPassword := 'abc'``.
_ST_HARDCODED = re.compile(
    r"\b(\w*(?:password|passwd|pwd|secret|apikey|api_key|token|pin|passcode)\w*)\s*"
    r"(?::\s*\w+\s*)?:=\s*'[^']{3,}'",
    re.IGNORECASE,
)

# CWE-835 — a WHILE that can never exit stalls the PLC scan cycle and trips the
# watchdog, which on real plant means the controller stops updating outputs.
_ST_INFINITE = re.compile(r"\bWHILE\s+(TRUE|1)\s+DO\b", re.IGNORECASE)

# CWE-369 — division by a variable, unless that variable is zero-guarded.
_ST_DIVISION = re.compile(r"/\s*([A-Za-z_]\w*)")
_ST_ZERO_GUARD = re.compile(r"\b(\w+)\s*(?:<>|>|>=|=)\s*0\b")

# CWE-129 — array write through a variable index with no upper-bound check.
_ST_ARRAY_WRITE = re.compile(r"\b(\w+)\s*\[\s*([A-Za-z_]\w*)\s*\]\s*:=")
_ST_UPPER_GUARD = re.compile(r"\b(\w+)\s*(?:<=|<)\s*\w+")

# CWE-306 — a physical output driven TRUE with no permissive in the routine.
_ST_OUTPUT_WRITE = re.compile(
    r"\b(%Q[XBWD]?[\d.]*|"
    r"\w*(?:valve|motor|pump|relay|breaker|actuator|output|coil)\w*)\s*:=\s*(TRUE|1)\b",
    re.IGNORECASE,
)
# No leading ``\b``: ST uses Hungarian prefixes everywhere (``xInterlockOk``,
# ``xOperatorAuth``), so the keyword is normally embedded, not word-initial.
_ST_PERMISSIVE = re.compile(
    r"\w*(?:auth|permit|interlock|enable|safe|estop|e_stop|permissive|guard)\w*",
    re.IGNORECASE,
)


def _strip_comments(code: str) -> str:
    """Remove ST comments so a reassuring comment cannot mask or fake a match.

    Without this, a comment such as ``(* index is bounds-checked above *)``
    could satisfy the permissive/guard patterns and suppress a real finding.
    """
    code = re.sub(r"\(\*.*?\*\)", " ", code, flags=re.DOTALL)  # (* block *)
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.DOTALL)  # /* block */
    code = re.sub(r"//[^\n]*", " ", code)  # // line
    return code


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def st_findings(code: str) -> List[Dict[str, str]]:
    """Return the list of ST findings for ``code`` (empty list if clean)."""
    src = _strip_comments(code)
    findings: List[Dict[str, str]] = []

    for match in _ST_HARDCODED.finditer(src):
        findings.append(
            {
                "cwe": "CWE-798",
                "severity": "HIGH",
                "description": f"Hard-coded secret assigned to {match.group(1)}",
            }
        )

    if _ST_INFINITE.search(src):
        findings.append(
            {
                "cwe": "CWE-835",
                "severity": "HIGH",
                "description": "Unbounded WHILE loop may overrun the PLC scan cycle",
            }
        )

    guarded = {g.lower() for g in _ST_ZERO_GUARD.findall(src)}
    for match in _ST_DIVISION.finditer(src):
        denominator = match.group(1)
        # An ALL-CAPS name is conventionally a CONSTANT in ST, so skip it.
        if denominator.lower() not in guarded and not denominator.isupper():
            findings.append(
                {
                    "cwe": "CWE-369",
                    "severity": "MEDIUM",
                    "description": f'Division by "{denominator}" with no zero guard',
                }
            )
            break

    upper_guarded = {g.lower() for g in _ST_UPPER_GUARD.findall(src)}
    for match in _ST_ARRAY_WRITE.finditer(src):
        index = match.group(2)
        if index.lower() not in upper_guarded:
            findings.append(
                {
                    "cwe": "CWE-129",
                    "severity": "HIGH",
                    "description": (
                        f"Array {match.group(1)}[] written via "
                        f'"{index}" with no upper-bound check'
                    ),
                }
            )
            break

    if _ST_OUTPUT_WRITE.search(src) and not _ST_PERMISSIVE.search(src):
        findings.append(
            {
                "cwe": "CWE-306",
                "severity": "CRITICAL",
                "description": "Physical output energised with no interlock/authorisation check",
            }
        )

    return findings


def run_sast_st(code: str) -> Dict[str, Any]:
    """ST counterpart of the Python ``run_sast``.

    Returns the same shape as the Python SAST layer so the two are drop-in
    interchangeable inside the experiment code.
    """
    findings = st_findings(code)
    return {
        "is_vulnerable": bool(findings),
        "findings": findings,
        "primary_cwe": findings[0]["cwe"] if findings else "NONE",
        "severity": findings[0]["severity"] if findings else "NONE",
        "detector_name": "ST-SAST",
    }


# ---------------------------------------------------------------------------
# Self-check — runs on import in __main__ only, keeps the module honest.
# ---------------------------------------------------------------------------
_VULN_PROBE = """
FUNCTION_BLOCK FB_Write
VAR_INPUT iIndex : INT; rValue : REAL; END_VAR
VAR arrBuf : ARRAY[0..15] OF REAL; END_VAR
IF iIndex >= 0 THEN
    arrBuf[iIndex] := rValue;
END_IF
END_FUNCTION_BLOCK
"""

_SAFE_PROBE = """
FUNCTION_BLOCK FB_Write
VAR_INPUT iIndex : INT; rValue : REAL; END_VAR
VAR arrBuf : ARRAY[0..15] OF REAL; END_VAR
IF iIndex >= 0 AND iIndex <= 15 THEN
    arrBuf[iIndex] := rValue;
END_IF
END_FUNCTION_BLOCK
"""


def _self_check() -> None:
    vuln = run_sast_st(_VULN_PROBE)
    safe = run_sast_st(_SAFE_PROBE)
    assert vuln["is_vulnerable"] is True, "ST-SAST missed an unbounded array write"
    assert safe["is_vulnerable"] is False, "ST-SAST false-positived on a guarded write"
    print(f"ST-SAST OK — probe: vulnerable={vuln['primary_cwe']}, safe=clean")


if __name__ == "__main__":  # pragma: no cover
    _self_check()
