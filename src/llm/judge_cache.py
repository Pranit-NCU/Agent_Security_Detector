"""Disconnect-safe judge-result cache (ADR-001 / ADR-002).

Why this module exists
----------------------
This is the piece of engineering that made the study finishable, and it was
validated the hard way — by deliberately killing runs mid-flight and confirming
nothing was lost.

Two independent problems forced it:

**Cost.** Experiments B, C, D and F each independently ask "is sample *s*
vulnerable?" of the same judges over the same untransformed benchmark. Run
naively that is ~726 model calls where 242 would do. Keyed caching removes the
redundancy, which is what turned a multi-day API drip into a single pass.

**Fragility.** Free Colab runtimes disconnect. They disconnect at hour three of
a four-hour run, and they do not warn you. A cache that writes non-atomically
will eventually be interrupted *during* a write, leaving a truncated JSON file —
which is worse than no cache at all, because the next run reads it, fails to
parse, and silently starts from sample zero.

The design therefore guarantees two properties:

1. **Atomic writes.** Sequence is: write ``.tmp`` -> ``fsync`` -> rotate the
   current file to ``.backup`` -> ``os.replace(.tmp, primary)``. ``os.replace``
   is atomic within a filesystem, so an interruption at *any* point leaves
   either the previous good primary or the backup fully intact. Never a
   half-written file.
2. **Backup fallback.** :func:`load_cache` tries the primary, then the backup.
   A corrupt primary degrades to "lost the last chunk", never to "lost
   everything".

Errored results are **never** cached, so a rate-limit response or a dropped
connection costs only the in-flight call. Re-running resumes where it stopped.

Circuit breaker
---------------
After ``CIRCUIT_THRESHOLD`` *consecutive* HTTP 429s from one judge, that judge
is skipped for the remainder of the session. Without this, a judge whose daily
quota is exhausted is retried on every remaining sample with a 65 s backoff
each time — roughly 195 s of dead waiting per sample, for nothing.

Usage
-----
    from src.llm.judge_cache import JudgeCache

    cache = JudgeCache(Path("results/judge_cache.json"))
    result = cache.get_or_compute(judge, sample, language="python")
    cache.save()          # also called automatically after each new entry
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Set

__all__ = ["JudgeCache", "CIRCUIT_THRESHOLD"]

# Consecutive 429s from one judge before it is skipped for the session.
CIRCUIT_THRESHOLD = 3

# Fields persisted for each cached verdict. Kept explicit (rather than
# ``__dict__``) so a change to JudgeResult cannot silently corrupt the cache.
_RESULT_FIELDS = (
    "is_vulnerable",
    "cwe",
    "severity",
    "confidence",
    "reasoning",
    "raw_response",
    "judge_name",
    "latency_s",
    "error",
)


def _normalise_language(language: str | None) -> str:
    """Map language aliases onto the prompt families the judges support."""
    lowered = (language or "python").strip().lower()
    st_aliases = {
        "st", "iecst", "iec61131", "iec-61131-3",
        "structured_text", "structured text", "plc",
    }
    if lowered in st_aliases:
        return "st"
    if lowered == "st_diff":
        return "st_diff"
    return "python"


class JudgeCache:
    """A keyed, atomically-persisted store of judge verdicts."""

    def __init__(self, path: Path | str, verbose: bool = True) -> None:
        self.path = Path(path)
        self.backup_path = self.path.with_suffix(".backup.json")
        self.verbose = verbose
        self._entries: Dict[str, Dict[str, Any]] = self._load()
        self._consecutive_429: Dict[str, int] = {}
        self._open_circuits: Set[str] = set()

    # -- persistence ------------------------------------------------------
    def _load(self) -> Dict[str, Dict[str, Any]]:
        """Try the primary file, then the backup. Never wipe on corruption."""
        for candidate, is_backup in ((self.path, False), (self.backup_path, True)):
            try:
                with open(candidate, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                if is_backup and self.verbose:
                    print(
                        f"  [cache] primary unreadable — recovered "
                        f"{len(data)} entries from backup"
                    )
                return data
            except FileNotFoundError:
                continue
            except json.JSONDecodeError:
                if self.verbose:
                    print(f"  [cache] {candidate.name} corrupt — trying backup")
                continue
        return {}

    def save(self) -> None:
        """Atomic, crash-safe write (see module docstring)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(self._entries, handle)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass  # not all filesystems support fsync (e.g. some mounts)
        if self.path.exists():
            try:
                os.replace(self.path, self.backup_path)  # keep last good copy
            except OSError:
                pass
        os.replace(tmp, self.path)  # promote new (atomic)

    # -- keying -----------------------------------------------------------
    @staticmethod
    def sample_id(sample: Dict[str, Any], language: str | None = None) -> str:
        """Cache identity for a sample.

        Python samples keep their bare ``sample_id`` so every previously warmed
        entry still hits; non-Python samples get an ``@<lang>`` suffix so an ST
        verdict can never collide with a Python one for the same id.
        """
        base = sample.get("sample_id") or sample.get("code", "")[:40]
        lang = _normalise_language(language or sample.get("language"))
        return base if lang == "python" else f"{base}@{lang}"

    @staticmethod
    def key(judge_name: str, sample_id: str, transform: str = "none") -> str:
        return f"{judge_name}::{sample_id}::{transform}"

    # -- introspection ----------------------------------------------------
    def __len__(self) -> int:
        return len(self._entries)

    @property
    def open_circuits(self) -> Set[str]:
        return set(self._open_circuits)

    def has(self, judge_name: str, sample: Dict[str, Any], transform: str = "none",
            language: str | None = None) -> bool:
        return self.key(judge_name, self.sample_id(sample, language), transform) in self._entries

    def put(self, judge_name: str, sample: Dict[str, Any], payload: Dict[str, Any],
            transform: str = "none", language: str | None = None,
            persist: bool = True) -> None:
        """Insert a verdict directly (used by the batched warming path)."""
        cache_key = self.key(judge_name, self.sample_id(sample, language), transform)
        self._entries[cache_key] = {k: payload.get(k) for k in _RESULT_FIELDS}
        if persist:
            self.save()

    # -- main entry point -------------------------------------------------
    def get_or_compute(
        self,
        judge: Any,
        sample: Dict[str, Any],
        code: Optional[str] = None,
        transform: str = "none",
        language: str | None = None,
        judge_fn: Optional[Callable[..., Any]] = None,
    ) -> Dict[str, Any]:
        """Return a cached verdict, or compute and cache one.

        ``judge`` must expose ``.name`` and a ``judge(code, language=...)``
        method, or a ``judge_fn`` callable may be supplied instead. The return
        value is a plain dict so callers need no judge-library import.
        """
        judge_name = getattr(judge, "name", None) or getattr(judge, "model_name", str(judge))
        lang = _normalise_language(language or sample.get("language"))
        cache_key = self.key(judge_name, self.sample_id(sample, lang), transform)

        cached = self._entries.get(cache_key)
        if cached is not None:
            return dict(cached)

        if judge_name in self._open_circuits:
            return {
                "is_vulnerable": False,
                "cwe": "QUOTA_SKIPPED",
                "severity": "NONE",
                "confidence": 0.0,
                "reasoning": "",
                "judge_name": judge_name,
                "latency_s": 0.0,
                "error": "Circuit open: quota exhausted earlier this session",
            }

        payload = self._invoke(judge, judge_fn, sample, code, lang)
        error = payload.get("error")

        if error and "429" in str(error):
            self._consecutive_429[judge_name] = self._consecutive_429.get(judge_name, 0) + 1
            if self._consecutive_429[judge_name] >= CIRCUIT_THRESHOLD:
                self._open_circuits.add(judge_name)
                if self.verbose:
                    print(
                        f"  [cache] {judge_name}: {CIRCUIT_THRESHOLD} consecutive "
                        f"429s — skipping for the rest of the session"
                    )
        elif not error:
            self._consecutive_429[judge_name] = 0

        # Errored verdicts are never cached, so a transient failure costs only
        # the in-flight call rather than poisoning the run.
        if not error:
            self._entries[cache_key] = {k: payload.get(k) for k in _RESULT_FIELDS}
            self.save()

        return payload

    @staticmethod
    def _invoke(
        judge: Any,
        judge_fn: Optional[Callable[..., Any]],
        sample: Dict[str, Any],
        code: Optional[str],
        lang: str,
    ) -> Dict[str, Any]:
        payload_code = code if code is not None else sample["code"]
        try:
            raw = judge_fn(payload_code) if judge_fn else judge.judge(payload_code, language=lang)
        except TypeError:
            raw = judge.judge(payload_code)  # judge without a language kwarg
        except Exception as exc:  # pragma: no cover — provider-specific failures
            return {
                "is_vulnerable": False,
                "cwe": "API_ERROR",
                "severity": "NONE",
                "confidence": 0.0,
                "reasoning": "",
                "judge_name": getattr(judge, "name", "unknown"),
                "latency_s": 0.0,
                "error": str(exc),
            }
        if isinstance(raw, dict):
            return raw
        return {field: getattr(raw, field, None) for field in _RESULT_FIELDS}
