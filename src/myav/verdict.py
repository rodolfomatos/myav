"""Fuse engine results into one verdict.

Normative rules (docs/ARCHITECTURE.md §3):

* maximum severity wins: MALICIOUS > SUSPICIOUS > UNKNOWN > CLEAN;
* an engine error never yields CLEAN;
* a primary engine that did not run (skipped/error) yields UNKNOWN;
* a secondary engine that did not run yields CLEAN + ``degraded`` — and every report
  must show it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .engine import CLEAN, ERROR, MALICIOUS, SKIPPED, SUSPICIOUS, EngineResult

LEVEL_CLEAN = "CLEAN"
LEVEL_UNKNOWN = "UNKNOWN"
LEVEL_SUSPICIOUS = "SUSPICIOUS"
LEVEL_MALICIOUS = "MALICIOUS"

_RANK = {LEVEL_CLEAN: 0, LEVEL_UNKNOWN: 1, LEVEL_SUSPICIOUS: 2, LEVEL_MALICIOUS: 3}
EXIT_CODES = {LEVEL_CLEAN: 0, LEVEL_UNKNOWN: 12, LEVEL_SUSPICIOUS: 11, LEVEL_MALICIOUS: 10}

_ENGINE_TO_LEVEL = {
    MALICIOUS: LEVEL_MALICIOUS,
    SUSPICIOUS: LEVEL_SUSPICIOUS,
    ERROR: LEVEL_UNKNOWN,
    SKIPPED: LEVEL_UNKNOWN,
    CLEAN: LEVEL_CLEAN,
}


@dataclass
class Verdict:
    level: str
    reasons: list[str] = field(default_factory=list)
    degraded: list[str] = field(default_factory=list)
    results: list[EngineResult] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.level]

    @property
    def should_quarantine(self) -> bool:
        return self.level in {LEVEL_MALICIOUS, LEVEL_SUSPICIOUS}

    @property
    def quarantine_tag(self) -> str:
        return "malicious" if self.level == LEVEL_MALICIOUS else "suspicious"

    def as_dict(self) -> dict:
        return {
            "level": self.level,
            "exit_code": self.exit_code,
            "reasons": self.reasons,
            "degraded": self.degraded,
            "engines": [result.as_dict() for result in self.results],
        }


def fuse(results: Iterable[EngineResult], stale_signatures: bool = False) -> Verdict:
    results = list(results)
    level = LEVEL_CLEAN
    reasons: list[str] = []
    degraded: list[str] = []

    for result in results:
        candidate = _ENGINE_TO_LEVEL[result.status]
        if result.status == SKIPPED:
            # A secondary engine that did not run is a gap, not a finding: it is
            # reported as degraded evidence, never allowed to downgrade a clean verdict.
            candidate = LEVEL_UNKNOWN if result.primary else LEVEL_CLEAN
            degraded.append(f"{result.engine}: skipped ({result.detail or 'no detail'})")
        elif result.status == ERROR:
            degraded.append(f"{result.engine}: error ({result.detail or 'no detail'})")
        if _RANK[candidate] > _RANK[level]:
            level = candidate
        if result.fired:
            label = result.signature or result.status
            reasons.append(f"{result.engine}: {label}")

    if stale_signatures:
        degraded.append("clamav: signature database is older than 48h")

    # Correlation: both ClamAV and YARA fired on the same file. Additive evidence,
    # never changes the level (max severity still wins).
    fired_engines = {r.engine for r in results if r.fired}
    if "clamav" in fired_engines and "yara" in fired_engines:
        reasons.append("correlation: clamav+yara agree")

    if level == LEVEL_CLEAN and not any(result.status == CLEAN for result in results):
        # Nothing actually ran and nothing failed loudly: we know nothing.
        level = LEVEL_UNKNOWN
        reasons.append("no engine produced evidence")

    return Verdict(level=level, reasons=reasons, degraded=degraded, results=results)
