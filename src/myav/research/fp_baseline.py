"""False-positive / false-negative measurement (research track).

Read-only: scans directories of known-good and known-bad files with
``--dry-run`` semantics (detection only, nothing quarantined, nothing mutated)
and reports false-positive rate, false-negative rate and a confusion matrix.

This is a **measurement**, not a detector. It does not ship as MYAV Core
protection and never will be, unless it graduates per
docs/RESEARCH_TRACK.md (deterministic, explainable, measurable, offline).
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..paths import Paths
from ..pipeline import Engines, scan_targets, walk_directory
from ..state import State
from ..verdict import LEVEL_MALICIOUS, LEVEL_SUSPICIOUS


@dataclass
class ScanOutcome:
    """Result of scanning a single directory."""
    directory: str
    total_scanned: int
    flagged: int
    skipped: int
    flagged_files: list[dict[str, str]] = field(default_factory=list)


@dataclass
class ConfusionMatrix:
    true_negative: int  # clean files correctly NOT flagged
    false_positive: int  # clean files incorrectly flagged
    false_negative: int  # malicious files NOT flagged
    true_positive: int   # malicious files correctly flagged

    @property
    def total_clean(self) -> int:
        return self.true_negative + self.false_positive

    @property
    def total_malicious(self) -> int:
        return self.false_negative + self.true_positive

    @property
    def total(self) -> int:
        return self.total_clean + self.total_malicious

    @property
    def false_positive_rate(self) -> float:
        return self.false_positive / self.total_clean * 100.0 if self.total_clean else 0.0

    @property
    def false_negative_rate(self) -> float:
        return self.false_negative / self.total_malicious * 100.0 if self.total_malicious else 0.0

    @property
    def precision(self) -> float:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator * 100.0 if denominator else 0.0

    @property
    def recall(self) -> float:
        return self.true_positive / self.total_malicious * 100.0 if self.total_malicious else 0.0


@dataclass
class MeasurementResult:
    clean_dir: str
    malicious_dir: str | None
    confusion: ConfusionMatrix
    clean_details: list[dict[str, str]] = field(default_factory=list)
    malicious_details: list[dict[str, str]] = field(default_factory=list)

    @property
    def false_positive_rate(self) -> float:
        return self.confusion.false_positive_rate

    @property
    def false_negative_rate(self) -> float:
        return self.confusion.false_negative_rate


def _scan_directory(
    directory: Path,
    config: Config,
    paths: Paths,
    engines: Engines,
    kind: str = "research-fp-baseline",
) -> ScanOutcome:
    """Scan every regular file under *directory* and return raw outcomes.

    Uses ``dry_run=True`` so nothing is quarantined or mutated. A temporary
    state database is used so the user's real state is untouched.
    """
    directory = directory.resolve()
    files = [p for p in walk_directory(directory, config) if p.is_file()]

    tmp_state_dir = Path(tempfile.mkdtemp(prefix="myav-research-"))
    try:
        state = State(tmp_state_dir / "state.db")
        outcomes = list(
            scan_targets(
                files,
                config,
                paths,
                state,
                engines,
                kind=kind,
                dry_run=True,
            )
        )
    finally:
        import shutil

        shutil.rmtree(tmp_state_dir, ignore_errors=True)

    flagged_files: list[dict[str, str]] = []
    skipped = 0
    scanned = 0
    for outcome in outcomes:
        if outcome.skipped:
            skipped += 1
            continue
        scanned += 1
        level = outcome.level
        if level in {LEVEL_MALICIOUS, LEVEL_SUSPICIOUS}:
            fired = [
                f"{r.engine}:{r.signature or r.status}"
                for r in (outcome.verdict.results if outcome.verdict else [])
                if r.fired
            ]
            flagged_files.append(
                {
                    "path": str(outcome.path),
                    "level": level,
                    "evidence": "; ".join(fired),
                    "sha256": outcome.sha256[:16] if outcome.sha256 else "",
                }
            )

    return ScanOutcome(
        directory=str(directory),
        total_scanned=scanned,
        flagged=len(flagged_files),
        skipped=skipped,
        flagged_files=flagged_files,
    )


def measure_fp_fn(
    clean_dir: Path,
    config: Config,
    paths: Paths,
    engines: Engines,
    malicious_dir: Path | None = None,
    kind: str = "research-fp-baseline",
) -> MeasurementResult:
    """Measure false-positive and false-negative rates.

    Scans *clean_dir* for false positives (clean files flagged) and, when
    *malicious_dir* is given, scans it for false negatives (malicious files
    not flagged). Returns a confusion matrix and derived rates.
    """
    clean_result = _scan_directory(clean_dir, config, paths, engines, kind=kind)

    true_negative = clean_result.total_scanned - clean_result.flagged
    false_positive = clean_result.flagged

    false_negative = 0
    true_positive = 0
    malicious_details: list[dict[str, str]] = []
    malicious_dir_str: str | None = None

    if malicious_dir is not None:
        malicious_dir_str = str(malicious_dir.resolve())
        malicious_result = _scan_directory(
            malicious_dir, config, paths, engines, kind=kind
        )
        false_negative = malicious_result.total_scanned - malicious_result.flagged
        true_positive = malicious_result.flagged
        malicious_details = malicious_result.flagged_files

    confusion = ConfusionMatrix(
        true_negative=true_negative,
        false_positive=false_positive,
        false_negative=false_negative,
        true_positive=true_positive,
    )

    return MeasurementResult(
        clean_dir=str(clean_dir.resolve()),
        malicious_dir=malicious_dir_str,
        confusion=confusion,
        clean_details=clean_result.flagged_files,
        malicious_details=malicious_details,
    )
