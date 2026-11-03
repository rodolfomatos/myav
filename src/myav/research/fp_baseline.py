"""False-positive baseline measurement (research track).

Read-only: scans every file under a directory with ``--dry-run`` semantics
(detection only, nothing quarantined, nothing mutated) and reports the
false-positive rate = files flagged MALICIOUS or SUSPICIOUS / total files
scanned.

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
class FPBaselineResult:
    directory: str
    total_scanned: int
    false_positives: int
    false_positive_rate: float
    flagged: list[dict[str, str]] = field(default_factory=list)
    skipped: int = 0

    @property
    def is_clean(self) -> bool:
        return self.false_positives == 0


def scan_directory_for_false_positives(
    directory: Path,
    config: Config,
    paths: Paths,
    engines: Engines,
    kind: str = "research-fp-baseline",
) -> FPBaselineResult:
    """Scan every regular file under *directory* and report the FP rate.

    Uses ``dry_run=True`` so nothing is quarantined or mutated. A temporary
    state database is used so the user's real state is untouched.
    """
    directory = directory.resolve()
    files = [p for p in walk_directory(directory, config) if p.is_file()]

    # Use a throwaway state so the user's real state DB is never touched by research.
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
        # Best-effort cleanup of the temp state dir.
        import shutil

        shutil.rmtree(tmp_state_dir, ignore_errors=True)

    flagged = []
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
            flagged.append(
                {
                    "path": str(outcome.path),
                    "level": level,
                    "evidence": "; ".join(fired),
                    "sha256": outcome.sha256[:16] if outcome.sha256 else "",
                }
            )

    fp_count = len(flagged)
    rate = (fp_count / scanned * 100.0) if scanned else 0.0

    return FPBaselineResult(
        directory=str(directory),
        total_scanned=scanned,
        false_positives=fp_count,
        false_positive_rate=rate,
        flagged=flagged,
        skipped=skipped,
    )
