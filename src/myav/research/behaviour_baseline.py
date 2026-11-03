"""User behaviour baseline (research track).

Read-only: records what is *normal* for this operator — process names, hours of
execution, directories touched, outbound connections, modified files — and
reports deviations from that baseline as alerts. Never blocks.

This is a **measurement**, not a detector. It does not ship as MYAV Core
protection and never will be, unless it graduates per
docs/RESEARCH_TRACK.md (deterministic, explainable, measurable, offline).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..config import Config
from ..paths import Paths
from ..pipeline import Engines, walk_directory
from ..state import State


@dataclass(frozen=True)
class BehaviourObservation:
    """A single observed behaviour event."""

    process_name: str
    hour_of_day: int
    directory: str
    connection: str | None = None
    modified_file: str | None = None


@dataclass
class BehaviourBaseline:
    """Learned baseline of normal behaviour for this machine/operator."""

    processes: set[str] = field(default_factory=set)
    hours: set[int] = field(default_factory=set)
    directories: set[str] = field(default_factory=set)
    connections: set[str] = field(default_factory=set)
    modified_files: set[str] = field(default_factory=set)
    learned_at: str = ""
    observation_count: int = 0

    def to_dict(self) -> dict:
        return {
            "processes": sorted(self.processes),
            "hours": sorted(self.hours),
            "directories": sorted(self.directories),
            "connections": sorted(self.connections),
            "modified_files": sorted(self.modified_files),
            "learned_at": self.learned_at,
            "observation_count": self.observation_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> BehaviourBaseline:
        return cls(
            processes=set(data.get("processes", [])),
            hours=set(data.get("hours", [])),
            directories=set(data.get("directories", [])),
            connections=set(data.get("connections", [])),
            modified_files=set(data.get("modified_files", [])),
            learned_at=data.get("learned_at", ""),
            observation_count=data.get("observation_count", 0),
        )


@dataclass(frozen=True)
class Deviation:
    """A single deviation from the baseline."""

    type: str  # new_process | new_hour | new_directory | new_connection | new_modified_file
    value: str


@dataclass
class BehaviourBaselineResult:
    """Result of a learn or check run."""

    baseline_learned: bool
    baseline: BehaviourBaseline | None
    deviations: list[Deviation] = field(default_factory=list)
    total_observations: int = 0
    deviation_count: int = 0

    @property
    def deviation_rate(self) -> float:
        return (
            self.deviation_count / self.total_observations * 100.0
            if self.total_observations
            else 0.0
        )


# --------------------------------------------------------------------------- learn


def learn_from_observations(
    observations: list[BehaviourObservation],
) -> BehaviourBaseline:
    """Build a baseline from a list of observations (pure, testable)."""
    baseline = BehaviourBaseline(learned_at=now_iso())
    for obs in observations:
        baseline.processes.add(obs.process_name)
        baseline.hours.add(obs.hour_of_day)
        baseline.directories.add(obs.directory)
        if obs.connection:
            baseline.connections.add(obs.connection)
        if obs.modified_file:
            baseline.modified_files.add(obs.modified_file)
    baseline.observation_count = len(observations)
    return baseline


def find_deviations(
    observations: list[BehaviourObservation],
    baseline: BehaviourBaseline,
) -> list[Deviation]:
    """Compare observations against a baseline and return deviations (pure)."""
    deviations: list[Deviation] = []
    for obs in observations:
        if obs.process_name not in baseline.processes:
            deviations.append(Deviation("new_process", obs.process_name))
        if obs.hour_of_day not in baseline.hours:
            deviations.append(Deviation("new_hour", str(obs.hour_of_day)))
        if obs.directory not in baseline.directories:
            deviations.append(Deviation("new_directory", obs.directory))
        if obs.connection and obs.connection not in baseline.connections:
            deviations.append(Deviation("new_connection", obs.connection))
        if obs.modified_file and obs.modified_file not in baseline.modified_files:
            deviations.append(Deviation("new_modified_file", obs.modified_file))
    return deviations


# --------------------------------------------------------------------------- persist


BASELINE_META_KEY = "behaviour_baseline"


def save_baseline(state: State, baseline: BehaviourBaseline) -> None:
    """Persist the baseline to the state DB (meta table)."""
    state.set_meta(BASELINE_META_KEY, json.dumps(baseline.to_dict()))


def load_baseline(state: State) -> BehaviourBaseline | None:
    """Load the previously persisted baseline, or None if none exists."""
    raw = state.get_meta(BASELINE_META_KEY)
    if not raw:
        return None
    try:
        data = json.loads(raw)
        return BehaviourBaseline.from_dict(data)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- run


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _observations_from_directory(
    directory: Path,
    config: Config,
) -> list[BehaviourObservation]:
    """Build synthetic observations from files under *directory*.

    Each file represents an observed event: the process is derived from the
    file extension, the hour is the current hour, and the file itself is the
    modified file. This is a proxy for real activity — suitable for research
    measurement, not production blocking.
    """
    directory = directory.resolve()
    files = [p for p in walk_directory(directory, config) if p.is_file()]
    now = datetime.now(timezone.utc)
    observations: list[BehaviourObservation] = []
    for path in files:
        ext = path.suffix.lower().lstrip(".") or "unknown"
        observations.append(
            BehaviourObservation(
                process_name=f"process-{ext}",
                hour_of_day=now.hour,
                directory=str(path.parent),
                modified_file=str(path),
            )
        )
    return observations


def run_behaviour_baseline(
    directory: Path,
    config: Config,
    paths: Paths,
    state: State,
    engines: Engines,
    *,
    learn: bool = False,
    check: bool = False,
) -> BehaviourBaselineResult:
    """Learn a baseline from *directory* and/or check current activity against it.

    Exactly one of ``learn`` or ``check`` should be True. The baseline is
    persisted in *state* so that a later ``check`` can compare against it.
    Read-only: nothing is quarantined or mutated.
    """
    observations = _observations_from_directory(directory, config)

    if learn:
        baseline = learn_from_observations(observations)
        save_baseline(state, baseline)
        return BehaviourBaselineResult(
            baseline_learned=True,
            baseline=baseline,
            total_observations=len(observations),
            deviation_count=0,
        )

    if check:
        baseline = load_baseline(state)
        if baseline is None:
            return BehaviourBaselineResult(
                baseline_learned=False,
                baseline=None,
                total_observations=len(observations),
                deviation_count=0,
            )
        deviations = find_deviations(observations, baseline)
        return BehaviourBaselineResult(
            baseline_learned=False,
            baseline=baseline,
            deviations=deviations,
            total_observations=len(observations),
            deviation_count=len(deviations),
        )

    return BehaviourBaselineResult(
        baseline_learned=False,
        baseline=None,
        total_observations=len(observations),
        deviation_count=0,
    )
