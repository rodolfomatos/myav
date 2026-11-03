"""User behaviour baseline tests (research track).

These tests verify the measurement tooling only — no detection feature ships
as part of MYAV Core from this ticket.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from myav.config import Config
from myav.paths import Paths, default_paths
from myav.platforms import detect_platform
from myav.research.behaviour_baseline import (
    BehaviourBaseline,
    BehaviourObservation,
    Deviation,
    find_deviations,
    learn_from_observations,
    run_behaviour_baseline,
)
from myav.state import State


@pytest.fixture
def behaviour_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    for name in ("Downloads", "Desktop", "Documents"):
        (home / name).mkdir(parents=True)
    return home


@pytest.fixture
def behaviour_platform(behaviour_home: Path):
    return detect_platform(home=behaviour_home, env={"MYAV_PLATFORM": "linux"})


@pytest.fixture
def behaviour_paths(behaviour_home: Path, behaviour_platform) -> Paths:
    return default_paths(home=behaviour_home, platform=behaviour_platform)


@pytest.fixture
def behaviour_config(behaviour_paths: Paths, behaviour_home: Path) -> Config:
    config = Config(paths=behaviour_paths)
    config.watcher.watch_dirs = [behaviour_home / "Downloads"]
    return config


@pytest.fixture
def behaviour_state(behaviour_paths: Paths) -> State:
    return State(behaviour_paths.state_db)


@pytest.fixture
def behaviour_engines(behaviour_platform):
    from myav.pipeline import Engines

    return Engines(
        clamav=None,
        yara=None,
        virustotal=None,
        signature_info=None,
        platform=behaviour_platform,
    )


def test_learn_from_observations_builds_baseline() -> None:
    obs = [
        BehaviourObservation("python", 10, "/home/u/Downloads"),
        BehaviourObservation("python", 10, "/home/u/Downloads"),
        BehaviourObservation("bash", 14, "/home/u/Documents"),
        BehaviourObservation(
            "firefox", 9, "/home/u/Desktop", connection="example.com:443"
        ),
    ]
    baseline = learn_from_observations(obs)

    assert baseline.processes == {"python", "bash", "firefox"}
    assert baseline.hours == {10, 14, 9}
    assert baseline.directories == {"/home/u/Downloads", "/home/u/Documents", "/home/u/Desktop"}
    assert baseline.connections == {"example.com:443"}
    assert baseline.modified_files == set()
    assert baseline.observation_count == 4
    assert baseline.learned_at


def test_find_deviations_detects_new_items() -> None:
    baseline = BehaviourBaseline(
        processes={"python", "bash"},
        hours={10, 14},
        directories={"/home/u/Downloads"},
        connections={"example.com:443"},
        modified_files={"/home/u/Downloads/a.txt"},
        learned_at="2026-11-03T10:00:00+00:00",
        observation_count=3,
    )

    obs = [
        BehaviourObservation("python", 10, "/home/u/Downloads"),  # normal
        BehaviourObservation(
            "firefox", 2, "/home/u/Documents",
            connection="evil.com:1234", modified_file="/home/u/Downloads/new.bin",
        ),  # 4 deviations
    ]
    deviations = find_deviations(obs, baseline)

    dev_types = {d.type for d in deviations}
    assert "new_process" in dev_types
    assert "new_hour" in dev_types
    assert "new_directory" in dev_types
    assert "new_connection" in dev_types
    assert "new_modified_file" in dev_types
    assert len(deviations) == 5


def test_find_deviations_no_deviations() -> None:
    baseline = BehaviourBaseline(
        processes={"python"},
        hours={10},
        directories={"/home/u/Downloads"},
        connections=set(),
        modified_files=set(),
        learned_at="2026-11-03T10:00:00+00:00",
        observation_count=1,
    )

    obs = [
        BehaviourObservation("python", 10, "/home/u/Downloads"),
    ]
    deviations = find_deviations(obs, baseline)
    assert deviations == []


def test_learn_and_check_roundtrip(
    behaviour_config, behaviour_paths, behaviour_state, behaviour_engines, tmp_path: Path
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello")
    (corpus / "b.py").write_text("print(1)")

    # Learn phase
    result_learn = run_behaviour_baseline(
        corpus,
        behaviour_config,
        behaviour_paths,
        behaviour_state,
        behaviour_engines,
        learn=True,
    )
    assert result_learn.baseline_learned is True
    assert result_learn.total_observations == 2
    assert result_learn.deviation_count == 0
    b = result_learn.baseline
    assert b is not None
    assert "process-txt" in b.processes
    assert "process-py" in b.processes

    # Check phase with same files -> no deviations
    result_check = run_behaviour_baseline(
        corpus,
        behaviour_config,
        behaviour_paths,
        behaviour_state,
        behaviour_engines,
        check=True,
    )
    assert result_check.baseline_learned is False
    assert result_check.deviation_count == 0
    assert result_check.deviation_rate == 0.0


def test_check_with_deviations(
    behaviour_config, behaviour_paths, behaviour_state, behaviour_engines, tmp_path: Path
) -> None:
    corpus1 = tmp_path / "corpus1"
    corpus1.mkdir()
    (corpus1 / "a.txt").write_text("hello")

    corpus2 = tmp_path / "corpus2"
    corpus2.mkdir()
    (corpus2 / "b.py").write_text("print(1)")
    (corpus2 / "c.sh").write_text("#!/bin/bash")

    # Learn from corpus1 only
    run_behaviour_baseline(
        corpus1,
        behaviour_config,
        behaviour_paths,
        behaviour_state,
        behaviour_engines,
        learn=True,
    )

    # Check corpus2 (has new process py and sh, new directory)
    result = run_behaviour_baseline(
        corpus2,
        behaviour_config,
        behaviour_paths,
        behaviour_state,
        behaviour_engines,
        check=True,
    )
    assert result.deviation_count > 0
    dev_types = {d.type for d in result.deviations}
    assert "new_process" in dev_types
    assert "new_directory" in dev_types


def test_check_without_baseline_returns_none(
    behaviour_config, behaviour_paths, behaviour_state, behaviour_engines, tmp_path: Path
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello")

    result = run_behaviour_baseline(
        corpus,
        behaviour_config,
        behaviour_paths,
        behaviour_state,
        behaviour_engines,
        check=True,
    )
    assert result.baseline_learned is False
    assert result.baseline is None
    assert result.deviation_count == 0


def test_behaviour_baseline_serialization_roundtrip() -> None:
    baseline = BehaviourBaseline(
        processes={"python", "bash"},
        hours={10, 14},
        directories={"/home/u/Downloads"},
        connections={"example.com:443"},
        modified_files={"/home/u/Downloads/a.txt"},
        learned_at="2026-11-03T10:00:00+00:00",
        observation_count=5,
    )
    d = baseline.to_dict()
    restored = BehaviourBaseline.from_dict(d)
    assert restored.processes == baseline.processes
    assert restored.hours == baseline.hours
    assert restored.directories == baseline.directories
    assert restored.connections == baseline.connections
    assert restored.modified_files == baseline.modified_files
    assert restored.learned_at == baseline.learned_at
    assert restored.observation_count == baseline.observation_count


def test_deviation_dataclass() -> None:
    d = Deviation("new_process", "firefox")
    assert d.type == "new_process"
    assert d.value == "firefox"


def test_deviation_rate_property() -> None:
    from myav.research.behaviour_baseline import BehaviourBaselineResult

    # No observations
    r = BehaviourBaselineResult(
        baseline_learned=False, baseline=None, total_observations=0, deviation_count=0
    )
    assert r.deviation_rate == 0.0

    # Some deviations
    r = BehaviourBaselineResult(
        baseline_learned=False,
        baseline=None,
        total_observations=10,
        deviation_count=3,
    )
    assert r.deviation_rate == 30.0
