"""Lightweight sandbox tests (research track).

These tests verify the measurement tooling only — no detection feature ships
as part of MYAV Core from this ticket.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from myav.research.sandbox import (
    EvasionIndicator,
    SandboxEvent,
    SandboxResult,
    _detect_timing_evasion,
    _detect_user_interaction_requirements,
    _detect_vm_artifacts,
    detect_all_events,
    result_to_dict,
    run_in_sandbox,
    shannon_entropy,
)


def test_shannon_entropy() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00\x00\x00") == 0.0
    assert shannon_entropy(b"\x00\x01\x02\x03") > 1.0


def test_sandbox_event_dataclass() -> None:
    e = SandboxEvent(
        timestamp=1.5,
        event_type="process",
        detail="test process",
        path="/tmp/test",
    )
    assert e.timestamp == 1.5
    assert e.event_type == "process"
    assert e.detail == "test process"
    assert e.path == "/tmp/test"


def test_sandbox_result_dataclass() -> None:
    r = SandboxResult(
        target="/tmp/test",
        duration_seconds=5.0,
        timeout_killed=False,
        exit_code=0,
    )
    assert r.target == "/tmp/test"
    assert r.event_count == 0
    assert r.evasion_count == 0
    assert not r.has_evasions


def test_detect_vm_artifacts_no_vm(tmp_path: Path) -> None:
    indicators = _detect_vm_artifacts()
    # May or may not find VM artifacts depending on environment; just check it runs
    assert isinstance(indicators, list)


def test_detect_user_interaction_no_events() -> None:
    indicators = _detect_user_interaction_requirements([])
    assert isinstance(indicators, list)


def test_detect_user_interaction_process_only() -> None:
    events = [
        SandboxEvent(timestamp=0.0, event_type="process", detail="proc started"),
    ]
    indicators = _detect_user_interaction_requirements(events)
    # Process ran but no file/network activity -> may require user interaction
    assert any(ev.type == "user_interaction" for ev in indicators)


def test_detect_user_interaction_with_file_event() -> None:
    events = [
        SandboxEvent(timestamp=0.0, event_type="process", detail="proc started"),
        SandboxEvent(timestamp=0.5, event_type="file", detail="file modified", path="/tmp/test"),
    ]
    indicators = _detect_user_interaction_requirements(events)
    # File event present, so no user interaction evasion expected
    assert not any(ev.type == "user_interaction" for ev in indicators)


def test_detect_timing_evasion() -> None:
    start = 0.0
    indicators = _detect_timing_evasion(start, start + 10.0)
    assert isinstance(indicators, list)


def test_run_in_sandbox_nonexistent_file(tmp_path: Path) -> None:
    nonexistent = tmp_path / "does_not_exist"
    result = run_in_sandbox(nonexistent, duration_seconds=1.0)
    assert result.exit_code == -1
    assert len(result.events) >= 1


def test_run_in_sandbox_hello_world(tmp_path: Path) -> None:
    # Create a simple script that just exits
    script = tmp_path / "hello.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    os.chmod(script, stat.S_IRUSR | stat.S_IXUSR)

    result = run_in_sandbox(script, duration_seconds=5.0)
    assert result.target == str(script)
    assert result.event_count >= 1
    # Should have a process start event
    assert any(e.event_type == "process" for e in result.events)


def test_run_in_sandbox_timeout(tmp_path: Path) -> None:
    # Create a script that runs forever
    script = tmp_path / "forever.sh"
    script.write_text("#!/bin/sh\nwhile true; do sleep 1; done\n")
    os.chmod(script, stat.S_IRUSR | stat.S_IXUSR)

    result = run_in_sandbox(script, duration_seconds=2.0)
    # Sandbox should complete without crashing; timeout_killed may be True or
    # False depending on system behaviour, but it should not raise.
    assert result.exit_code is not None
    assert result.duration_seconds >= 0.0


def test_result_to_dict() -> None:
    result = SandboxResult(
        target="/tmp/test",
        duration_seconds=5.0,
        timeout_killed=False,
        exit_code=0,
        events=[
            SandboxEvent(
                timestamp=0.0,
                event_type="process",
                detail="test",
                path="/tmp/test",
            )
        ],
        evasions=[
            EvasionIndicator(
                type="vm_artifact",
                description="test vm",
                severity="medium",
            )
        ],
    )
    d = result_to_dict(result)
    assert d["command"] == "research-sandbox"
    assert d["target"] == "/tmp/test"
    assert d["duration_seconds"] == 5.0
    assert d["event_count"] == 1
    assert d["evasion_count"] == 1
    assert d["has_evasions"] is True
    assert len(d["events"]) == 1
    assert len(d["evasions"]) == 1


def test_run_in_sandbox_json_serializable(tmp_path: Path) -> None:
    script = tmp_path / "hello.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    os.chmod(script, stat.S_IRUSR | stat.S_IXUSR)

    result = run_in_sandbox(script, duration_seconds=2.0)
    d = result_to_dict(result)
    # Must be JSON-serializable
    json.dumps(d)


def test_detect_all_events_empty(tmp_path: Path) -> None:
    result = detect_all_events(tmp_path)
    assert isinstance(result, SandboxResult)
    assert result.target == str(tmp_path.resolve())


def test_sandbox_respects_duration(tmp_path: Path) -> None:
    script = tmp_path / "quick.sh"
    script.write_text("#!/bin/sh\nexit 42\n")
    os.chmod(script, stat.S_IRUSR | stat.S_IXUSR)

    result = run_in_sandbox(script, duration_seconds=10.0)
    assert result.duration_seconds < 10.0  # Should exit quickly
    assert result.exit_code == 42
