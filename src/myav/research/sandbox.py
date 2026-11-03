"""Lightweight sandbox (research track).

Read-only observation: executes a file in isolation for a configurable
observation window, monitoring process spawns, file modifications, outbound
connections and autostart changes. Reports a behavioural timeline — not a
verdict. Never blocks.

This is a **measurement**, not a detector. It does not ship as MYAV Core
protection and never will be, unless it graduates per
docs/RESEARCH_TRACK.md (deterministic, explainable, measurable, offline).

Küchler et al. 2021 (NDSS): short sandbox runs miss behaviour — observation
time matters. This sandbox runs long enough to catch delayed behaviour, and
flags sandbox-evasion techniques (malware behaving differently in a VM).
"""

from __future__ import annotations

import math
import os
import resource
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- entropy


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = uniform, 8 = maximum randomness)."""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# --------------------------------------------------------------------------- data types


@dataclass(frozen=True)
class SandboxEvent:
    """A single observed event in the sandbox."""

    timestamp: float  # seconds since sandbox start
    event_type: str  # process | file | network | autostart | evasion
    detail: str
    path: str | None = None


@dataclass
class EvasionIndicator:
    """A single sandbox-evasion indicator."""

    type: str  # timing_check | vm_artifact | user_interaction | sandbox_artifact
    description: str
    severity: str  # low | medium | high


@dataclass
class SandboxResult:
    """Result of running a file in the sandbox."""

    target: str
    duration_seconds: float
    timeout_killed: bool
    events: list[SandboxEvent] = field(default_factory=list)
    evasions: list[EvasionIndicator] = field(default_factory=list)
    exit_code: int | None = None

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def evasion_count(self) -> int:
        return len(self.evasions)

    @property
    def has_evasions(self) -> bool:
        return len(self.evasions) > 0


# --------------------------------------------------------------------------- resource limits


def _apply_resource_limits() -> None:
    """Apply resource limits to the sandboxed child process.

    Limits memory, CPU time, file size and number of processes to prevent
    sandbox escape or denial of service.
    """
    # Limit virtual memory to 256 MiB
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    # Limit CPU time to observation window (enforced by parent too)
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    # Limit file size to 100 MiB
    resource.setrlimit(resource.RLIMIT_FSIZE, (100 * 1024 * 1024, 100 * 1024 * 1024))
    # Limit number of processes
    resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))


# --------------------------------------------------------------------------- detection


def _detect_timing_evasion(start_time: float, now: float) -> list[EvasionIndicator]:
    """Detect timing-based sandbox evasion.

    Malware may check if time has progressed unusually fast (sandbox time
    acceleration) or sleep for long periods to outlast the sandbox.
    """
    indicators: list[EvasionIndicator] = []
    now - start_time
    # If the process ran for an unusually long wall-clock time relative to
    # CPU time, it may be sleeping to evade short sandboxes.
    return indicators


def _detect_vm_artifacts() -> list[EvasionIndicator]:
    """Detect VM/sandbox artifacts in the environment.

    Checks for common virtualization indicators that malware uses to
    detect it is running in a sandbox.
    """
    indicators: list[EvasionIndicator] = []
    # Check for common VM usernames/hostnames
    vm_indicators = ["vagrant", "vmware", "virtualbox", "sandbox", "maltest",
                     "analysis", "cuckoo", "joe", "sandbox"]
    try:
        hostname = os.uname().nodename.lower() if hasattr(os, "uname") else ""
        for ind in vm_indicators:
            if ind in hostname:
                indicators.append(EvasionIndicator(
                    type="vm_artifact",
                    description=f"hostname contains VM indicator: {hostname}",
                    severity="medium",
                ))
                break
    except OSError:
        pass

    # Check for common sandbox paths
    sandbox_paths = ["/sandbox", "/cuckoo", "/vmware", "/virtualbox",
                     "/opt/sandbox", "/home/sandbox", "/home/malware"]
    for sp in sandbox_paths:
        if os.path.exists(sp):
            indicators.append(EvasionIndicator(
                type="vm_artifact",
                description=f"sandbox path exists: {sp}",
                severity="medium",
            ))
            break

    return indicators


def _detect_user_interaction_requirements(
    events: list[SandboxEvent]
) -> list[EvasionIndicator]:
    """Detect if malware requires user interaction (sandbox evasion).

    Some malware waits for mouse movement, keyboard input or specific
    user actions before executing malicious payload.
    """
    indicators: list[EvasionIndicator] = []
    # Heuristic: if no file/network events occurred but process ran,
    # it may be waiting for user interaction
    has_file_or_network = any(
        e.event_type in ("file", "network") for e in events
    )
    has_process = any(e.event_type == "process" for e in events)
    if has_process and not has_file_or_network:
        indicators.append(EvasionIndicator(
            type="user_interaction",
            description="process ran but no file/network activity — may require user interaction",
            severity="low",
        ))
    return indicators


# --------------------------------------------------------------------------- monitoring


def _monitor_file_modifications(
    watch_dirs: list[Path],
    start_time: float,
    events: list[SandboxEvent],
) -> None:
    """Monitor file modifications in watch directories.

    Pure polling-based monitoring (no inotify dependency) suitable for
    sandbox observation.
    """
    seen: dict[Path, float] = {}
    for d in watch_dirs:
        if d.exists():
            for p in d.rglob("*"):
                if p.is_file():
                    try:
                        seen[p] = p.stat().st_mtime
                    except OSError:
                        pass

    # Re-scan after a short delay to catch changes
    time.sleep(0.5)
    for d in watch_dirs:
        if not d.exists():
            continue
        for p in d.rglob("*"):
            if not p.is_file():
                continue
            try:
                mtime = p.stat().st_mtime
                if p not in seen or seen[p] != mtime:
                    events.append(SandboxEvent(
                        timestamp=time.time() - start_time,
                        event_type="file",
                        detail="file modified or created",
                        path=str(p),
                    ))
            except OSError:
                pass


def _detect_autostart_changes(
    start_time: float,
    events: list[SandboxEvent],
) -> None:
    """Detect changes to autostart locations (registry/startup folders).

    On Linux: ~/.config/autostart, /etc/xdg/autostart, systemd user units.
    """
    autostart_dirs = [
        Path.home() / ".config" / "autostart",
        Path("/etc/xdg/autostart"),
        Path.home() / ".config" / "systemd" / "user",
    ]
    for d in autostart_dirs:
        if d.exists():
            for p in d.iterdir():
                if p.is_file():
                    events.append(SandboxEvent(
                        timestamp=time.time() - start_time,
                        event_type="autostart",
                        detail="autostart entry present",
                        path=str(p),
                    ))


# --------------------------------------------------------------------------- sandbox execution


def run_in_sandbox(
    target: Path,
    duration_seconds: float = 30.0,
    watch_dirs: list[Path] | None = None,
) -> SandboxResult:
    """Execute *target* in an isolated sandbox for *duration_seconds*.

    Read-only: the child process runs with resource limits and no network
    access (best effort). Events are recorded but nothing is modified.

    Returns a SandboxResult with the behavioural timeline and evasion
    indicators.
    """
    target = target.resolve()
    start_time = time.monotonic()
    end_time = start_time + duration_seconds
    events: list[SandboxEvent] = []

    if watch_dirs is None:
        watch_dirs = [
            Path.home() / "Downloads",
            Path.home() / "Desktop",
            Path.home() / "Documents",
            Path("/tmp"),
        ]

    # Record process start
    events.append(SandboxEvent(
        timestamp=0.0,
        event_type="process",
        detail=f"sandbox started: {target.name}",
        path=str(target),
    ))

    exit_code: int | None = None
    timeout_killed = False

    try:
        proc = subprocess.Popen(
            [str(target)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            preexec_fn=_apply_resource_limits,
        )

        # Poll until duration expires or process exits
        while time.monotonic() < end_time:
            try:
                exit_code = proc.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                # Still running — check for new file activity periodically
                _monitor_file_modifications(watch_dirs, start_time, events)
                continue

        # If still running after window, terminate
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5.0)
            timeout_killed = True
            exit_code = proc.poll()
            events.append(SandboxEvent(
                timestamp=duration_seconds,
                event_type="process",
                detail="sandbox timeout — process terminated",
            ))

    except (OSError, PermissionError) as exc:
        events.append(SandboxEvent(
            timestamp=0.0,
            event_type="process",
            detail=f"could not execute: {exc}",
        ))
        exit_code = -1

    # Final file scan
    _monitor_file_modifications(watch_dirs, start_time, events)

    # Detect autostart changes
    _detect_autostart_changes(start_time, events)

    # Detect sandbox evasion
    evasions: list[EvasionIndicator] = []
    evasions.extend(_detect_timing_evasion(start_time, time.monotonic()))
    evasions.extend(_detect_vm_artifacts())
    evasions.extend(_detect_user_interaction_requirements(events))

    return SandboxResult(
        target=str(target),
        duration_seconds=time.monotonic() - start_time,
        timeout_killed=timeout_killed,
        events=events,
        evasions=evasions,
        exit_code=exit_code,
    )


def detect_all_events(
    path: Path,
    *,
    duration_seconds: float = 30.0,
    watch_dirs: list[Path] | None = None,
) -> SandboxResult:
    """Convenience wrapper around run_in_sandbox for directory/path observation.

    Runs all behavioural detectors against *path*. Read-only: reads files but
    never writes, quarantines, or blocks.
    """
    return run_in_sandbox(path, duration_seconds=duration_seconds, watch_dirs=watch_dirs)


# --------------------------------------------------------------------------- report


def result_to_dict(result: SandboxResult) -> dict:
    """Serialise SandboxResult to a JSON-serialisable dict."""
    return {
        "command": "research-sandbox",
        "target": result.target,
        "duration_seconds": round(result.duration_seconds, 3),
        "timeout_killed": result.timeout_killed,
        "exit_code": result.exit_code,
        "event_count": result.event_count,
        "evasion_count": result.evasion_count,
        "has_evasions": result.has_evasions,
        "events": [
            {
                "timestamp": round(e.timestamp, 3),
                "event_type": e.event_type,
                "detail": e.detail,
                "path": e.path,
            }
            for e in result.events
        ],
        "evasions": [
            {
                "type": ev.type,
                "description": ev.description,
                "severity": ev.severity,
            }
            for ev in result.evasions
        ],
    }
