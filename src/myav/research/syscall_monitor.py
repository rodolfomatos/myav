"""Syscall-level observation for the research sandbox (T036).

This module turns an ``strace`` log into structured, testable data. It never
executes anything itself: the sandbox decides when to run under ``strace`` and
passes the resulting text here.

The interesting detections are pure functions over a :class:`SyscallSummary`:

- **Mass encryption / destruction:** many distinct files written, renamed or
  unlinked in one short observation window.
- **Syscall evasion:** anti-debug ``ptrace``, fork/clone storms and self-deletion.

These are research findings, not verdicts. Nothing here ships as MYAV Core
protection unless it graduates per ``docs/RESEARCH_TRACK.md``.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

# Syscall families worth tracing: file operations, process creation, networking.
TRACE_EXPRESSION = "%file,%process,%network"

# Flags that mean an ``open*`` call can write to the path.
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")

_FORK_SYSCALLS = ("fork", "vfork", "clone", "clone3")

# ``[pid 123] name(args) = ret`` or ``123 name(args) = ret`` (strace -f -o).
_LINE_RE = re.compile(
    r"^(?:\[pid\s+\d+\]\s*|\d+\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<args>.*)\)\s+=\s+(?P<ret>.*)$"
)
_QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_CONNECT_TARGET_RE = re.compile(
    r'(?:inet_addr\s*\(?|inet_pton\([^,]+,\s*|sun_path=)\s*"([^"]+)"'
)


# --------------------------------------------------------------------------- data types


@dataclass(frozen=True)
class RenameOp:
    """A successful rename observed in the trace."""

    old: str
    new: str

    def to_dict(self) -> dict:
        return {"old": self.old, "new": self.new}


@dataclass(frozen=True)
class ConnectOp:
    """A successful outbound connection target."""

    target: str

    def to_dict(self) -> dict:
        return {"target": self.target}


@dataclass
class SyscallSummary:
    """Structured view over a parsed ``strace`` log."""

    syscall_counts: dict[str, int] = field(default_factory=dict)
    files_written: list[str] = field(default_factory=list)
    renames: list[RenameOp] = field(default_factory=list)
    unlinks: list[str] = field(default_factory=list)
    execs: list[str] = field(default_factory=list)
    connects: list[ConnectOp] = field(default_factory=list)
    lines_parsed: int = 0
    lines_skipped: int = 0

    @property
    def total_syscalls(self) -> int:
        return sum(self.syscall_counts.values())

    @property
    def unique_files_written(self) -> list[str]:
        return list(dict.fromkeys(self.files_written))

    @property
    def ptrace_calls(self) -> int:
        return self.syscall_counts.get("ptrace", 0)

    @property
    def fork_calls(self) -> int:
        return sum(self.syscall_counts.get(name, 0) for name in _FORK_SYSCALLS)

    def to_dict(self) -> dict:
        return {
            "total_syscalls": self.total_syscalls,
            "lines_parsed": self.lines_parsed,
            "lines_skipped": self.lines_skipped,
            "syscall_counts": dict(
                sorted(
                    self.syscall_counts.items(),
                    key=lambda item: item[1],
                    reverse=True,
                )
            ),
            "files_written": self.unique_files_written,
            "renames": [op.to_dict() for op in self.renames],
            "unlinks": list(self.unlinks),
            "execs": list(self.execs),
            "connects": [op.to_dict() for op in self.connects],
            "ptrace_calls": self.ptrace_calls,
            "fork_calls": self.fork_calls,
        }


@dataclass(frozen=True)
class Finding:
    """A syscall-level behavioural finding (alert, never a verdict)."""

    kind: str
    severity: str  # low | medium | high
    description: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "description": self.description,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------- strace plumbing


def strace_available() -> bool:
    """Return True when an ``strace`` binary is on PATH."""
    return shutil.which("strace") is not None


def build_strace_command(target: Path, output_path: Path) -> list[str]:
    """Build the argv used to run *target* under ``strace``.

    ``-qq`` suppresses attach/exit chatter, ``-f`` follows children, and ``--``
    stops option parsing so a target name can never be mistaken for a flag.
    """
    return [
        "strace",
        "-f",
        "-qq",
        "-e",
        f"trace={TRACE_EXPRESSION}",
        "-o",
        str(output_path),
        "--",
        str(target),
    ]


# --------------------------------------------------------------------------- parser


def _quoted(args: str) -> list[str]:
    """Return every double-quoted argument, unescaping ``\\"`` and ``\\\\``."""
    return [m.group(1).replace('\\"', '"').replace("\\\\", "\\") for m in _QUOTED_RE.finditer(args)]


def _result_ok(ret: str) -> bool:
    """A syscall line is successful unless it returned ``-1``."""
    return not ret.lstrip().startswith("-1")


def _write_path(name: str, args: str, quoted: list[str]) -> str | None:
    """Return the path an ``open*``/``creat`` call would write, if any."""
    if name == "creat":
        return quoted[0] if quoted else None
    if name == "open":
        if quoted and any(flag in args for flag in WRITE_FLAGS):
            return quoted[0]
        return None
    if name in ("openat", "openat2"):
        if quoted and any(flag in args for flag in WRITE_FLAGS):
            return quoted[0]
        return None
    return None


def _unlink_path(name: str, quoted: list[str]) -> str | None:
    if name in ("unlink", "rmdir"):
        return quoted[0] if quoted else None
    if name == "unlinkat":
        return quoted[0] if quoted else None
    return None


def parse_strace_log(text: str) -> SyscallSummary:
    """Parse an ``strace -f -e trace=%file,%process,%network`` log.

    Failures (``= -1``) are counted as syscalls but never recorded as writes,
    renames or unlinks. Unfinished/resumed lines are skipped safely.
    """
    summary = SyscallSummary()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("+++") or line.startswith("---"):
            continue
        match = _LINE_RE.match(line)
        if match is None:
            summary.lines_skipped += 1
            continue

        name = match.group("name")
        args = match.group("args")
        ret = match.group("ret")
        summary.lines_parsed += 1
        summary.syscall_counts[name] = summary.syscall_counts.get(name, 0) + 1

        if not _result_ok(ret):
            continue

        quoted = _quoted(args)

        written = _write_path(name, args, quoted)
        if written is not None:
            summary.files_written.append(written)

        if name in ("rename", "renameat", "renameat2") and len(quoted) >= 2:
            summary.renames.append(RenameOp(old=quoted[0], new=quoted[1]))

        unlinked = _unlink_path(name, quoted)
        if unlinked is not None:
            summary.unlinks.append(unlinked)

        if name in ("execve", "execveat") and quoted:
            summary.execs.append(quoted[0])

        if name == "connect":
            target = _CONNECT_TARGET_RE.search(args)
            if target is not None:
                summary.connects.append(ConnectOp(target=target.group(1)))

    return summary


# --------------------------------------------------------------------------- detection


def detect_mass_encryption(
    summary: SyscallSummary,
    *,
    min_writes: int = 20,
    min_renames: int = 10,
    min_unlinks: int = 10,
) -> list[Finding]:
    """Flag ransomware-like mass encryption or destruction.

    Thresholds are explicit and configurable. The finding reports the observed
    counts so an operator can tell a compiler from a payload.
    """
    writes = len(summary.unique_files_written)
    renames = len(summary.renames)
    unlinks = len(summary.unlinks)
    findings: list[Finding] = []

    if writes >= min_writes or renames >= min_renames:
        findings.append(
            Finding(
                kind="ransomware_mass_encryption",
                severity="high",
                description=(
                    "Mass file writes/renames observed — possible ransomware encryption"
                ),
                detail=(
                    f"{writes} file(s) written, {renames} renamed "
                    f"(thresholds: {min_writes} writes / {min_renames} renames)"
                ),
            )
        )

    if unlinks >= min_unlinks:
        findings.append(
            Finding(
                kind="ransomware_mass_delete",
                severity="high",
                description="Mass file deletion observed — possible destructive payload",
                detail=f"{unlinks} file(s) unlinked (threshold: {min_unlinks})",
            )
        )

    return findings


def detect_syscall_evasion(
    summary: SyscallSummary,
    *,
    target: str | None = None,
    fork_threshold: int = 50,
) -> list[Finding]:
    """Flag anti-debug, fork storms and self-deletion seen in the trace."""
    findings: list[Finding] = []

    ptrace_calls = summary.ptrace_calls
    if ptrace_calls:
        findings.append(
            Finding(
                kind="evasion_ptrace",
                severity="high",
                description="ptrace observed — possible anti-debug avoidance",
                detail=f"{ptrace_calls} ptrace call(s)",
            )
        )

    forks = summary.fork_calls
    if forks >= fork_threshold:
        findings.append(
            Finding(
                kind="evasion_fork_bomb",
                severity="medium",
                description="Fork/clone storm observed — possible resource exhaustion",
                detail=f"{forks} fork/clone call(s) (threshold: {fork_threshold})",
            )
        )

    if target is not None and target in summary.unlinks:
        findings.append(
            Finding(
                kind="evasion_self_delete",
                severity="high",
                description="Payload deleted its own file — possible anti-forensics",
                detail=f"unlink({target})",
            )
        )

    return findings


def analyse_strace_log(
    text: str, *, target: str | None = None
) -> tuple[SyscallSummary, list[Finding]]:
    """Parse *text* and run every syscall-level detector over it."""
    summary = parse_strace_log(text)
    findings = detect_mass_encryption(summary)
    findings.extend(detect_syscall_evasion(summary, target=target))
    return summary, findings
