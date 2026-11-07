"""Syscall-level sandbox observation tests (T036).

Everything here is pure: the parser consumes synthetic ``strace`` text, so the
tests do not need ptrace permissions or a real payload.
"""

from __future__ import annotations

from pathlib import Path

from myav.research.syscall_monitor import (
    ConnectOp,
    Finding,
    RenameOp,
    SyscallSummary,
    analyse_strace_log,
    build_strace_command,
    detect_mass_encryption,
    detect_syscall_evasion,
    parse_strace_log,
    strace_available,
)


def _log(*lines: str) -> str:
    return "\n".join(lines) + "\n"


def test_strace_available_returns_bool() -> None:
    assert isinstance(strace_available(), bool)


def test_build_strace_command() -> None:
    cmd = build_strace_command(Path("/tmp/sample"), Path("/tmp/trace.log"))
    assert cmd[0] == "strace"
    assert "-f" in cmd
    assert "trace=%file,%process,%network" in cmd
    assert cmd[-2:] == ["--", "/tmp/sample"]
    assert "/tmp/trace.log" in cmd


def test_parse_empty_log() -> None:
    summary = parse_strace_log("")
    assert summary.total_syscalls == 0
    assert summary.files_written == []
    assert summary.lines_parsed == 0


def test_parse_counts_and_operations() -> None:
    text = _log(
        '1234 execve("/bin/payload", ["/bin/payload"], 0x0) = 0',
        '1234 openat(AT_FDCWD, "/tmp/read.txt", O_RDONLY) = 3',
        '1234 openat(AT_FDCWD, "/tmp/out.bin", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4',
        '1234 open("/tmp/out2.bin", O_WRONLY|O_APPEND) = 5',
        '1234 openat(AT_FDCWD, "/tmp/fail.bin", O_WRONLY|O_CREAT, 0666) '
        "= -1 EACCES (Permission denied)",
        '1234 rename("/tmp/a", "/tmp/b") = 0',
        '1234 renameat(AT_FDCWD, "/tmp/c", AT_FDCWD, "/tmp/d") = 0',
        '1234 unlink("/tmp/old") = 0',
        '1234 unlinkat(AT_FDCWD, "/tmp/old2", 0) = 0',
        '1234 connect(3, {sa_family=AF_INET, sin_port=htons(80), '
        'sin_addr=inet_addr("1.2.3.4")}, 16) = 0',
    )
    summary = parse_strace_log(text)

    assert summary.lines_parsed == 10
    assert summary.lines_skipped == 0
    assert summary.syscall_counts["openat"] == 3
    # Read-only opens and failed writes never count as writes.
    assert summary.unique_files_written == ["/tmp/out.bin", "/tmp/out2.bin"]
    assert summary.renames == [
        RenameOp(old="/tmp/a", new="/tmp/b"),
        RenameOp(old="/tmp/c", new="/tmp/d"),
    ]
    assert summary.unlinks == ["/tmp/old", "/tmp/old2"]
    assert summary.execs == ["/bin/payload"]
    assert summary.connects == [ConnectOp(target="1.2.3.4")]


def test_parse_pid_prefix_and_bracket_prefix() -> None:
    text = _log(
        '1234 openat(AT_FDCWD, "/tmp/a", O_WRONLY|O_CREAT) = 3',
        '[pid 99] openat(AT_FDCWD, "/tmp/b", O_WRONLY|O_CREAT) = 4',
    )
    summary = parse_strace_log(text)
    assert summary.unique_files_written == ["/tmp/a", "/tmp/b"]


def test_parse_skips_unfinished_and_noise() -> None:
    text = _log(
        "+++ exited with 0 +++",
        '1234 openat(AT_FDCWD, "/tmp/a", O_WRONLY|O_CREAT <unfinished ...>',
        "1234 <... openat resumed>) = 3",
        '1234 openat(AT_FDCWD, "/tmp/b", O_WRONLY|O_CREAT) = 4',
    )
    summary = parse_strace_log(text)
    assert summary.lines_parsed == 1
    assert summary.lines_skipped == 2
    assert summary.unique_files_written == ["/tmp/b"]


def test_summary_to_dict() -> None:
    summary = SyscallSummary(
        syscall_counts={"openat": 2, "clone": 1},
        files_written=["/tmp/a", "/tmp/a", "/tmp/b"],
        renames=[RenameOp("/tmp/a", "/tmp/b")],
        unlinks=["/tmp/c"],
        execs=["/bin/x"],
        connects=[ConnectOp("10.0.0.1")],
        lines_parsed=6,
    )
    payload = summary.to_dict()
    assert payload["total_syscalls"] == 3
    assert payload["files_written"] == ["/tmp/a", "/tmp/b"]
    assert payload["renames"] == [{"old": "/tmp/a", "new": "/tmp/b"}]
    assert payload["connects"] == [{"target": "10.0.0.1"}]
    assert payload["ptrace_calls"] == 0
    assert payload["fork_calls"] == 1


def test_mass_encryption_writes_threshold() -> None:
    summary = SyscallSummary(files_written=[f"/tmp/f{i}" for i in range(20)])
    findings = detect_mass_encryption(summary, min_writes=20)
    assert [f.kind for f in findings] == ["ransomware_mass_encryption"]
    assert findings[0].severity == "high"


def test_mass_encryption_renames_threshold() -> None:
    summary = SyscallSummary(
        renames=[RenameOp(f"/tmp/a{i}", f"/tmp/a{i}.locked") for i in range(10)]
    )
    findings = detect_mass_encryption(summary, min_renames=10)
    assert [f.kind for f in findings] == ["ransomware_mass_encryption"]


def test_mass_deletion_threshold() -> None:
    summary = SyscallSummary(unlinks=[f"/tmp/f{i}" for i in range(10)])
    findings = detect_mass_encryption(summary, min_unlinks=10)
    assert [f.kind for f in findings] == ["ransomware_mass_delete"]


def test_mass_encryption_below_threshold_is_quiet() -> None:
    summary = SyscallSummary(
        files_written=["/tmp/a"],
        renames=[RenameOp("/tmp/a", "/tmp/b")],
        unlinks=["/tmp/c"],
    )
    assert detect_mass_encryption(summary) == []


def test_evasion_ptrace() -> None:
    summary = SyscallSummary(syscall_counts={"ptrace": 1})
    findings = detect_syscall_evasion(summary)
    assert [f.kind for f in findings] == ["evasion_ptrace"]
    assert findings[0].severity == "high"


def test_evasion_fork_storm() -> None:
    summary = SyscallSummary(syscall_counts={"clone": 30, "fork": 20})
    findings = detect_syscall_evasion(summary, fork_threshold=50)
    assert [f.kind for f in findings] == ["evasion_fork_bomb"]


def test_evasion_self_delete() -> None:
    summary = SyscallSummary(unlinks=["/tmp/payload"])
    findings = detect_syscall_evasion(summary, target="/tmp/payload")
    assert [f.kind for f in findings] == ["evasion_self_delete"]


def test_evasion_self_delete_requires_match() -> None:
    summary = SyscallSummary(unlinks=["/tmp/something-else"])
    assert detect_syscall_evasion(summary, target="/tmp/payload") == []


def test_analyse_strace_log_combines_findings() -> None:
    lines = [
        '99 execve("/tmp/payload", ["/tmp/payload"], 0x0) = 0',
        "99 ptrace(PTRACE_TRACEME, 0, NULL, NULL) = 0",
        '99 unlink("/tmp/payload") = 0',
    ]
    lines.extend(
        f'99 openat(AT_FDCWD, "/tmp/f{i}", O_WRONLY|O_CREAT) = 3' for i in range(20)
    )
    summary, findings = analyse_strace_log(_log(*lines), target="/tmp/payload")
    kinds = {f.kind for f in findings}
    assert summary.total_syscalls == 23
    assert {"ransomware_mass_encryption", "evasion_ptrace", "evasion_self_delete"} <= kinds


def test_finding_to_dict() -> None:
    finding = Finding(
        kind="ransomware_mass_encryption",
        severity="high",
        description="desc",
        detail="detail",
    )
    assert finding.to_dict() == {
        "kind": "ransomware_mass_encryption",
        "severity": "high",
        "description": "desc",
        "detail": "detail",
    }
