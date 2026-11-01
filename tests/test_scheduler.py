"""Scheduler rendering per platform.

The important guarantees: nothing is written unless ``yes=True``; root-owned artefacts are
printed, never written; and the three supported scheduler families each produce a usable
file for the four recurring jobs.
"""

from __future__ import annotations

from pathlib import Path

from myav import scheduler
from myav.platforms import detect_platform


def test_render_systemd(platform, tmp_path: Path) -> None:
    artefacts = scheduler.render(platform, tmp_path, "rodolfo", binary=Path("/usr/bin/myav"))
    labels = [item.label for item in artefacts]
    assert "watch service" in labels
    assert "update timer" in labels
    assert "scan timer" in labels
    assert "clamd unit (system)" in labels

    watch = next(item for item in artefacts if item.label == "watch service")
    assert "ExecStart=/usr/bin/myav watch" in watch.content
    assert not watch.needs_root

    clamd = next(item for item in artefacts if item.label == "clamd unit (system)")
    assert clamd.needs_root
    assert clamd.path is not None

    scan_timer = next(item for item in artefacts if item.label == "scan timer")
    assert "Sun *-*-* 03:00:00" in scan_timer.content

    update_timer = next(item for item in artefacts if item.label == "update timer")
    assert "02:30:00" in update_timer.content


def test_render_default_binary(platform, tmp_path: Path) -> None:
    artefacts = scheduler.render(platform, tmp_path, "user")
    watch = next(item for item in artefacts if item.label == "watch service")
    assert f"ExecStart={tmp_path / 'bin' / 'myav'} watch" in watch.content


def test_install_dry_run_writes_nothing(platform, tmp_path: Path) -> None:
    artefacts = scheduler.render(platform, tmp_path, "user", binary=Path("/usr/bin/myav"))
    actions = scheduler.install(artefacts, yes=False)
    assert any(action.startswith("WOULD WRITE:") for action in actions)
    assert any(action.startswith("MANUAL:") for action in actions)
    assert not any((tmp_path / ".config").rglob("myav-*"))


def test_install_writes_user_level_only(platform, tmp_path: Path) -> None:
    artefacts = scheduler.render(platform, tmp_path, "user", binary=Path("/usr/bin/myav"))
    actions = scheduler.install(artefacts, yes=True)
    assert any(action.startswith("WROTE:") for action in actions)
    assert any(action.startswith("MANUAL:") for action in actions)
    written = list((platform.dirs.home / ".config" / "systemd" / "user").glob("myav-*"))
    assert len(written) == 5
    # The root-owned clamd unit is printed, never written.
    assert not (platform.dirs.home / ".config" / "systemd" / "user" / "myav-clamd.service").exists()


def test_render_launchd() -> None:
    mac = detect_platform(env={"MYAV_PLATFORM": "macos"})
    artefacts = scheduler.render(mac, Path("/opt/myav"), "u", binary=Path("/usr/bin/myav"))
    labels = [item.label for item in artefacts]
    assert "watch agent" in labels
    assert "weekly agent" in labels
    weekly = next(item for item in artefacts if item.label == "weekly agent")
    assert "StartCalendarInterval" in weekly.content
    assert "<key>Weekday</key><integer>0</integer>" in weekly.content


def test_render_task_scheduler_wsl() -> None:
    wsl = detect_platform(env={"MYAV_PLATFORM": "wsl"})
    artefacts = scheduler.render(wsl, Path("/opt/myav"), "rodolfo", distro="Ubuntu")
    assert len(artefacts) == 1
    script = artefacts[0].content
    assert "myav-watch" in script
    assert "myav-weekly" in script
    assert "wsl.exe" in script
    assert "-d Ubuntu" in script
    assert "-Weekly -DaysOfWeek Sunday -At 03:00" in script
    assert "MultipleInstances IgnoreNew" in script


def test_render_task_scheduler_native_windows_runs_binary_directly() -> None:
    """Native Windows must not route through wsl.exe, and must quote a spaced path."""
    windows = detect_platform(env={"MYAV_PLATFORM": "windows"})
    binary = Path(r"C:\Program Files\myav\myav.exe")
    artefacts = scheduler.render(windows, Path(r"C:\myav"), "rodolfo", binary=binary)
    script = artefacts[0].content
    assert "wsl.exe" not in script
    assert "-Execute 'C:\\Program Files\\myav\\myav.exe'" in script
    assert "-Argument 'watch'" in script
    assert "-Argument 'full-scan --report'" in script
    assert "-Weekly -DaysOfWeek Sunday -At 03:00" in script


def test_render_unknown_scheduler() -> None:
    android = detect_platform(env={"MYAV_PLATFORM": "android"})
    assert scheduler.render(android, Path("/opt/myav"), "u") == []


def test_status_systemd(platform, tmp_path: Path) -> None:
    units = platform.dirs.home / ".config" / "systemd" / "user"
    units.mkdir(parents=True)
    (units / "myav-watch.service").write_text("x")
    result = scheduler.status(platform, tmp_path, "u")
    assert result["installed"] == ["myav-watch.service"]


def test_status_systemd_none(platform, tmp_path: Path) -> None:
    result = scheduler.status(platform, tmp_path, "u")
    assert result["installed"] == []


def test_status_launchd(tmp_path: Path) -> None:
    mac = detect_platform(home=tmp_path, env={"MYAV_PLATFORM": "macos"})
    agents = mac.dirs.home / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    (agents / "dev.myav.watch.plist").write_text("x")
    result = scheduler.status(mac, tmp_path, "u")
    assert result["installed"] == ["dev.myav.watch.plist"]


def test_status_task_scheduler_unreachable(monkeypatch, tmp_path: Path) -> None:
    windows = detect_platform(env={"MYAV_PLATFORM": "windows"})
    monkeypatch.setattr(scheduler.shutil, "which", lambda name: None)
    monkeypatch.setattr(scheduler.Path, "exists", lambda self: False)
    result = scheduler.status(windows, tmp_path, "u")
    assert result["installed"] == []
    assert "schtasks not reachable" in result["note"]


def test_status_task_scheduler_reads_names(monkeypatch, tmp_path: Path) -> None:
    windows = detect_platform(env={"MYAV_PLATFORM": "windows"})
    monkeypatch.setattr(scheduler.shutil, "which", lambda name: "/fake/schtasks.exe")
    monkeypatch.setattr(scheduler.Path, "exists", lambda self: True)

    class Completed:
        stdout = "TaskName: \\myav-watch\nTaskName: \\myav-weekly\nTaskName: \\other\n"
        returncode = 0

    monkeypatch.setattr(scheduler.subprocess, "run", lambda *a, **k: Completed())
    result = scheduler.status(windows, tmp_path, "u")
    assert result["installed"] == ["\\myav-watch", "\\myav-weekly"]


def test_status_task_scheduler_oserror(monkeypatch, tmp_path: Path) -> None:
    windows = detect_platform(env={"MYAV_PLATFORM": "windows"})
    monkeypatch.setattr(scheduler.shutil, "which", lambda name: "/fake/schtasks.exe")
    monkeypatch.setattr(scheduler.Path, "exists", lambda self: True)

    def boom(*args, **kwargs):
        raise OSError("no exec")

    monkeypatch.setattr(scheduler.subprocess, "run", boom)
    result = scheduler.status(windows, tmp_path, "u")
    assert result["installed"] == []
    assert "no exec" in result["note"]


def test_status_unknown_scheduler() -> None:
    android = detect_platform(env={"MYAV_PLATFORM": "android"})
    result = scheduler.status(android, Path("/opt/myav"), "u")
    assert result == {"scheduler": android.scheduler, "installed": []}
    assert result["scheduler"] not in {"systemd-user", "launchd", "task-scheduler"}
