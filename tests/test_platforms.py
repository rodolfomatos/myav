from __future__ import annotations

from pathlib import Path

from myav.platforms import (
    ANDROID_CAPS,
    DESKTOP_CAPS,
    IOS_CAPS,
    Capability,
    detect_platform,
)


def test_detect_windows(tmp_path: Path) -> None:
    platform = detect_platform(
        home=tmp_path,
        env={"APPDATA": str(tmp_path / "roaming"), "LOCALAPPDATA": str(tmp_path / "local")},
        sys_platform="win32",
        proc_version="",
    )
    assert platform.key == "windows"
    assert platform.family == "windows"
    assert platform.scheduler == "task-scheduler"
    assert platform.dirs.config == tmp_path / "roaming" / "myav"
    assert platform.dirs.state == tmp_path / "local" / "myav" / "state"
    assert platform.supports(Capability.WATCH_FILES)


def test_detect_macos(tmp_path: Path) -> None:
    platform = detect_platform(home=tmp_path, env={}, sys_platform="darwin", proc_version="")
    assert platform.key == "macos"
    assert platform.scheduler == "launchd"
    assert platform.dirs.state == tmp_path / "Library" / "Application Support" / "myav"
    assert "launch-agents" in platform.startup_sources


def test_detect_linux(tmp_path: Path) -> None:
    platform = detect_platform(
        home=tmp_path, env={}, sys_platform="linux", proc_version="Linux 6.5"
    )
    assert platform.key == "linux"
    assert platform.scheduler == "systemd-user"
    assert not platform.is_wsl


def test_detect_wsl_by_proc_version(tmp_path: Path) -> None:
    platform = detect_platform(
        home=tmp_path, env={}, sys_platform="linux", proc_version="6.6 microsoft-standard-WSL2"
    )
    assert platform.key == "wsl"
    assert platform.is_wsl
    assert platform.scheduler == "task-scheduler"
    assert platform.supports(Capability.STARTUP_WINDOWS)


def test_detect_wsl_by_env(tmp_path: Path) -> None:
    platform = detect_platform(
        home=tmp_path,
        env={"WSL_DISTRO_NAME": "Ubuntu"},
        sys_platform="linux",
        proc_version="",
    )
    assert platform.key == "wsl"


def test_detect_android(tmp_path: Path) -> None:
    platform = detect_platform(
        home=tmp_path, env={"ANDROID_ROOT": "/system"}, sys_platform="linux", proc_version=""
    )
    assert platform.key == "android"
    assert platform.family == "mobile"
    assert platform.capabilities == ANDROID_CAPS
    assert platform.scheduler == "workmanager"


def test_detect_unknown(tmp_path: Path) -> None:
    platform = detect_platform(home=tmp_path, env={}, sys_platform="haiku", proc_version="")
    assert platform.key == "unknown"
    assert not platform.is_desktop
    assert platform.capabilities == frozenset()
    assert platform.scheduler == "none"


def test_forced_platforms(tmp_path: Path) -> None:
    expectations = {
        "linux": ("linux", "systemd-user"),
        "wsl": ("linux", "task-scheduler"),
        "macos": ("darwin", "launchd"),
        "windows": ("windows", "task-scheduler"),
        "android": ("mobile", "workmanager"),
        "ios": ("mobile", "none"),
    }
    for key, (family, scheduler) in expectations.items():
        platform = detect_platform(home=tmp_path, env={"MYAV_PLATFORM": key})
        assert platform.key == key
        assert platform.family == family
        assert platform.scheduler == scheduler
        if key != "ios":
            assert "forced" in platform.notes


def test_ios_has_only_scan_and_quarantine(tmp_path: Path) -> None:
    platform = detect_platform(home=tmp_path, env={"MYAV_PLATFORM": "ios"})
    assert platform.capabilities == IOS_CAPS
    assert not platform.supports(Capability.WATCH_FILES)


def test_forced_unknown_key_falls_back_to_detection(tmp_path: Path) -> None:
    platform = detect_platform(
        home=tmp_path,
        env={"MYAV_PLATFORM": "toaster"},
        sys_platform="linux",
        proc_version="Linux",
    )
    assert platform.key == "linux"


def test_desktop_capabilities_include_daemon_and_scheduler() -> None:
    assert Capability.DAEMON in DESKTOP_CAPS
    assert Capability.SCHEDULER in DESKTOP_CAPS
    assert Capability.WATCH_FILES in DESKTOP_CAPS


def test_as_dict_is_json_shaped(tmp_path: Path) -> None:
    payload = detect_platform(home=tmp_path, env={"MYAV_PLATFORM": "linux"}).as_dict()
    assert payload["key"] == "linux"
    assert isinstance(payload["capabilities"], list)
    assert set(payload["dirs"]) == {"home", "config", "state", "data", "cache"}
