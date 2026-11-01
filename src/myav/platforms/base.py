"""Platform capability model.

myav runs as a full scanner on the four desktop platforms and as a *companion* on mobile.
The difference is not cosmetic: iOS cannot watch another app's files at all, and Android
cannot scan outside scoped storage without a privileged app. Rather than silently degrade,
each platform declares what it can do and the CLI refuses the rest with a clear message.

Nothing in this package imports the rest of myav, so it stays trivially testable.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Capability(str, Enum):
    """What a platform can actually do. The CLI gates commands on these."""

    SCAN_FILES = "scan-files"
    WATCH_FILES = "watch-files"
    DAEMON = "daemon"
    SCHEDULER = "scheduler"
    STARTUP_INVENTORY = "startup-inventory"
    STARTUP_WINDOWS = "startup-windows"
    QUARANTINE = "quarantine"
    SYSTEM_PACKAGES = "system-packages"


@dataclass(frozen=True)
class BaseDirs:
    """Per-platform, app-specific writable locations."""

    home: Path
    config: Path
    state: Path
    data: Path
    cache: Path


@dataclass(frozen=True)
class Platform:
    key: str
    label: str
    family: str  # linux | darwin | windows | mobile
    is_wsl: bool
    capabilities: frozenset[Capability]
    dirs: BaseDirs
    scheduler: str  # systemd-user | launchd | task-scheduler | workmanager | none
    startup_sources: tuple[str, ...]
    notes: str

    def supports(self, capability: Capability) -> bool:
        return capability in self.capabilities

    @property
    def is_desktop(self) -> bool:
        return self.family in {"linux", "darwin", "windows"}

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "family": self.family,
            "is_wsl": self.is_wsl,
            "capabilities": sorted(c.value for c in self.capabilities),
            "scheduler": self.scheduler,
            "startup_sources": list(self.startup_sources),
            "dirs": {
                name: str(getattr(self.dirs, name))
                for name in ("home", "config", "state", "data", "cache")
            },
            "notes": self.notes,
        }


DESKTOP_CAPS = frozenset(
    {
        Capability.SCAN_FILES,
        Capability.WATCH_FILES,
        Capability.DAEMON,
        Capability.SCHEDULER,
        Capability.STARTUP_INVENTORY,
        Capability.QUARANTINE,
        Capability.SYSTEM_PACKAGES,
    }
)

ANDROID_CAPS = frozenset(
    {
        Capability.SCAN_FILES,
        Capability.SCHEDULER,
        Capability.QUARANTINE,
    }
)

IOS_CAPS = frozenset({Capability.SCAN_FILES, Capability.QUARANTINE})


def _home(home: Path | None) -> Path:
    return Path(home) if home is not None else Path.home()


def _xdg(env: dict[str, str], name: str, fallback: Path) -> Path:
    value = env.get(name)
    return Path(value).expanduser() if value else fallback


def _posix_dirs(home: Path, env: dict[str, str]) -> BaseDirs:
    return BaseDirs(
        home=home,
        config=_xdg(env, "XDG_CONFIG_HOME", home / ".config") / "myav",
        state=_xdg(env, "XDG_STATE_HOME", home / ".local" / "state") / "myav",
        data=_xdg(env, "XDG_DATA_HOME", home / ".local" / "share") / "myav",
        cache=_xdg(env, "XDG_CACHE_HOME", home / ".cache") / "myav",
    )


def _macos_dirs(home: Path, env: dict[str, str]) -> BaseDirs:
    return BaseDirs(
        home=home,
        config=_xdg(env, "XDG_CONFIG_HOME", home / ".config") / "myav",
        state=home / "Library" / "Application Support" / "myav",
        data=home / "Library" / "Application Support" / "myav",
        cache=home / "Library" / "Caches" / "myav",
    )


def _windows_dirs(home: Path, env: dict[str, str]) -> BaseDirs:
    appdata = Path(env.get("APPDATA", str(home / "AppData" / "Roaming")))
    local = Path(env.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
    return BaseDirs(
        home=home,
        config=appdata / "myav",
        state=local / "myav" / "state",
        data=local / "myav",
        cache=local / "myav" / "cache",
    )


def _is_wsl(proc_version: str, env: dict[str, str]) -> bool:
    if env.get("WSL_DISTRO_NAME") or env.get("WSL_INTEROP"):
        return True
    return "microsoft" in proc_version.lower() or "wsl" in proc_version.lower()


def detect_platform(
    home: Path | None = None,
    env: dict[str, str] | None = None,
    sys_platform: str | None = None,
    proc_version: str | None = None,
) -> Platform:
    """Detect the running platform. Every input is injectable so tests never guess."""
    env = dict(os.environ if env is None else env)
    sys_platform = sys_platform or sys.platform
    home_path = _home(home)
    forced = env.get("MYAV_PLATFORM", "").lower()

    if proc_version is None:
        try:
            proc_version = Path("/proc/version").read_text(encoding="utf-8", errors="replace")
        except OSError:
            proc_version = ""

    if forced:
        return _forced_platform(forced, home_path, env, sys_platform, proc_version)

    if sys_platform.startswith("win"):
        return Platform(
            key="windows",
            label="Windows",
            family="windows",
            is_wsl=False,
            capabilities=DESKTOP_CAPS,
            dirs=_windows_dirs(home_path, env),
            scheduler="task-scheduler",
            startup_sources=("registry-run", "startup-folder", "scheduled-tasks"),
            notes="ClamAV and YARA ship official Windows builds; watch via ReadDirectoryChangesW.",
        )

    if sys_platform == "darwin":
        return Platform(
            key="macos",
            label="macOS",
            family="darwin",
            is_wsl=False,
            capabilities=DESKTOP_CAPS,
            dirs=_macos_dirs(home_path, env),
            scheduler="launchd",
            startup_sources=("launch-agents", "login-items"),
            notes="ClamAV + YARA via Homebrew; quarantine uses the same verify-then-move protocol.",
        )

    if sys_platform.startswith("linux"):
        if env.get("ANDROID_ROOT") or env.get("ANDROID_DATA"):
            return Platform(
                key="android",
                label="Android (companion)",
                family="mobile",
                is_wsl=False,
                capabilities=ANDROID_CAPS,
                dirs=_posix_dirs(home_path, env),
                scheduler="workmanager",
                startup_sources=(),
                notes="Scans shared storage on demand and on a schedule; no real-time watch "
                "without a privileged/Device Owner app.",
            )
        if _is_wsl(proc_version, env):
            return Platform(
                key="wsl",
                label="WSL2",
                family="linux",
                is_wsl=True,
                capabilities=DESKTOP_CAPS | {Capability.STARTUP_WINDOWS},
                dirs=_posix_dirs(home_path, env),
                scheduler="task-scheduler",
                startup_sources=("registry-run", "startup-folder", "desktop-files"),
                notes="No systemd in this configuration: scheduling is driven from Windows. "
                "Scanning /mnt/c is possible but slow (9p) and off by default.",
            )
        return Platform(
            key="linux",
            label="Linux",
            family="linux",
            is_wsl=False,
            capabilities=DESKTOP_CAPS,
            dirs=_posix_dirs(home_path, env),
            scheduler="systemd-user",
            startup_sources=("desktop-files", "systemd-user-units"),
            notes="Native path: systemd user units for clamd, watcher and the weekly scan.",
        )

    return Platform(
        key="unknown",
        label="Unsupported",
        family="unknown",
        is_wsl=False,
        capabilities=frozenset(),
        dirs=_posix_dirs(home_path, env),
        scheduler="none",
        startup_sources=(),
        notes="No platform adapter: myav refuses to scan rather than pretend.",
    )


def _forced_platform(
    key: str,
    home: Path,
    env: dict[str, str],
    sys_platform: str | None = None,
    proc_version: str | None = None,
) -> Platform:
    """``MYAV_PLATFORM`` override, used by tests and by the companion apps."""
    table = {
        "linux": (
            "Linux",
            "linux",
            "systemd-user",
            ("desktop-files", "systemd-user-units"),
            DESKTOP_CAPS,
            _posix_dirs,
        ),
        "wsl": (
            "WSL2",
            "linux",
            "task-scheduler",
            ("registry-run", "startup-folder"),
            DESKTOP_CAPS | {Capability.STARTUP_WINDOWS},
            _posix_dirs,
        ),
        "macos": ("macOS", "darwin", "launchd", ("launch-agents",), DESKTOP_CAPS, _macos_dirs),
        "windows": (
            "Windows",
            "windows",
            "task-scheduler",
            ("registry-run",),
            DESKTOP_CAPS,
            _windows_dirs,
        ),
        "android": ("Android (companion)", "mobile", "workmanager", (), ANDROID_CAPS, _posix_dirs),
        "ios": ("iOS (companion)", "mobile", "none", (), IOS_CAPS, _posix_dirs),
    }
    if key == "ios":
        return Platform(
            key="ios",
            label="iOS (companion)",
            family="mobile",
            is_wsl=False,
            capabilities=IOS_CAPS,
            dirs=_posix_dirs(home, env),
            scheduler="none",
            startup_sources=(),
            notes="Share-sheet scan of user-picked files only; no background filesystem access.",
        )
    if key not in table:
        return detect_platform(
            home=home,
            env={k: v for k, v in env.items() if k != "MYAV_PLATFORM"},
            sys_platform=sys_platform,
            proc_version=proc_version,
        )
    label, family, scheduler, sources, caps, dirs_fn = table[key]
    return Platform(
        key=key,
        label=label,
        family=family,
        is_wsl=key == "wsl",
        capabilities=frozenset(caps),
        dirs=dirs_fn(home, env),
        scheduler=scheduler,
        startup_sources=tuple(sources),
        notes="forced via MYAV_PLATFORM",
    )
