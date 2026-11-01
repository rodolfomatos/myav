"""Filesystem layout for myav, plus the mount rules that define scan scope.

Layout comes from the platform adapter (XDG on Linux/WSL, Application Support on macOS,
LOCALAPPDATA on Windows). Two invariants live here:

1. Quarantine, logs, reports, caches and the state DB are always owner-only (``0700``).
2. On WSL, nothing is ever written under ``/mnt/c`` — the reference machine had 3.8 GiB
   free on ``C:`` when the project was created.

"USB drive" in WSL means *a mount under /mnt that is not the C: drive and not a WSL
internal mount*. WSL exposes no udev/udisks, so a USB stick and a second internal volume
are indistinguishable. Native Linux uses /media and /run/media.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .platforms import Platform, detect_platform

MOUNT_ROOT = Path("/mnt")
WINDOWS_DRIVE = "c"
IGNORED_MOUNT_NAMES = {"wsl", "wslg", "host", "wslg-distro"}
# Native-Linux removable mount points (absent in WSL; kept for portability).
PORTABLE_MOUNT_ROOTS = (Path("/media"), Path("/run/media"))


class UnsafeLocationError(RuntimeError):
    """Raised when something tries to write to a location myav must never write to."""


@dataclass(frozen=True)
class Paths:
    """Every directory myav touches, resolved once."""

    config_dir: Path
    state_dir: Path
    data_dir: Path
    cache_dir: Path
    home: Path

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def reports_dir(self) -> Path:
        return self.state_dir / "reports"

    @property
    def logs_dir(self) -> Path:
        return self.state_dir / "logs"

    @property
    def state_db(self) -> Path:
        return self.state_dir / "state.db"

    @property
    def rules_dir(self) -> Path:
        return self.data_dir / "rules"

    @property
    def yara_cache(self) -> Path:
        return self.cache_dir / "yara-rules.yarc"

    def all_dirs(self) -> tuple[Path, ...]:
        return (
            self.config_dir,
            self.state_dir,
            self.data_dir,
            self.cache_dir,
            self.quarantine_dir,
            self.reports_dir,
            self.logs_dir,
        )


def default_paths(home: Path | None = None, platform: Platform | None = None) -> Paths:
    """Resolve the platform layout. ``home`` is injectable for tests."""
    plat = platform or detect_platform(home=home)
    dirs = plat.dirs
    return Paths(
        config_dir=dirs.config,
        state_dir=dirs.state,
        data_dir=dirs.data,
        cache_dir=dirs.cache,
        home=dirs.home,
    )


def is_within(path: Path, root: Path) -> bool:
    """True when ``path`` is ``root`` or lives below it (symlinks resolved)."""
    try:
        Path(os.path.realpath(path)).relative_to(Path(os.path.realpath(root)))
        return True
    except ValueError:
        return False


def is_windows_path(path: Path | str) -> bool:
    """True for anything under /mnt/c — write-forbidden territory on WSL."""
    return is_within(Path(path), MOUNT_ROOT / WINDOWS_DRIVE)


def assert_writable_location(path: Path) -> Path:
    """Guard every write with this. Raises instead of filling the Windows disk."""
    if is_windows_path(path):
        raise UnsafeLocationError(
            f"refusing to write under {MOUNT_ROOT / WINDOWS_DRIVE}: {path} "
            "(C: was 100% full when myav was built)"
        )
    return Path(path)


def ensure_dirs(paths: Paths, mode: int = 0o700) -> None:
    """Create every myav directory with owner-only permissions."""
    for directory in paths.all_dirs():
        assert_writable_location(directory)
        directory.mkdir(parents=True, exist_ok=True, mode=mode)
        os.chmod(directory, mode)


def _parse_mounts_line(line: str) -> tuple[str, str, str] | None:
    parts = line.split()
    if len(parts) < 3:
        return None
    source, target, fstype = parts[0], parts[1], parts[2]
    target = target.replace("\\040", " ").replace("\\011", "\t")
    return source, target, fstype


def read_mounts(mounts_file: Path | str = "/proc/mounts") -> list[tuple[str, str, str]]:
    try:
        text = Path(mounts_file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    parsed = (_parse_mounts_line(line) for line in text.splitlines())
    return [entry for entry in parsed if entry is not None]


def classify_mount(target: str) -> str:
    """Classify a mount point as ``windows``, ``usb``, ``portable`` or ``ignore``."""
    path = Path(target)
    if path == MOUNT_ROOT / WINDOWS_DRIVE or is_within(path, MOUNT_ROOT / WINDOWS_DRIVE):
        return "windows"
    if is_within(path, MOUNT_ROOT):
        relative = Path(os.path.realpath(path)).relative_to(Path(os.path.realpath(MOUNT_ROOT)))
        first = relative.parts[0] if relative.parts else ""
        if not first or first.lower() in IGNORED_MOUNT_NAMES:
            return "ignore"
        return "usb"
    for root in PORTABLE_MOUNT_ROOTS:
        if is_within(path, root):
            return "portable"
    return "ignore"


def discover_removable_mounts(mounts_file: Path | str = "/proc/mounts") -> list[Path]:
    """Mount points the watcher and the full scan treat as removable media."""
    seen: set[Path] = set()
    result: list[Path] = []
    for _source, target, _fstype in read_mounts(mounts_file):
        if classify_mount(target) not in {"usb", "portable"}:
            continue
        path = Path(target)
        if path in seen or not path.exists():
            continue
        seen.add(path)
        result.append(path)
    return result
