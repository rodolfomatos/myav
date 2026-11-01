"""Configuration loading for myav.

The config file is TOML at ``~/.config/myav/config.toml``. If it contains a VirusTotal
API key it must be ``0600``; anything looser is a hard error rather than a warning,
because the key is the only secret this tool holds.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .paths import Paths, default_paths

if sys.version_info >= (3, 11):  # pragma: no cover - exercised on 3.11+, we run 3.10
    import tomllib as _toml
else:  # pragma: no cover - the branch under test
    import tomli as _toml

MIB = 1024 * 1024

# POSIX mode bits are meaningless on Windows, where access is controlled by NTFS ACLs and
# ``os.chmod`` cannot express "owner only". Treating a Windows file as "0644" would make
# every existing config unreadable, so the mode check is POSIX-only. The config still lives
# inside the per-user ``%APPDATA%`` profile, which Windows protects with user ACLs.
ENFORCE_POSIX_MODES = os.name != "nt"


class ConfigError(RuntimeError):
    """Invalid or unsafe configuration."""


@dataclass
class ClamAVConfig:
    prefer_daemon: bool = True
    tcp_host: str = "127.0.0.1"
    tcp_port: int = 3310
    local_socket: str = "/run/clamav/clamd.ctl"
    timeout: int = 60


@dataclass
class YaraConfig:
    timeout: int = 30
    max_scan_bytes: int = 100 * MIB
    malicious_severity: int = 7
    suspicious_severity: int = 4


@dataclass
class VirusTotalConfig:
    enabled: bool = False
    api_key: str = ""
    requests_per_minute: int = 4
    requests_per_day: int = 500
    ttl_positive_seconds: int = 7 * 24 * 3600
    ttl_negative_seconds: int = 24 * 3600
    timeout: int = 15


@dataclass
class WatcherConfig:
    watch_dirs: list[Path] = field(default_factory=list)
    watch_removable: bool = True
    settle_seconds: float = 2.0
    workers: int = 2
    queue_size: int = 256


@dataclass
class ScanConfig:
    timeout: int = 60
    follow_symlinks: bool = False
    skip_hidden: bool = False


@dataclass
class ReportConfig:
    retention: int = 90


@dataclass
class Config:
    paths: Paths = field(default_factory=default_paths)
    clamav: ClamAVConfig = field(default_factory=ClamAVConfig)
    yara: YaraConfig = field(default_factory=YaraConfig)
    virustotal: VirusTotalConfig = field(default_factory=VirusTotalConfig)
    watcher: WatcherConfig = field(default_factory=WatcherConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    warnings: list[str] = field(default_factory=list)

    # ---------------------------------------------------------------- loading

    @classmethod
    def load(cls, path: Path | None = None, home: Path | None = None) -> Config:
        paths = default_paths(home)
        config = cls(paths=paths)
        config.watcher.watch_dirs = [
            paths.home / "Downloads",
            paths.home / "Desktop",
            paths.home / "Documents",
        ]
        target = Path(path) if path is not None else paths.config_file
        if not target.exists():
            return config

        _check_permissions(target)
        try:
            raw = _toml.loads(target.read_text(encoding="utf-8"))
        except _toml.TOMLDecodeError as exc:
            raise ConfigError(f"{target}: invalid TOML: {exc}") from exc
        return config.with_overrides(raw)

    def with_overrides(self, raw: dict[str, Any]) -> Config:
        """Return a copy with values from a parsed TOML mapping applied."""
        warnings = list(self.warnings)
        updated = replace(self)

        clamav = replace(updated.clamav)
        for key, caster in (
            ("prefer_daemon", bool),
            ("tcp_host", str),
            ("tcp_port", int),
            ("local_socket", str),
            ("timeout", int),
        ):
            value = _get(raw, "clamav", key)
            if value is not None:
                setattr(clamav, key, caster(value))
        updated.clamav = clamav

        yara = replace(updated.yara)
        for key, caster in (
            ("timeout", int),
            ("max_scan_bytes", int),
            ("malicious_severity", int),
            ("suspicious_severity", int),
        ):
            value = _get(raw, "yara", key)
            if value is not None:
                setattr(yara, key, caster(value))
        updated.yara = yara

        vt = replace(updated.virustotal)
        for key, caster in (
            ("enabled", bool),
            ("api_key", str),
            ("requests_per_minute", int),
            ("requests_per_day", int),
            ("ttl_positive_seconds", int),
            ("ttl_negative_seconds", int),
            ("timeout", int),
        ):
            value = _get(raw, "virustotal", key)
            if value is not None:
                setattr(vt, key, caster(value))
        if bool(vt.api_key) != vt.enabled:
            # An empty key cannot enable the engine; a key with enabled=false stays off.
            vt.enabled = bool(vt.api_key) and vt.enabled
        updated.virustotal = vt

        watcher = replace(updated.watcher)
        dirs = _get(raw, "watcher", "watch_dirs")
        if dirs is not None:
            watcher.watch_dirs = [_expand_dir(d, updated.paths.home) for d in dirs]
        for key, caster in (
            ("watch_removable", bool),
            ("settle_seconds", float),
            ("workers", int),
            ("queue_size", int),
        ):
            value = _get(raw, "watcher", key)
            if value is not None:
                setattr(watcher, key, caster(value))
        updated.watcher = watcher

        scan = replace(updated.scan)
        for key, caster in (
            ("timeout", int),
            ("follow_symlinks", bool),
            ("skip_hidden", bool),
        ):
            value = _get(raw, "scan", key)
            if value is not None:
                setattr(scan, key, caster(value))
        updated.scan = scan

        report = replace(updated.report)
        value = _get(raw, "report", "retention")
        if value is not None:
            report.retention = int(value)
        updated.report = report

        updated.warnings = warnings + unknown_sections(raw)
        updated.validate()
        return updated

    def validate(self) -> None:
        if self.yara.suspicious_severity > self.yara.malicious_severity:
            raise ConfigError("yara.suspicious_severity must be <= yara.malicious_severity")
        if self.watcher.settle_seconds < 0:
            raise ConfigError("watcher.settle_seconds must be >= 0")
        if self.watcher.workers < 1:
            raise ConfigError("watcher.workers must be >= 1")
        if self.report.retention < 1:
            raise ConfigError("report.retention must be >= 1")
        for directory in self.watcher.watch_dirs:
            if not directory.is_absolute():
                raise ConfigError(f"watcher.watch_dirs must be absolute: {directory}")

    # ---------------------------------------------------------------- output

    def public_dict(self, redact: bool = True) -> dict[str, Any]:
        key = self.virustotal.api_key
        if redact and key:
            key = key[:4] + "…" + key[-2:] if len(key) > 8 else "***"
        return {
            "paths": {
                "config_dir": str(self.paths.config_dir),
                "state_dir": str(self.paths.state_dir),
                "data_dir": str(self.paths.data_dir),
                "quarantine_dir": str(self.paths.quarantine_dir),
            },
            "clamav": vars(self.clamav),
            "yara": vars(self.yara),
            "virustotal": {
                **vars(self.virustotal),
                "api_key": key,
                "configured": bool(self.virustotal.api_key),
            },
            "watcher": {
                **vars(self.watcher),
                "watch_dirs": [str(p) for p in self.watcher.watch_dirs],
            },
            "scan": vars(self.scan),
            "report": vars(self.report),
            "warnings": self.warnings,
        }


def _expand_dir(value: Any, home: Path) -> Path:
    """Expand ``~`` against *myav's* home, not the process's (services differ)."""
    text = str(value)
    if text == "~":
        return home
    if text.startswith("~/"):
        return home / text[2:]
    return Path(os.path.expanduser(text))


def _get(raw: dict[str, Any], section: str, key: str) -> Any:
    table = raw.get(section, {})
    if not isinstance(table, dict):
        raise ConfigError(f"[{section}] must be a table")
    return table.get(key)


def unknown_sections(raw: dict[str, Any]) -> list[str]:
    known = {"clamav", "yara", "virustotal", "watcher", "scan", "report"}
    return [f"unknown config section [{name}] ignored" for name in raw if name not in known]


def _check_permissions(path: Path) -> None:
    if not ENFORCE_POSIX_MODES:
        return
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise ConfigError(
            f"{path} is mode {mode:04o}; myav requires 0600 because it may hold the "
            f"VirusTotal API key. Fix with: chmod 600 {path}"
        )


def write_api_key(paths: Paths, key: str) -> Path:
    """Persist the VT key with 0600 from the first byte (no chmod-after-write race)."""
    paths.config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = paths.config_file
    existing = ""
    if target.exists():
        existing = target.read_text(encoding="utf-8")
        if ENFORCE_POSIX_MODES:
            mode = target.stat().st_mode & 0o777
            if mode & 0o077:
                raise ConfigError(f"{target} is mode {mode:04o}; chmod 600 it first")
    if "[virustotal]" in existing:
        content = _set_vt_section(existing, key)
    else:
        content = existing.rstrip("\n") + f'\n\n[virustotal]\nenabled = true\napi_key = "{key}"\n'
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    if ENFORCE_POSIX_MODES:
        os.chmod(target, 0o600)
    return target


def _set_vt_section(existing: str, key: str) -> str:
    """Replace or insert ``enabled``/``api_key`` *inside* the existing ``[virustotal]``."""
    out: list[str] = []
    in_vt = False
    saw_key = False
    saw_enabled = False

    def close_section() -> None:
        nonlocal saw_key, saw_enabled
        if in_vt:
            if not saw_enabled:
                out.append("enabled = true")
            if not saw_key:
                out.append(f'api_key = "{key}"')
        saw_key = saw_enabled = False

    for line in existing.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            close_section()
            in_vt = stripped == "[virustotal]"
            out.append(line)
            continue
        if in_vt and stripped.startswith("api_key"):
            out.append(f'api_key = "{key}"')
            saw_key = True
        elif in_vt and stripped.startswith("enabled"):
            out.append("enabled = true")
            saw_enabled = True
        else:
            out.append(line)
    close_section()
    return "\n".join(out) + "\n"
