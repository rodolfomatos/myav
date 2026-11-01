"""Startup inventory: what runs when the machine boots.

Read-only by design. myav reports a new startup entry; it never disables one and never
writes to the Windows registry. On WSL the interesting surface is Windows, so both the
CIM list and the registry Run keys are read through ``powershell.exe``/``reg.exe``.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from .platforms import Platform
from .state import BootEntry

POWERSHELL_CMD = (
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
    "Get-CimInstance Win32_StartupCommand | "
    "Select-Object Name,Command,Location,User | ConvertTo-Json -Compress"
)
REGISTRY_KEYS = (
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
)


def entry_key(name: str, command: str) -> str:
    return hashlib.sha256(f"{name.strip().lower()}|{command.strip()}".encode()).hexdigest()[:16]


def _run(argv: list[str], timeout: int = 30) -> str:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout or ""


def find_windows_binaries() -> dict[str, str | None]:
    return {
        "powershell": shutil.which("powershell.exe")
        or (
            "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"
            if Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe").exists()
            else None
        ),
        "reg": shutil.which("reg.exe")
        or (
            "/mnt/c/Windows/System32/reg.exe"
            if Path("/mnt/c/Windows/System32/reg.exe").exists()
            else None
        ),
    }


def parse_cim_json(text: str) -> list[BootEntry]:
    if not text.strip():
        return []
    try:
        payload = json.loads(text)
    except ValueError:
        return []
    if isinstance(payload, dict):
        payload = [payload]
    entries: list[BootEntry] = []
    for item in payload:
        name = str(item.get("Name") or "").strip()
        command = str(item.get("Command") or "").strip()
        location = str(item.get("Location") or "").strip()
        if not name and not command:
            continue
        entries.append(
            BootEntry(
                key=entry_key(name, command),
                name=name or command,
                command=command,
                location=location,
            )
        )
    return entries


def parse_reg_output(text: str, key: str) -> list[BootEntry]:
    entries: list[BootEntry] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line.startswith("    ") or "REG_" not in line:
            continue
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        name, _kind, command = parts
        if not name:
            continue
        entries.append(
            BootEntry(key=entry_key(name, command), name=name, command=command, location=key)
        )
    return entries


def parse_desktop_file(path: Path) -> BootEntry | None:
    name = ""
    command = ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    in_entry = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_entry = line == "[Desktop Entry]"
            continue
        if not in_entry or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key == "Name" and not name:
            name = value.strip()
        elif key == "Exec" and not command:
            command = value.strip()
        elif key == "Hidden" and value.strip().lower() == "true":
            return None
    if not name and not command:
        return None
    return BootEntry(
        key=entry_key(name, command),
        name=name or command,
        command=command,
        location=str(path),
    )


def linux_autostart(home: Path | None = None) -> list[BootEntry]:
    home = home or Path.home()
    entries: list[BootEntry] = []
    for directory in (home / ".config" / "autostart", Path("/etc/xdg/autostart")):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.desktop")):
            entry = parse_desktop_file(path)
            if entry:
                entries.append(entry)
    return entries


def collect(platform: Platform, home: Path | None = None) -> tuple[list[BootEntry], list[str]]:
    """Return (entries, notes). Notes explain what could not be read."""
    notes: list[str] = []
    entries: list[BootEntry] = []

    if platform.family == "windows" or platform.is_wsl:
        binaries = find_windows_binaries()
        powershell = binaries["powershell"]
        if powershell:
            text = _run([powershell, "-NoProfile", "-NonInteractive", "-Command", POWERSHELL_CMD])
            entries.extend(parse_cim_json(text))
            if not text.strip():
                notes.append("PowerShell returned no startup data")
        else:
            notes.append("PowerShell not reachable — Windows startup entries unavailable")

        reg = binaries["reg"]
        if reg:
            for key in REGISTRY_KEYS:
                text = _run([reg, "query", key])
                if text:
                    entries.extend(parse_reg_output(text, key))
        else:
            notes.append("reg.exe not reachable — registry Run keys unavailable")

    if platform.family in {"linux", "darwin"} or platform.is_wsl:
        entries.extend(linux_autostart(home))
        if platform.family == "darwin":
            notes.append("macOS login items require Full Disk Access; only LaunchAgents are listed")

    # Deduplicate by key, keeping the first location.
    seen: set[str] = set()
    unique: list[BootEntry] = []
    for entry in entries:
        if entry.key in seen:
            continue
        seen.add(entry.key)
        unique.append(entry)
    return unique, notes


def check(state, platform: Platform, home: Path | None = None) -> dict:
    entries, notes = collect(platform, home)
    first_run = state.boot_run_count() == 0
    new, removed = state.boot_apply(entries)
    return {
        "entries": len(entries),
        "new": [entry.__dict__ for entry in new],
        "removed": [entry.__dict__ for entry in removed],
        "first_run": first_run,
        "notes": notes,
        "baseline": state.boot_snapshot() if not notes else state.boot_snapshot(),
    }
