"""Scheduler integration per platform.

myav needs four recurring jobs:

======================  ======================  ==============================
job                     when                    privilege
======================  ======================  ==============================
start clamd             at boot                 root / system service
update signatures       daily 02:30             root
watch new files         at login, always        user
full scan               Sunday 03:00            user
======================  ======================  ==============================

systemd user units on Linux, launchd agents on macOS, Task Scheduler on Windows and — as on
the reference machine — on WSL, where systemd is not running and ``wsl.exe`` is the only
reliable trigger. Nothing here is applied unless the caller passes ``yes=True``.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .platforms import Platform


@dataclass
class Artifact:
    label: str
    path: Path | None
    content: str
    needs_root: bool = False
    activate: str = ""


def render(
    platform: Platform,
    myav_home: Path,
    user: str,
    distro: str = "Ubuntu",
    binary: Path | None = None,
) -> list[Artifact]:
    # ``binary`` wins when myav was installed with pip (no ../bin/myav beside the package).
    binary = Path(binary) if binary is not None else Path(myav_home) / "bin" / "myav"
    if platform.scheduler == "systemd-user":
        return _systemd(platform, binary)
    if platform.scheduler == "launchd":
        return _launchd(platform, binary)
    if platform.scheduler == "task-scheduler":
        return _task_scheduler(platform, binary, user, distro)
    return []


def _systemd(platform: Platform, binary: Path) -> list[Artifact]:
    user_units = platform.dirs.home / ".config" / "systemd" / "user"
    watch = f"""[Unit]
Description=myav write watcher (Downloads, Desktop, removable volumes)
After=default.target

[Service]
Type=simple
ExecStart={binary} watch
Restart=on-failure
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=default.target
"""
    update_service = f"""[Unit]
Description=myav signature update

[Service]
Type=oneshot
ExecStart={binary} update-signatures
"""
    update_timer = """[Unit]
Description=Daily myav signature update at 02:30

[Timer]
OnCalendar=*-*-* 02:30:00
Persistent=true
RandomizedDelaySec=600

[Install]
WantedBy=timers.target
"""
    scan_service = f"""[Unit]
Description=myav full scan

[Service]
Type=oneshot
ExecStart={binary} full-scan --report
Nice=10
IOSchedulingClass=idle
"""
    scan_timer = """[Unit]
Description=Weekly myav full scan, Sunday 03:00

[Timer]
OnCalendar=Sun *-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
"""
    clamd = """[Unit]
Description=ClamAV daemon for myav
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/clamd --foreground=true
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
    return [
        Artifact(
            "watch service",
            user_units / "myav-watch.service",
            watch,
            activate="systemctl --user daemon-reload && systemctl --user enable --now myav-watch",
        ),
        Artifact("update service", user_units / "myav-update.service", update_service),
        Artifact(
            "update timer",
            user_units / "myav-update.timer",
            update_timer,
            activate="systemctl --user enable --now myav-update.timer",
        ),
        Artifact("scan service", user_units / "myav-scan.service", scan_service),
        Artifact(
            "scan timer",
            user_units / "myav-scan.timer",
            scan_timer,
            activate="systemctl --user enable --now myav-scan.timer",
        ),
        Artifact(
            "clamd unit (system)",
            Path("/etc/systemd/system/myav-clamd.service"),
            clamd,
            needs_root=True,
            activate=(
                "sudo cp myav-clamd.service /etc/systemd/system/ "
                "&& sudo systemctl enable --now myav-clamd"
            ),
        ),
    ]


def _launchd(platform: Platform, binary: Path) -> list[Artifact]:
    agents = platform.dirs.home / "Library" / "LaunchAgents"

    def plist(label: str, args: list[str], extra: str) -> str:
        arg_xml = "".join(f"        <string>{arg}</string>\n" for arg in args)
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
{arg_xml}    </array>
{extra}    <key>StandardOutPath</key>
    <string>{platform.dirs.state / "logs" / (label + ".log")}</string>
    <key>StandardErrorPath</key>
    <string>{platform.dirs.state / "logs" / (label + ".err.log")}</string>
</dict>
</plist>
"""

    watch = plist(
        "dev.myav.watch",
        [str(binary), "watch"],
        "    <key>RunAtLoad</key>\n    <true/>\n    <key>KeepAlive</key>\n    <true/>\n",
    )
    update = plist(
        "dev.myav.update",
        [str(binary), "update-signatures"],
        "    <key>RunAtLoad</key>\n    <false/>\n"
        "    <key>StartCalendarInterval</key>\n    <dict>\n"
        "        <key>Hour</key><integer>2</integer>\n"
        "        <key>Minute</key><integer>30</integer>\n    </dict>\n",
    )
    weekly = plist(
        "dev.myav.weekly",
        [str(binary), "full-scan", "--report"],
        "    <key>StartCalendarInterval</key>\n    <dict>\n"
        "        <key>Weekday</key><integer>0</integer>\n"
        "        <key>Hour</key><integer>3</integer>\n"
        "        <key>Minute</key><integer>0</integer>\n    </dict>\n",
    )
    return [
        Artifact(
            "watch agent",
            agents / "dev.myav.watch.plist",
            watch,
            activate=f"launchctl load -w {agents / 'dev.myav.watch.plist'}",
        ),
        Artifact(
            "update agent",
            agents / "dev.myav.update.plist",
            update,
            activate=f"launchctl load -w {agents / 'dev.myav.update.plist'}",
        ),
        Artifact(
            "weekly agent",
            agents / "dev.myav.weekly.plist",
            weekly,
            activate=f"launchctl load -w {agents / 'dev.myav.weekly.plist'}",
        ),
        Artifact(
            "clamd (Homebrew)",
            None,
            "# ClamAV is installed with Homebrew on macOS and started with:\n"
            "brew install clamav && brew services start clamav\n",
            activate="brew install clamav && brew services start clamav",
        ),
    ]


def _ps_quote(text: str) -> str:
    """Single-quote a value for PowerShell, doubling embedded quotes."""
    return "'" + text.replace("'", "''") + "'"


def _task_scheduler(platform: Platform, binary: Path, user: str, distro: str) -> list[Artifact]:
    # On WSL the trigger must re-enter the Linux distro. On native Windows ``myav`` is a
    # normal executable, so the command is run directly. Mixing the two produces tasks that
    # fail at the first trigger, which is why they are built separately.
    if platform.is_wsl:
        executable = "wsl.exe"
        commands = [
            ("myav-watch", "AtLogOn", f'-d {distro} -u {user} -e "{binary}" watch'),
            (
                "myav-nightly",
                "Daily 02:30",
                f'-d {distro} -u root -e "{binary}" update-signatures',
            ),
            (
                "myav-weekly",
                "Sunday 03:00",
                f'-d {distro} -u {user} -e "{binary}" full-scan --report',
            ),
            ("myav-clamd", "AtLogOn", f'-d {distro} -u root -e "{binary}" clamd-start'),
        ]
    else:
        executable = str(binary)
        commands = [
            ("myav-watch", "AtLogOn", "watch"),
            ("myav-nightly", "Daily 02:30", "update-signatures"),
            ("myav-weekly", "Sunday 03:00", "full-scan --report"),
            ("myav-clamd", "AtLogOn", "clamd-start"),
        ]

    script = [
        "# myav scheduled tasks — review before running.",
        "# Creates four tasks for the CURRENT user. No admin prompt is needed.",
        "# The nightly signature update may require elevation if ClamAV lives under",
        "# Program Files; if so, run that task once as Administrator and check its log.",
        "$ErrorActionPreference = 'Stop'",
        "",
    ]
    for name, when, arguments in commands:
        if "Daily" in when:
            trigger = "New-ScheduledTaskTrigger -Daily -At 02:30"
        elif "Sunday" in when:
            trigger = "New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 03:00"
        else:
            trigger = "New-ScheduledTaskTrigger -AtLogOn"
        script.append(
            f"# {name}: {when}\n"
            f"Register-ScheduledTask -TaskName {_ps_quote(name)} "
            f"-Action (New-ScheduledTaskAction -Execute {_ps_quote(executable)} "
            f"-Argument {_ps_quote(arguments)}) "
            f"-Trigger ({trigger}) "
            f"-Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable "
            f"-MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 8)) "
            f"-Description 'myav local antivirus' -Force | Out-Null\n"
        )
    script.append("Write-Host 'myav tasks registered. Check with: schtasks /Query /TN myav-*'")
    return [
        Artifact(
            "PowerShell installer",
            platform.dirs.state / "schedules" / "install-myav-tasks.ps1",
            "\n".join(script),
            activate="powershell.exe -NoProfile -ExecutionPolicy Bypass -File <path>",
        )
    ]


def install(artifacts: list[Artifact], yes: bool = False) -> list[str]:
    """Write user-level artefacts. Root-level ones are printed, never written."""
    actions: list[str] = []
    for artifact in artifacts:
        if artifact.path is None or artifact.needs_root:
            actions.append(
                f"MANUAL: {artifact.label} → {artifact.activate or 'see printed content'}"
            )
            continue
        if not yes:
            actions.append(f"WOULD WRITE: {artifact.path}")
            continue
        artifact.path.parent.mkdir(parents=True, exist_ok=True)
        artifact.path.write_text(artifact.content, encoding="utf-8")
        actions.append(f"WROTE: {artifact.path}")
    return actions


def status(platform: Platform, myav_home: Path, user: str) -> dict:
    if platform.scheduler == "systemd-user":
        units = platform.dirs.home / ".config" / "systemd" / "user"
        present = sorted(path.name for path in units.glob("myav-*")) if units.is_dir() else []
        return {"scheduler": "systemd-user", "installed": present}
    if platform.scheduler == "launchd":
        agents = platform.dirs.home / "Library" / "LaunchAgents"
        present = sorted(path.name for path in agents.glob("dev.myav.*")) if agents.is_dir() else []
        return {"scheduler": "launchd", "installed": present}
    if platform.scheduler == "task-scheduler":
        schtasks = shutil.which("schtasks.exe") or "/mnt/c/Windows/System32/schtasks.exe"
        if not Path(schtasks).exists():
            return {
                "scheduler": "task-scheduler",
                "installed": [],
                "note": "schtasks not reachable",
            }
        try:
            text = subprocess.run(
                [schtasks, "/Query", "/FO", "LIST"],
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            return {"scheduler": "task-scheduler", "installed": [], "note": str(exc)}
        names = sorted(
            {
                line.split(":", 1)[1].strip()
                for line in text.splitlines()
                if line.startswith("TaskName:") and "myav" in line
            }
        )
        return {"scheduler": "task-scheduler", "installed": names}
    return {"scheduler": platform.scheduler, "installed": []}
