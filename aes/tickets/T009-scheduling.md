---
ticket: T009
title: Scheduling via Windows Task Scheduler (systemd is offline)
sprint: sprint-01
priority: high
status: pending
created: 2026-11-01
---

# T009 — Scheduler integration

## Context

Verified on this machine: `systemctl is-system-running` → `offline`, `service cron status` → not
running. There is no in-distro scheduler. Windows Task Scheduler can launch
`wsl.exe -d Ubuntu -u <user>` and this starts the distro if it is down.

## Acceptance Criteria

- [ ] `scripts/schedule-install.sh --dry-run` prints the four tasks and their commands, changes nothing
- [ ] `--apply` (operator-run) creates them with `schtasks.exe /Create /F`
- [ ] Tasks: `myav-clamd` (logon, root), `myav-watch` (logon, user), `myav-nightly` (02:30, root),
  `myav-weekly` (Sunday 03:00, user)
- [ ] Missed-run catch-up enabled (`/RI` not used; use Task Scheduler XML for
  `StartWhenAvailable=true`)
- [ ] `myav doctor --only schedule` reads `schtasks /Query /XML` and prints next-run + last result
- [ ] Detects and reports a task that exists but is **Disabled**
- [ ] `scripts/schedule-uninstall.sh` removes only the four `myav-*` tasks
- [ ] No `sudoers` entry, no systemd unit, no `/etc/cron*` file is ever created
- [ ] Power: `myav-weekly` documented as requiring the machine awake at 03:00;
  `StartWhenAvailable` covers sleep, not power-off
- [ ] Idempotent: re-running `--apply` updates in place

## Scope
**In:** `scripts/schedule-{install,uninstall}.sh`, Task Scheduler XML templates, `doctor` checks.
**Out:** enabling systemd, editing `/etc/wsl.conf`, modifying existing non-`myav-*` tasks.

## Rollback
`scripts/schedule-uninstall.sh` (or `schtasks /Delete /TN myav-*`). No other state.

## Known Risks
- Task Scheduler running `wsl.exe` in a non-interactive session: `-u root` avoids the Windows UAC
  prompt, but the distro must be registered (`wsl -l -v` → `Ubuntu`).
- If the Windows user logs out, logon tasks do not run; weekly still fires.
- Creating scheduled tasks is a **system setting** → requires explicit operator approval.
