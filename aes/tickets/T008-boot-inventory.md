---
ticket: T008
title: Startup inventory + new-entry alerting
sprint: sprint-01
priority: medium
status: pending
created: 2026-11-01
---

# T008 — Startup inventory

## Context

Requirement 6: "List every app that starts on boot, alert me when a new one appears."
In WSL the operator's real startup surface is **Windows**, plus a few Linux autostart files.
Read-only enumeration only.

## Acceptance Criteria

- [ ] Windows: `Win32_StartupCommand` via `powershell.exe -NoProfile -NonInteractive -OutputFormat Text`
  → parsed to `{name, command, location, user}`
- [ ] Windows: `reg query HKCU\...\Run` and `HKLM\...\Run` (+ `RunOnce`, `Wow6432Node`) via `reg.exe`
- [ ] Linux: `~/.config/autostart/*.desktop`, `/etc/xdg/autostart/*.desktop` (Name + Exec)
- [ ] Baseline stored in `state.db` (`boot_entries`, key = normalised name+command hash)
- [ ] First run records a baseline and says so (no alert storm)
- [ ] New entry → `ALERT` line in the report + non-zero `--check` exit (4) for scripting
- [ ] Removed entry → informational only
- [ ] PowerShell output is parsed, never `eval`'d or passed to a shell
- [ ] Works when interop is unavailable → Linux-only mode with `windows: unavailable`
- [ ] Test with fixture JSON/Text output; a real-interop smoke test is tagged `slow`

## Scope
**In:** `src/myav/bootwatch.py`, parsing, tests.
**Out:** disabling entries, registry writes, Windows notifications (Sprint 02).

## Rollback
Delete the `boot_entries` table; no system state.

## Known Risks
- `Win32_StartupCommand` may need WMI service and can be slow (~2 s); cache for 1 h.
- Encoding: PowerShell stdout is UTF-16/codepage-dependent in some setups → force
  `[Console]::OutputEncoding=[Text.Encoding]::UTF8` in the command.
