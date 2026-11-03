---
ticket: T015
title: Windows toast notification for alerts
sprint: sprint-02
priority: medium
status: done
created: 2026-11-03
---

# T015 — Windows toast notification for alerts

## Context

When myav finds a MALICIOUS or SUSPICIOUS file, or a new startup entry, the operator should be
alerted. On Windows, a toast notification is the natural surface. On Linux/WSL/macOS the
command is not applicable and must exit 3 with a clear message (platform capability model).

T015 adds `Capability.TOAST`, includes it in the Windows desktop capabilities, and adds a
`myav notify <title> <message>` command gated on that capability. The actual Windows toast is
rendered via PowerShell (BurntToast-style) but the command is structured so it can be tested
without a Windows machine.

## Acceptance Criteria

- [ ] `Capability.TOAST` added to the Capability enum
- [ ] Windows platform adapter includes `TOAST`
- [ ] `myav notify <title> <message>` added to the CLI, gated on `Capability.TOAST`
- [ ] `myav notify` exits 3 on non-Windows platforms with a clear message
- [ ] `myav notify --json` outputs structured result
- [ ] Tests cover: Windows path (forced platform), non-Windows rejection, JSON output
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/platforms/base.py` (TOAST capability), `src/myav/cli.py` (notify command),
tests.

**Out:** actual PowerShell toast rendering (requires Windows), notification on scan/watcher
events (wired later), Linux/macOS notification adapters.

## Rollback

Git revert.
