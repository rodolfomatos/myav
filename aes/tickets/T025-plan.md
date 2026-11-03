---
ticket: T025
title: Visual progress bar for long full scans
sprint: Sprint 04
priority: medium
status: done
created: 2026-11-03
---

# T025 — Visual progress bar for long full scans

## Context

T024 added a plain `[progress] N/M (P%)` line to stderr. For long full scans over a
large home directory, a visual bar (`████████░░░░ 50%`) gives the operator immediate
feedback without counting digits. T025 replaces the text line with a real progress bar
that only renders on a TTY (silent when piped to a file, in --json, or --quiet).

## Acceptance Criteria

- [ ] `myav full-scan` renders a visual bar on TTY: `████████░░░░ 50% (5/10 files/s)`
- [ ] Bar respects terminal width; falls back gracefully on narrow/unknown widths
- [ ] Non-TTY (piped, redirected): no bar emitted (keeps stderr clean for logs)
- [ ] `--json` and `--quiet` suppress the bar
- [ ] Shows rate (files/sec) and elapsed time alongside the bar
- [ ] Tests cover: bar text on TTY, no bar when not TTY, suppressed with --json/--quiet
- [ ] No new runtime dependencies (pure stdlib)
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/cli.py` (progress bar in cmd_full_scan), `src/myav/progress.py` (new
helper module), tests.

**Out:** ETA estimation, progress for `myav watch`, tqdm/rich integration.

## Rollback

Git revert.
