---
ticket: T024
title: Per-file progress line for long full scans
sprint: Sprint 04
priority: medium
status: done
created: 2026-11-03
---

# T024 — Per-file progress line for long full scans

## Context

A full scan of a large home directory can take a long time (PROJECT_STATUS.md §4.4).
The operator has no visibility into progress: how many files scanned, how many remain,
which file is currently being scanned, and estimated time remaining. T024 adds a
per-file progress line to `myav full-scan` and `myav watch` so the operator can see
the scan advancing in real time.

## Acceptance Criteria

- [ ] `myav full-scan` prints a progress line: `scanned N / M files (P%) — current file`
- [ ] Progress line updates on every scanned file (stdout, not a report)
- [ ] `--json` mode suppresses the progress line (machine-readable output only)
- [ ] `--quiet` mode suppresses the progress line
- [ ] Progress also available for `myav watch --once` (baseline of existing files)
- [ ] Tests cover: progress text on full-scan, suppressed with --json, suppressed with --quiet
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/cli.py` (progress in cmd_full_scan and cmd_watch), `src/myav/pipeline.py`
(optional progress callback), tests.

**Out:** ETA estimation, progress bar UI library, progress for `myav scan` (manual).

## Rollback

Git revert.
