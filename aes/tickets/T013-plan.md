---
ticket: T013
title: Baseline scan of pre-existing files
sprint: sprint-02
priority: high
status: done
created: 2026-11-03
---

# T013 — Baseline scan of pre-existing files

## Context

When myav is first installed, there are already many pre-existing files on the machine
(Downloads, Desktop, Documents, home directory). The watcher only catches *new* files;
`full-scan` scans on demand but there is no concept of a "baseline" — the operator cannot
tell what was already on the machine before myav was installed versus what arrived later.

T013 adds a `myav baseline` command that performs a full scan of the default scope and
records it as kind="baseline" in the state DB, plus a meta key `baseline_established_at`
so the operator knows when the baseline was taken. Future scans can reference it.

## Acceptance Criteria

- [ ] `myav baseline` scans the default scope (watch dirs + removable mounts) and records
      results as kind="baseline"
- [ ] Sets meta key `baseline_established_at` in state DB after a successful baseline
- [ ] `myav baseline --json` outputs structured results (exit code follows worst verdict)
- [ ] A plain-English report is written for the baseline scan
- [ ] `myav doctor` reports whether a baseline exists and when it was established
- [ ] Tests cover: baseline command, baseline report, baseline meta tracking, doctor
      baseline status
- [ ] Coverage ≥ 80%, lint clean (`ruff check src tests`)

## Scope

**In:** `src/myav/cli.py` (baseline command), `src/myav/pipeline.py` (baseline kind),
`src/myav/state.py` (baseline meta helpers), tests.

**Out:** Cross-platform baseline (Linux/WSL first), comparing future scans against baseline
to detect new files (that is T014-adjacent), automatic baseline on first run.

## Rollback

Git revert.

## Known Risks

- A baseline over a large home directory can be slow (same caveat as full-scan).
- The baseline is a point-in-time snapshot; files change between baseline and the next scan.
