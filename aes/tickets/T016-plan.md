---
ticket: T016
title: Quarantine size budget & rotation
sprint: sprint-02
priority: medium
status: done
created: 2026-11-03
---

# T016 — Quarantine size budget & rotation

## Context

Quarantine grows indefinitely as files are moved in. Without a budget, it can fill the disk.
T016 adds a configurable size budget for quarantine and a rotation mechanism: when the budget
is exceeded, the oldest entries are purged (oldest first, never the newest). The operator can
check the budget with `myav quarantine budget` and enforce it with `myav quarantine rotate`.

## Acceptance Criteria

- [ ] `ReportConfig.quarantine_budget_bytes` added (default: None = no budget)
- [ ] Config section `[quarantine]` with `budget_bytes` supported in config.toml
- [ ] `State.quarantine_total_size()` returns the sum of all payload sizes in bytes
- [ ] `Quarantine.rotate()` purges oldest entries until under budget, returns count purged
- [ ] `myav quarantine budget` shows current size, budget, and usage %
- [ ] `myav quarantine budget --set N` sets the budget (bytes)
- [ ] `myav quarantine rotate` enforces the budget, prints how many were purged
- [ ] Report's "What is quarantined" section shows size vs budget when budget is set
- [ ] Tests cover: budget get/set, rotate purges oldest first, rotate no-op when under budget
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/config.py` (budget_bytes), `src/myav/state.py` (quarantine_total_size),
`src/myav/quarantine.py` (rotate), `src/myav/cli.py` (budget/rotate actions), `src/myav/report.py`
(budget line), tests.

**Out:** automatic rotation on every quarantine (that's a scheduler integration), size-based
purge of specific entries.

## Rollback

Git revert.
