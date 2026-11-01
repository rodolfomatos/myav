---
ticket: T012
title: Operator runbook + final docs
sprint: sprint-01
priority: medium
status: pending
created: 2026-11-01
---

# T012 — Runbook

## Context

Every privileged or surprising step must be explicable **before** it runs. This ticket produces the
document the operator follows, and reconciles docs with what was actually built.

## Acceptance Criteria

- [ ] `docs/RUNBOOK.md`: install → configure VT key → fetch rules → schedule → verify, each step with
  *what it does*, *what it changes*, *how to undo it*, and the exact command
- [ ] `docs/OPERATIONS.md`: daily/weekly behaviour, what a report looks like, how to restore,
  how to allow a false positive, how to read a degraded state
- [ ] Every command listed in the runbook is copy-paste tested (scripted check)
- [ ] `docs/ARCHITECTURE.md` updated to match the final module tree
- [ ] `CLAUDE.md` environment facts re-verified and re-dated
- [ ] README with a 5-line quickstart and an explicit "what this does not protect" section
- [ ] `aes/handoffs/` entry for the next session

## Scope
**In:** docs, README, handoff.
**Out:** marketing, screenshots.

## Rollback
Git revert.

## Known Risks
- Docs drift is the default outcome. The runbook's commands are executed by `make docs-runbook-check`
  so drift fails the build.
