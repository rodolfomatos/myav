---
ticket: T023
title: --json for every command
sprint: Polish
priority: low
status: done
created: 2026-11-03
---

# T023 — --json for every command

## Context

Most myav commands already support `--json`. The exceptions are `allow list/add/remove` and
`report`, which only print text. T023 adds `--json` to these remaining commands so every
command has a machine-readable output mode.

## Acceptance Criteria

- [ ] `myav allow list --json` outputs JSON
- [ ] `myav allow add --json` outputs JSON
- [ ] `myav allow remove --json` outputs JSON
- [ ] `myav report --json` outputs JSON (report content as string)
- [ ] Existing --json commands unchanged
- [ ] Tests cover: each new --json path
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/cli.py` (allow and report commands), tests.

**Out:** --json on internal `inner` command.

## Rollback

Git revert.
