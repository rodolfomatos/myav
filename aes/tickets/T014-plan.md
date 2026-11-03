---
ticket: T014
title: Allowlist UI (myav allow add/remove/list)
sprint: sprint-02
priority: high
status: done
created: 2026-11-03
---

# T014 — Allowlist UI (myav allow add/remove/list)

## Context

`myav allow add` and `myav allow list` already exist (cli.py `cmd_allow`). The allowlist is a
false-positive escape hatch: a file whose sha256 is allowlisted always scores CLEAN. What is
missing is `myav allow remove` — the operator cannot revoke an allowlist entry once added.

T014 adds `remove` (by sha256, and optionally by path which resolves to its hash) plus a
`State.disallow` method. The `add`/`list` paths are unchanged.

## Acceptance Criteria

- [ ] `myav allow remove <sha256>` removes the hash from the allowlist
- [ ] `myav allow remove --path <path>` hashes the file and removes that sha256
- [ ] `myav allow remove` on a non-existent hash reports "not allowlisted" and exits non-zero
- [ ] `myav allow list` and `myav allow add` still work unchanged
- [ ] `State.disallow(sha256)` added with INSERT OR IGNORE semantics (idempotent)
- [ ] Tests cover: remove by hash, remove by path, remove missing, remove idempotent
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/cli.py` (allow remove action + parser), `src/myav/state.py` (disallow),
tests.

**Out:** bulk remove, remove-all, pattern matching.

## Rollback

Git revert.
