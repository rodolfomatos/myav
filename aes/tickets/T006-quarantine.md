---
ticket: T006
title: Verdict fusion + quarantine + restore (the "never delete" guarantee)
sprint: sprint-01
priority: high
status: pending
created: 2026-11-01
---

# T006 — Verdict + quarantine

## Context

The single most dangerous module in the project. A bug here destroys user files. The protocol in
`docs/ARCHITECTURE.md` §4 is normative.

## Acceptance Criteria

- [ ] Fusion: max severity wins; engine error → `UNKNOWN`; never `CLEAN` with any error or missing engine
- [ ] Same-filesystem: `os.rename` (atomic); cross-device: copy → fsync(file) → fsync(dir) → verify → unlink
- [ ] Hash mismatch **never** unlinks the source; both copies kept; verdict `UNKNOWN`; operator alerted
- [ ] Permission error on unlink → source kept, quarantine copy kept, reported as `partial`
- [ ] Sidecar JSON: original path, mode, mtime, size, sha256, engine evidence, ts, reason, tag
- [ ] Quarantined payload stored mode `0000`, name = uuid4, no original extension
- [ ] `restore <id>` verifies hash, refuses overwrite without `--force`, restores mode/mtime, re-hashes
- [ ] `allow <sha256>` skips quarantine; allowlist consulted before move, audited in `state.db`
- [ ] `purge` requires `--yes`; without it, prints the plan and exits 3
- [ ] Idempotent: quarantining the same sha256 twice does not create duplicates
- [ ] **Property test**: random byte blobs, random failures injected (ENOSPC, EACCES, EXDEV) →
  invariant "no file is lost" always holds
- [ ] Test asserts zero `unlink` calls when verification fails (mock)

## Scope
**In:** `src/myav/verdict.py`, `quarantine.py`, `state.db` schema, tests.
**Out:** UI, notifications, purge scheduling.

## Rollback
No system state; quarantine dir is user data — never delete it as "rollback".

## Known Risks
- Cross-device move from `/mnt/c` is slow and non-atomic; default scope excludes `/mnt/c`.
- `os.rename` on the same fs is atomic but the sidecar is written **after** the move — a crash
  between them leaves an orphan payload. Mitigation: write sidecar first (state=staged), then move,
  then mark `complete`; a startup scan reconciles staged entries.
