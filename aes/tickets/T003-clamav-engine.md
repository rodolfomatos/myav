---
ticket: T003
title: ClamAV engine adapter (clamdscan → clamscan fallback)
sprint: sprint-01
priority: high
status: pending
created: 2026-11-01
---

# T003 — ClamAV adapter

## Context

Per-file `clamscan` reloads the ~250 MiB signature DB (1–3 s/file) — unusable in a watcher.
`clamdscan` against a warm daemon is milliseconds.

## Acceptance Criteria

- [ ] `ClamAVEngine.scan(path) -> EngineResult` with `status`, `signature`, `raw`
- [ ] Uses `clamdscan --no-summary --stdout` when the socket answers; falls back to `clamscan`
  and records `degraded=fallback` in the result
- [ ] Timeout (default 60 s) → result `error`, never `clean`
- [ ] Unreadable file → `error`, never `clean`
- [ ] Signature DB version + age exposed for `doctor` and reports
- [ ] EICAR fixture (constructed from parts, not a literal in source) returns `FOUND`
- [ ] Fake `clamdscan` binary in `tests/fixtures/bin` proves fallback, timeout, and parse paths
- [ ] No `shell=True`; argv list only; filenames with spaces/quotes/newlines tested

## Scope
**In:** `src/myav/engines/clamav.py`, `engine.py` base, tests.
**Out:** starting the daemon (T009/supervisor).

## Rollback
Remove adapter; no system state.

## Known Risks
Daemon down at scan time is the normal case until the supervisor exists → fallback must be correct
first, daemon path second.
