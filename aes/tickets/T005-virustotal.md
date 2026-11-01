---
ticket: T005
title: VirusTotal hash-only lookup (opt-in, rate-limited, cached)
sprint: sprint-01
priority: medium
status: pending
created: 2026-11-01
---

# T005 — VirusTotal (hash only)

## Context

Reputation for files VT already knows. The hard requirement: **no upload, ever**. The API key is
provided by the operator and lives at `~/.config/myav/config.toml` (0600).

## Acceptance Criteria

- [ ] Only `GET https://www.virustotal.com/api/v3/files/{sha256}` (md5 fallback) exists in the codebase
- [ ] A test greps the module and fails if `POST`, `PUT`, `/files` upload, or a request body appears
- [ ] Unconfigured → `vt.status = "not-configured"`, verdict still produced, no network call
- [ ] 404 → `vt.status = "unknown"`, cached 24 h
- [ ] Rate limiter: ≤ 4 req/min, ≤ 500/day, persistent across process restarts (`state.db`)
- [ ] 429 → backoff, `vt.status = "rate-limited"`, never retried in a tight loop
- [ ] Cache TTL: positives 7 days, negatives 24 h; cache key = sha256 only
- [ ] Key never appears in logs, reports, `--json`, or exception messages (redaction test)
- [ ] Offline mode (`--no-network` / config) disables the engine with a clear reason
- [ ] No filename or path is ever sent

## Scope
**In:** `src/myav/engines/virustotal.py`, config schema, tests with a mocked transport.
**Out:** file submission, VT Intelligence, hunting API.

## Rollback
Disable in config; delete `vt_cache` table rows.

## Known Risks
- Free tier is 4 lookups/min → a burst of downloads will queue; the watcher must not stall on VT.
  Design: VT runs **asynchronously** and updates the verdict later, or is skipped under load.
- Hash lookup itself leaks "this machine has file X" to VT. Documented, opt-in.
