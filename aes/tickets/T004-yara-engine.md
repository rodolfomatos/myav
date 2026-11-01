---
ticket: T004
title: YARA engine + pinned public rule pack with provenance
sprint: sprint-01
priority: high
status: pending
created: 2026-11-01
---

# T004 — YARA + rule pack

## Context

Neo23x0 `signature-base` is the most credible public pack (malware families, webshells, miners).
License **DRL 1.1** (free for non-commercial use) → vendor nothing into git; fetch and verify.

## Acceptance Criteria

- [ ] `scripts/fetch-yara.sh` downloads a **pinned commit** archive, verifies SHA-256, writes
  `rules/PROVENANCE.json` (url, commit, sha256, rule_count, fetched_at)
- [ ] Fetch aborts if a rule fails to compile (`yara -C` / `yara-python compile`)
- [ ] `rules/` and `*.yar` are gitignored; provenance file **is** committed
- [ ] `YaraEngine.scan(path)` honours `max_scan_bytes` (100 MiB) and per-file timeout
- [ ] Skips symlinks and non-regular files
- [ ] Match result carries rule name, namespace, tags, and `meta.severity` when present
- [ ] Severity mapping documented (> = 7 MALICIOUS, 4–6 SUSPICIOUS, else informational)
- [ ] Missing/uncompiled pack → `skipped:no-rules`, never `clean`
- [ ] Unit tests use a 3-rule synthetic pack, not the real one (fast, deterministic)
- [ ] `myav doctor` prints pack commit + rule count + compile status

## Scope
**In:** `src/myav/engines/yara.py`, `scripts/fetch-yara.sh`, `rules/PROVENANCE.json`, tests.
**Out:** rule authoring, auto-refresh scheduling (Sprint 03).

## Rollback
`rm -rf rules/`; nothing else.

## Known Risks
- `yara-python` needs build deps; ship CLI (`yara`) as the default path and `yara-python` as an
  optional accelerator.
- Pack size ≈ 1 500 rules → compile once, cache under `~/.cache/myav/yara-rules.yarc` (ext4).
