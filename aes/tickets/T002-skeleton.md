---
ticket: T002
title: Skeleton — config, paths, state, CLI, exit codes
sprint: sprint-01
priority: high
status: pending
created: 2026-11-01
---

# T002 — Skeleton

## Context

Establishes the module boundaries from `docs/ARCHITECTURE.md` §2 so every later ticket plugs in
without touching policy code.

## Acceptance Criteria

- [ ] `python -m myav` with no args prints help and exits 0; unknown subcommand exits 2
- [ ] Subcommands parse: `scan`, `watch`, `quarantine`, `restore`, `allow`, `boot`, `report`, `doctor`, `selftest`, `full-scan`, `inner`, `config`
- [ ] `--json` on every read command; exit codes 0/10/11/12 per ARCHITECTURE §3
- [ ] `config.py` loads `~/.config/myav/config.toml` (0600 enforced, error if group/world-readable)
- [ ] XDG dirs created `0700`; nothing created under `/mnt/c`
- [ ] `state.py` migrates/creates SQLite schema v1 idempotently
- [ ] `hash.py` streams sha256/md5; test asserts 1 GiB file never fully buffered (size-based check)
- [ ] Unit tests ≥ 90 % on these modules

## Scope
**In:** `src/myav/{cli,config,paths,state,hash}.py`, `pyproject.toml`, `bin/myav`.
**Out:** engines, watcher, reports.

## Rollback
Delete `src/myav/`, revert `pyproject.toml`. No system state touched.

## Known Risks
Python 3.10 lacks `tomllib` → depend on `tomli`. Keep the dep optional-imported so the CLI still
runs (degraded) if missing.
