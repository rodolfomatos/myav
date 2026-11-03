---
ticket: T021
title: Scheduled YARA pack refresh with rule-diff review
sprint: sprint-03
priority: medium
status: done
created: 2026-11-03
---

# T021 — Scheduled YARA pack refresh with rule-diff review

## Context

`myav rules fetch --accept-license` downloads a pinned pack; `--update` moves to a newer
commit. There is no scheduled refresh, and no review of what changed between packs.
T021 adds `myav rules refresh` which fetches the latest pack, compares against the
previously pinned commit, and shows a rule-diff (added/removed/changed rule files).

## Acceptance Criteria

- [ ] `myav rules refresh` added to the CLI
- [ ] Reads current PROVENANCE.json before fetching
- [ ] Fetches newer pack with `--update`
- [ ] Shows rule-diff: rule file count before/after, changed/added/removed files
- [ ] `--json` output supported
- [ ] Tests cover: refresh with changes, refresh with no changes, no previous provenance
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/cli.py` (rules refresh action), `src/myav/rules.py` (diff helper if needed),
tests.

**Out:** automatic scheduling of refresh (wired later), diff review UI beyond text.

## Rollback

Git revert.
