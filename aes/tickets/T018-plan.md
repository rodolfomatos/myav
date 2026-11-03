---
ticket: T018
title: ClamAV + YARA correlation scoring
sprint: sprint-03
priority: medium
status: done
created: 2026-11-03
---

# T018 — ClamAV + YARA correlation scoring

## Context

`fuse` takes maximum severity across engines and lists each engine's finding as a reason.
When both ClamAV and YARA flag the same file, the evidence is stronger than either alone.
T018 adds correlation detection: when both engines fire on the same file, a correlation
reason is added to the verdict so reports and quarantine evidence show the corroboration.

## Acceptance Criteria

- [ ] `fuse` detects when both ClamAV and YARA fired (status MALICIOUS or SUSPICIOUS)
- [ ] Adds correlation reason: "correlation: clamav+yara agree"
- [ ] Correlation reason appears in `verdict.reasons`
- [ ] Correlation does not change the level (max severity still wins) — it is additive evidence
- [ ] Tests cover: both fire (correlation present), only ClamAV fires (no correlation), only
      YARA fires (no correlation), neither fires (no correlation)
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/verdict.py` (fuse), tests.

**Out:** using correlation to change quarantine threshold, correlation with VirusTotal.

## Rollback

Git revert.
