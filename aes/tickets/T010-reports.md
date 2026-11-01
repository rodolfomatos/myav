---
ticket: T010
title: Plain-English reports
sprint: sprint-01
priority: medium
status: pending
created: 2026-11-01
---

# T010 — Reports

## Context

Requirement 8. The report is the product's user interface. It must be readable by a non-specialist
and must never overstate confidence.

## Acceptance Criteria

- [ ] Written to `~/.local/state/myav/reports/YYYY-MM-DD-HHMM-<watch|full|manual>.md`, mode 0644
- [ ] Sections, in order: **What ran**, **What was scanned**, **What was found**,
  **What is quarantined**, **Needs your attention**
- [ ] Header always states engine state: clamd up/down, signature age, YARA pack commit/age,
  VT configured/not, scope used
- [ ] Every finding line: `path — VERDICT — engine:signature/rule — sha256 (short)`
- [ ] Degraded states are called out in **Needs your attention**, not hidden
- [ ] Counts reconciled: `scanned = clean + suspicious + malicious + unknown + skipped`
  (asserted in tests; a mismatch is a bug)
- [ ] Signature/rule names get a one-line plain-English gloss where known, otherwise
  "unknown signature name — treated as malicious"
- [ ] `myav report last` prints to stdout; `--json` emits the same data
- [ ] Retention: keep 90 reports, prune older with a line in the new report
- [ ] No absolute home path leakage beyond what the operator already knows (they own the machine) —
  but the VT key and file **contents** never appear

## Scope
**In:** `src/myav/report.py`, templates, retention, tests.
**Out:** email/desktop notifications (Sprint 02), HTML.

## Rollback
Delete `reports/`; state.db unaffected.

## Known Risks
- A report claiming "0 threats" while an engine errored is the worst failure mode → the
  reconciliation assertion and the engine-state header are mandatory, not cosmetic.
