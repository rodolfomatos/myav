---
ticket: T017
title: VT quota dashboard in report
sprint: sprint-02
priority: medium
status: done
created: 2026-11-03
---

# T017 — VT quota dashboard in report

## Context

`build_context` already shows `requests_last_day/per_day` in the VirusTotal engine-state line.
T017 makes the quota more visible: when VT is configured, the report shows a dedicated line
with requests used today, requests used this minute, daily/minute limits, and remaining
quota — so the operator can see at a glance how much VT budget is left.

## Acceptance Criteria

- [ ] When VT is configured, report shows a VT quota line: requests today, requests this
      minute, daily limit, per-minute limit, remaining
- [ ] When VT is not configured, report says "not configured (optional)" as before
- [ ] Tests cover: VT configured (quota line present), VT not configured (no quota line)
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/report.py` (build_context vt_state, render_report), tests.

**Out:** VT quota alerts, auto-throttling beyond existing rate limits.

## Rollback

Git revert.
