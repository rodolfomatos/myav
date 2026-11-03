---
ticket: T028
title: User behaviour baseline — what is normal on this machine
sprint: research-01
priority: high
status: done
created: 2026-11-03
---

# T028 — User behaviour baseline

## Context

Open question O6 from research-review.md §8: "Would a behaviour baseline help or just add noise?" Signature detection has a hard ceiling against new samples (Kolter & Maloof 2006; Bayer et al. 2009 NDSS). Behaviour is a different signal. T028 builds a read-only baseline of what is *normal* for this operator: processes run, times of day, directories touched, outbound network connections, files modified. Deviations from this baseline generate alerts — not blocks.

## Acceptance Criteria

- [ ] `src/myav/research/behaviour_baseline.py` created: records a baseline over a training window
- [ ] `myav research behaviour-baseline <dir> [--learn N days] [--check]` CLI command
- [ ] Learns: process names, execution hours, accessed directories, outbound connections, modified files
- [ ] Checks: compares current activity against baseline, reports deviations as alerts
- [ ] `--json` output supported
- [ ] Tests cover: baseline learns from synthetic activity, deviations are flagged, no deviation on matching activity, JSON output
- [ ] Nothing ships as protection: alerting only, never blocking
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/research/behaviour_baseline.py`, CLI `research behaviour-baseline`, tests.

**Out:** automatic blocking, kernel integration, ML model.

## Rollback

Git revert.

## Known Risks

- A baseline learned on a small window will have high false-positive rate; the operator must be told the window size matters.
- Behavioural baselines are machine-specific; results do not transfer between machines.
