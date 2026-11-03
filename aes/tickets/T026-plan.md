---
ticket: T026
title: False-positive baseline study (research track)
sprint: research-01
priority: medium
status: done
created: 2026-11-03
---

# T026 — False-positive baseline study (research track)

## Context

PROJECT_STATUS.md §3.6 states the research track is "not started" and describes it as
"baselines, ML, graph analysis, sandbox" — none of which ship as protection. The bar any
future model must clear (RESEARCH_REFERENCES.md §3): **temporal evaluation, stated
false-positive rate, base-rate honesty**.

research-review.md §8 lists open question **O3**: "What is MYAV's false-positive rate on
real user files? — Unmeasured."

T026 answers O3 with a read-only measurement: scan a corpus of known-good files with
`myav scan --dry-run` (detection only, nothing quarantined) and compute the false-positive
rate = files flagged MALICIOUS/SUSPICIOUS / total files scanned. The result is a
measurement document, not a detection feature.

## Acceptance Criteria

- [ ] `docs/RESEARCH_TRACK.md` created: research track charter, scope, entry bar, open questions
- [ ] `src/myav/research/__init__.py` and `src/myav/research/fp_baseline.py` created: read-only FP scanner
- [ ] `myav research fp-baseline <dir>` CLI command added, gated on research capability
- [ ] Scans every file under `<dir>` with `--dry-run` (no quarantine, no mutation)
- [ ] Reports: total scanned, FP count, FP rate %, list of flagged files with evidence
- [ ] `--json` output supported
- [ ] Tests cover: FP baseline on a clean corpus (0 FP), FP baseline with a planted EICAR (1 FP), JSON output
- [ ] Coverage ≥ 80%, lint clean
- [ ] Nothing in this ticket ships as protection: no ML, no behaviour model, no sandbox

## Scope

**In:** measurement tooling, report, CLI command, tests.

**Out:** any adaptive detection, ML model, behaviour baseline, automatic blocking, changes to
the verdict/quarantine pipeline.

## Rollback

Git revert. Nothing installed or configured is changed.

## Known Risks

- A corpus containing EICAR-like strings or compressed malware samples will inflate the FP
  rate; the operator must curate the corpus.
- `--dry-run` means no files are quarantined; the measurement reflects what *would* be
  flagged, not what *was* flagged.
