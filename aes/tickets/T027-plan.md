---
ticket: T027
title: Honest measurement — false-positive + false-negative rate
sprint: research-01
priority: high
status: done
created: 2026-11-03
---

# T027 — Honest measurement (FPR + FNR + confusion matrix)

## Context

T026 created the research track charter and the `myav research fp-baseline` command, answering open question O3 partially (false-positive rate on known-good files). What is still missing is the other side of the coin: the **false-negative rate** (known-malicious samples that myav misses) and a **confusion matrix** that reconciles both. Without both numbers, any claim about detection quality is dishonest — exactly what Sommer & Paxson (2010) and Pendlebury et al. (2019) warn against.

## Acceptance Criteria

- [ ] `myav research fp-baseline <dir>` extended to also accept `--malicious-dir <dir>` for known-bad samples
- [ ] Scans both directories with dry-run semantics (nothing quarantined, nothing mutated)
- [ ] Reports: total clean scanned, total malicious scanned, false positives, false negatives, FPR %, FNR %, confusion matrix
- [ ] `--json` output supported
- [ ] Tests cover: clean corpus only (FNR = 0, FP rate measured), mixed corpus (both FP and FN measured), JSON output, missing directories
- [ ] Nothing ships as protection: this is a measurement document only
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/research/fp_baseline.py` (extend with malicious dir), CLI `research fp-baseline --malicious-dir`, tests.

**Out:** any adaptive detection, ML model, behavioural baseline, automatic blocking.

## Rollback

Git revert.

## Known Risks

- Using real malware samples is dangerous; tests must use only harmless test strings (EICAR) or AMTSO-style harmless test files.
- FNR depends entirely on the quality of the "known malicious" corpus; the operator must curate it.
