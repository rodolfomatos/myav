---
ticket: T030
title: ML with scientific rigour — EMBER baseline + temporal evaluation
sprint: research-01
priority: medium
status: done
created: 2026-11-03
---

# T030 — ML with scientific rigour

## Context

Sommer & Paxson (2010) and Pendlebury et al. (2019) establish that ML detectors fail under real base rates and that random train/test splits overstate performance. T030 builds a research ML baseline using EMBER (Anderson & Roth 2018) with **temporal evaluation**: train on one time period, test on a later period. Reports FPR and FNR — never bare accuracy. No model ships as protection.

## Acceptance Criteria

- [ ] `src/myav/research/ml_baseline.py` created: trains/evaluates a simple classifier on EMBER features
- [ ] `myav research ml-baseline [--train-dir] [--test-dir] [--temporal]` CLI command
- [ ] Temporal evaluation: split by time, not randomly
- [ ] Reports: FPR, FNR, precision, recall, confusion matrix — never "accuracy" alone
- [ ] `--json` output supported
- [ ] Model is explainable: feature importance reported (SHAP-style or built-in)
- [ ] Tests cover: temporal split produces different result than random split, FPR/FNR computed, JSON output, empty directory handled
- [ ] Nothing ships as protection: measurement only
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/research/ml_baseline.py`, CLI `research ml-baseline`, tests.

**Out:** shipping ML as detection, deep learning, neural networks.

## Rollback

Git revert.

## Known Risks

- EMBER features require the EMBER dataset; tests may use synthetic features if EMBER unavailable.
- ML baseline will likely show poor temporal performance — that is an honest result, not a failure.
