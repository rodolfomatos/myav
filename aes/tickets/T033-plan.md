---
ticket: T033
title: Supply chain and operational honesty dashboard
sprint: research-01
priority: medium
status: done
created: 2026-11-06
---

# T033 — Supply chain and operational honesty dashboard

## Context

RESEARCH_REFERENCES.md §6 establishes supply-chain controls (SLSA, Sigstore, CycloneDX, OpenSSF Scorecard). T033 hardens myav's own supply chain and adds an operational honesty dashboard: the operator can see exactly how much to trust myav on *this* machine, based on real measured data, not marketing claims.

## Acceptance Criteria

- [ ] `src/myav/research/honesty_dashboard.py` created: dashboard with real measured metrics
- [ ] `myav research honesty-dashboard` CLI command added
- [ ] SBOM generated per release (not committed once) — `docs/sbom/myav.cdx.json` regenerated per release
- [ ] Releases signed (Sigstore/cosign or GPG) — documented how to sign
- [ ] Dashboard reports real measured metrics: files scanned, flagged, restored, confirmed false positives, FPR over time
- [ ] Dashboard reports "confidence level" based on measurement quantity, not marketing
- [ ] `--json` output supported
- [ ] Tests cover: SBOM structure valid, dashboard computes metrics from state DB, JSON output
- [ ] Nothing ships as protection: transparency only
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/research/honesty_dashboard.py`, SBOM/release signing process, CLI `research honesty-dashboard`, tests.

**Out:** actual release signing key management (operator holds the key), production CI/CD pipeline, automatic SBOM generation in CI.

## Rollback

Git revert. Nothing installed or configured is changed.

## Known Risks

- Confidence level is subjective; must be clearly labeled as an estimate.
- Signing keys must be operator-controlled, not committed to the repo.
- SBOM regeneration requires build tooling not present in all environments.
