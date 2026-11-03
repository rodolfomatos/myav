---
ticket: T033
title: Supply chain and operational honesty dashboard
sprint: research-01
priority: medium
status: pending
created: 2026-11-03
---

# T033 — Supply chain and operational honesty

## Context

RESEARCH_REFERENCES.md §6 establishes supply-chain controls (SLSA, Sigstore, CycloneDX, OpenSSF Scorecard). T033 hardens myav's own supply chain and adds an operational honesty dashboard: the operator can see exactly how much to trust myav on *this* machine, based on real measured data, not marketing claims.

## Acceptance Criteria

- [ ] SBOM generated per release (not committed once)
- [ ] Releases signed (Sigstore/cosign or GPG)
- [ ] `docs/sbom/` regenerated per release, not static
- [ ] `myav research honesty-dashboard` CLI command shows real measured metrics: files scanned, flagged, restored, confirmed false positives, FPR over time
- [ ] Dashboard reports "confidence level" based on measurement quantity, not marketing
- [ ] Tests cover: SBOM structure valid, dashboard computes metrics from state DB, JSON output
- [ ] Nothing ships as protection: transparency only
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/research/honesty_dashboard.py`, SBOM/release signing process, CLI `research honesty-dashboard`, tests.

**Out:** actual release signing key management (operator holds the key), production CI/CD pipeline.

## Rollback

Git revert.

## Known Risks

- Confidence level is subjective; must be clearly labeled as an estimate.
- Signing keys must be operator-controlled, not committed to the repo.
