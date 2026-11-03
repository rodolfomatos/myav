---
ticket: T029
title: Purpose-specific behavioural detection (ransomware, fileless/LOTL, documents)
sprint: research-01
priority: high
status: pending
created: 2026-11-03
---

# T029 — Purpose-specific behavioural detection

## Context

Küchler et al. 2021 (NDSS) show that sandbox observation time matters: short runs miss behaviour. T029 adds purpose-specific behavioural detectors that fire on *patterns* rather than byte signatures:

- **Ransomware:** honeyfiles/canaries in watched directories; sudden high-entropy renaming in bulk
- **Fileless / LOTL:** PowerShell, WMI, mshta, certutil running obfuscated scripts; VBA/macro deobfuscation
- **Documents:** extraction of Office macros, PDF OLE objects, without executing the document

These are alert-only detections for research measurement.

## Acceptance Criteria

- [ ] `src/myav/research/behaviour_detectors.py` created with detector modules for ransomware, fileless/LOTL, documents
- [ ] `myav research behaviour-detect <path>` CLI command scans a path/directory and reports behavioural matches
- [ ] Honeyfile/canary detection: if a canary file is modified/renamed, alert
- [ ] Bulk rename detection: N files renamed with suspicious extensions in short window
- [ ] Obfuscated script detection: PowerShell/VBA with high entropy or known obfuscation patterns
- [ ] `--json` output supported
- [ ] Tests cover: canary modification detected, bulk rename detected, obfuscated script detected, clean file not flagged, JSON output
- [ ] Nothing ships as protection: alerting only
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/research/behaviour_detectors.py`, CLI `research behaviour-detect`, tests.

**Out:** automatic blocking, sandbox integration, ML.

## Rollback

Git revert.

## Known Risks

- Behavioural detectors are heuristic; they will have false positives. The measurement must state the rate.
- Obfuscation patterns evolve; detectors must be treated as experiments, not product features.
