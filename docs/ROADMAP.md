# Roadmap

This roadmap reflects the **Core / Research split** defined in [VISION.md](VISION.md). Core is the
shippable product; Research is the experimental track with no delivery dates.

## [HIGH] Sprint 01 — Working MVP (scan → quarantine → report → prove)
- **Core**
- Impact: High — this is the product
- Effort: High
- **Status: complete** (all tickets T001–T012 implemented; live verification pending operator `sudo` step)
- Tickets: T001–T012 (see `aes/sprints/sprint-01.md`)

## [HIGH] Sprint 02 — Hardening
- **Core**
- Impact: High
- Effort: Medium
- Status: todo
- Baseline scan of pre-existing files; allowlist UI; report/alert delivery
  (Windows toast); quarantine size budget; VT quota dashboard.

## [MEDIUM] Sprint 03 — Coverage beyond write events
- **Core**
- Impact: Medium
- Effort: High
- Status: todo
- Second opinion (ClamAV + YARA correlation scoring); archive/compressed
  handling (zip/7z/docm); `usbipd`-aware device enumeration instead of mount
  polling; scheduled YARA pack refresh with rule-diff review.

## [LOW] Polish
- **Core**
- Impact: Low
- Effort: Low
- Status: todo
- Shell completion, `--json` for every command.

## Research track (no sprint assignment — no dates)

| Area | What it means | Status |
|---|---|---|
| Behavioural baseline | Learn normal process/file/network patterns; detect anomalies | Design |
| Machine Learning | Interpretable models (Isolation Forest, XGBoost) trained on labelled data | Design |
| Graph analysis | Process tree / file-access / network correlation as a graph | Design |
| Sandbox integration | CAPE/Cuckoo for dynamic analysis of suspicious files | Design |
| Scientific evaluation | Reproducible training/eval pipeline with family-wise splits | Design |

Nothing in the Research track is presented as a working feature in Core. When a research item
reaches validation, it is promoted via a self-ticket through the AES pipeline.

## Backlog — [DISCOVERED mid-task]
*(empty)*
