# Research track charter

**Status:** active (Core validated live on 2026-11-03 via `scripts/verify-live.sh` → HEALTHY)
**Start:** 2026-11-03
**Bar to ship as Core protection:** a research idea enters Core only if it is
deterministic, explainable, measurable (stated false-positive rate), and offline
(RESEARCH_REFERENCES.md §3). Baselines, ML, graph analysis and sandboxing fail at least
one of those today — they stay in Research.

## Purpose

The research track explores adaptive detection (behaviour baselines, ML classifiers,
sandbox integration, graph analysis) **without presenting any of it as protection the
user actually has**. Every research artefact is explicitly labeled "research — not a
detector you can rely on."

## Entry conditions (all must hold)

1. Core is validated live (`verify-live.sh` → HEALTHY). ✅ 2026-11-03
2. The work is read-only / non-mutating unless explicitly opt-in.
3. No claim of detection rate, blocking, or prevention is made.
4. Results state methodology, base rates, and false-positive rates — never bare accuracy.

## Open questions (from research-review.md §8)

- **O3:** What is MYAV's false-positive rate on real user files? → T026
- **O6:** Would a behaviour baseline help or just add noise? → needs a base-rate study

## Tickets

| ID | Title | Status |
|----|-------|--------|
| T026 | False-positive baseline study | done |

## Non-goals (explicit)

- No ML model shipped as detection.
- No behaviour baseline shipped as detection.
- No sandbox integration shipped as detection.
- No graph analysis shipped as detection.
- No detection-rate marketing claim.

## How a research idea graduates to Core

A research result graduates to Core only when a human operator reviews the measurement
document and all four entry conditions hold. Until then it remains "research — not
protection."
