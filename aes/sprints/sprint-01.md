---
sprint: sprint-01
period: 2026-11-01 → 2026-11-15
status: active
goal: A working MVP that detects, quarantines, reports, and proves itself with EICAR.
---

# Sprint 01 — Working MVP

## Sprint Goal

The operator can drop a file in `~/Downloads`, see it scanned within seconds, get a plain-English
report, find anything flagged in quarantine, and restore it. Sunday 03:00 full scan is scheduled.
EICAR proves the whole chain.

## Tickets

| ID | Title | Status |
|----|-------|--------|
| T001 | System dependency install (operator-run) | awaiting operator go |
| T002 | Project skeleton: config, paths, state, CLI | pending |
| T003 | ClamAV engine adapter | pending |
| T004 | YARA engine + pinned rule pack | pending |
| T005 | VirusTotal hash-only lookup | pending |
| T006 | Verdict fusion + quarantine + restore | pending |
| T007 | Write watcher | pending |
| T008 | Startup inventory + new-entry alert | pending |
| T009 | Task Scheduler integration | pending |
| T010 | Plain-English reports | pending |
| T011 | EICAR self-test + live verification | pending |
| T012 | Operator runbook + final docs | pending |

## Definition of Done (sprint)

- [ ] `make verify-live` green on the real machine (EICAR detect → quarantine → restore)
- [ ] `myav doctor` green (clamd up, signatures < 24 h, YARA pack compiled, VT state reported)
- [ ] Scheduled tasks exist and report the correct next-run time
- [ ] Zero writes to `/mnt/c` (verified by an assertion in the test suite)
- [ ] Coverage ≥ 80 %, lint clean
- [ ] Report produced by both the watcher and the full scan

## Risks

- Operator has not yet approved apt/system changes → T001 blocks T003/T009/T011.
- Defender may intercept EICAR → test may report INCONCLUSIVE.
- 9p `/mnt/c` performance makes the `windows` scope unusable in practice; default off.

## Retrospective

*Filled at end of sprint.*
