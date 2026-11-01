---
project: myav
created: 2026-11-01
current_sprint: sprint-01
current_ticket: 
tier: AES-heavy
---

# Kanban — myav

> Source of truth for project state. Agents update this file, not their memory.
> Tier: **AES-heavy** — architectural, system-level, security-sensitive.

## Backlog

| ID | Title | Priority | Notes |
|----|-------|----------|-------|
| T013 | Baseline scan of pre-existing files | high | Sprint 02 |
| T014 | Allowlist UI (myav allow add/remove/list) | high | Sprint 02 |
| T015 | Windows toast notification for alerts | medium | Sprint 02 |
| T016 | Quarantine size budget & rotation | medium | Sprint 02 |
| T017 | VT quota dashboard in report | medium | Sprint 02 |
| T018 | ClamAV + YARA correlation scoring | medium | Sprint 03 |
| T019 | Archive/compressed handling (zip/7z/docm) | high | Sprint 03 |
| T020 | usbipd-aware device enumeration | medium | Sprint 03 |
| T021 | Scheduled YARA pack refresh with rule-diff review | medium | Sprint 03 |
| T022 | Shell completion | low | Polish |
| T023 | --json for every command | low | Polish |

## In Progress

| ID | Title | Phase |
|----|-------|-------|
| — | — | — |

## Review

| ID | Title | Reviewer |
|----|-------|----------|
| — | — | — |

## Done

| ID | Title | Verified by |
|----|-------|-------------|
| T000 | AES project bootstrap (scaffold + docs + kanban) | `ls`, `git log` |
| T001 | System dependency install (operator-run) | `scripts/install-system.sh --dry-run` |
| T002 | Project skeleton: config, paths, state, CLI | `make test` (262 pass) |
| T003 | ClamAV engine adapter | `tests/test_engines.py` |
| T004 | YARA engine + pinned rule pack | `tests/test_rules.py` |
| T005 | VirusTotal hash-only lookup | `tests/test_engines.py` |
| T006 | Verdict fusion + quarantine + restore | `tests/test_quarantine.py` |
| T007 | Write watcher (Downloads/Desktop/Documents/USB) | `tests/test_watcher.py` |
| T008 | Startup inventory + new-entry alert | `tests/test_bootwatch.py` |
| T009 | Task Scheduler / systemd / launchd integration | `tests/test_scheduler.py` |
| T010 | Plain-English reports | `tests/test_report.py` |
| T011 | EICAR self-test + live verification | `tests/test_selftest.py` |
| T012 | Operator runbook + final docs | `docs/RUNBOOK.md`, `docs/FAQ.md` |

## Blocked

| ID | Title | Blocked by |
|----|-------|------------|
| T001 (live proof) | Live ClamAV/YARA install + EICAR proof | Operator must run `sudo ./scripts/install-system.sh --apply` then `./scripts/verify-live.sh` |

## Learning History

| Date | Ticket | Insight |
|------|--------|---------|
| 2026-11-01 | T000 | WSL2 here has **systemd offline** and **cron not running** — all scheduling must go through Windows Task Scheduler; verified with `systemctl is-system-running` → `offline`. |
| 2026-11-01 | T000 | `C:` has **3.8 GiB free (100 % used)** — signatures (≈350 MiB), quarantine, and reports must live on ext4 only. |
| 2026-11-01 | T000 | Windows Defender real-time is **ON** and scans WSL files: EICAR tests can be intercepted. Design for `INCONCLUSIVE`, never disable Defender. |
| 2026-11-01 | T003/T004 | ClamAV `clamdscan` + `clamscan` fallback works; YARA 4.1.3 (Ubuntu 22.04) rejects newer rule syntax — `compile_pack` skips and reports per-file failures instead of aborting. |
| 2026-11-01 | T005 | VirusTotal is hash-only, opt-in, off by default; cache with separate positive/negative TTLs. |
| 2026-11-01 | T006 | Quarantine protocol: verify-then-move-then-verify; cross-device copy→fsync→hash→unlink; metadata in SQLite (not sidecar JSON). |
| 2026-11-01 | T007 | Watcher uses `watchdog` + 5 s mount poll + 2 s settle window; queue bounded at 256 with drop counter. |
| 2026-11-01 | T009 | Native Windows scheduler renders commands directly; WSL path routes through `wsl.exe -d <distro> -u <user>`. |
| 2026-11-01 | T009 | `Persistent=true` (systemd) and `StartWhenAvailable` (Task Scheduler) catch missed runs; launchd has no equivalent. |
| 2026-11-01 | T010 | Reports reconcile counts; sections: What ran, What was scanned, What was found, What is quarantined, Needs your attention, How to read this report. |
| 2026-11-01 | T003/T006 | Config: `ENFORCE_POSIX_MODES = os.name != "nt"` — Windows uses per-user ACLs, not mode bits; fixes native-Windows config rejection. |
| 2026-11-01 | T005 | `write_api_key` now correctly inserts into existing bare `[virustotal]` section via `_set_vt_section`. |
