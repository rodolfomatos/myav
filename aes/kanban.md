---
project: myav
created: 2026-11-01
current_sprint: research-01
current_ticket: none
tier: AES-heavy
---

# Kanban — myav

> Source of truth for project state. Agents update this file, not their memory.
> Tier: **AES-heavy** — architectural, system-level, security-sensitive.

## In Progress

| ID | Title | Phase |
|----|-------|-------|
| — | — | — |

## Backlog

| ID | Title | Priority | Notes |
|----|-------|----------|-------|
| T033 | Supply chain and operational honesty dashboard | medium | Research-01 |

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
| T013 | Baseline scan of pre-existing files | `pytest` (267 pass), `ruff` clean, coverage 93.97% |
| T014 | Allowlist UI (myav allow add/remove/list) | `pytest` (272 pass), `ruff` clean, coverage 94.02% |
| T015 | Windows toast notification for alerts | `pytest` (276 pass), `ruff` clean, coverage 94.05% |
| T016 | Quarantine size budget & rotation | `pytest` (281 pass), `ruff` clean, coverage 92.71% |
| T017 | VT quota dashboard in report | `pytest` (282 pass), `ruff` clean, coverage 92.72% |
| T018 | ClamAV + YARA correlation scoring | `pytest` (286 pass), `ruff` clean, coverage 92.73% |
| T019 | Archive/compressed handling (zip/7z/docm) | `pytest` (292 pass), `ruff` clean, coverage 92.60% |
| T020 | usbipd-aware device enumeration | `pytest` (296 pass), `ruff` clean, coverage 92.40% |
| T021 | Scheduled YARA pack refresh with rule-diff review | `pytest` (299 pass), `ruff` clean, coverage 91.96% |
| T022 | Shell completion | `pytest` (306 pass), `ruff` clean, coverage 91.73% |
| T023 | --json for every command | `pytest` (306 pass), `ruff` clean, coverage 91.73% |
| T024 | Per-file progress line for long full scans | `pytest` (309 pass), `ruff` clean, coverage 91.72% |
| T025 | Visual progress bar for long full scans | `pytest` (318 pass), `ruff` clean, coverage 91.62% |
| T026 | False-positive baseline study (research track) | `pytest` (326 pass), `ruff` clean, coverage 91.67% |
| T027 | Honest measurement — FPR + FNR + confusion matrix (research track) | `pytest` (333 pass), `ruff` clean, coverage 91.81% |
| T028 | User behaviour baseline (research track) | `pytest` (351 pass), `ruff` clean, coverage 92.03% |
| T029 | Purpose-specific behavioural detection (research track) | `pytest` (365 pass), `ruff` clean, coverage 92.08% |
| T030 | ML with scientific rigour — EMBER baseline + temporal evaluation (research track) | `pytest` (381 pass), `ruff` clean, coverage 92.06% |
| T031 | Lightweight sandbox — sufficient observation time (research track) | `pytest` (396 pass), `ruff` clean, coverage 92.06% |
| T032 | Campaign correlation graphs — beyond isolated files (research track) | `pytest` (405 pass), `ruff` clean, coverage 92.06% |
| T034 | GUI desktop (Tkinter) — research track | `pytest` (412 pass), `ruff` clean, coverage 92.06% |

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
| 2026-11-03 | T026 | Research track unlocked: `verify-live.sh` → HEALTHY on 2026-11-03. Research track charter created (`docs/RESEARCH_TRACK.md`). First research measurement: false-positive baseline study (`myav research fp-baseline`), answering open question O3 from research-review.md §8. Key lesson: `EngineResult.fired` is a computed property of `status`, not a constructor field — passing `fired=` raises TypeError caught by `_safe_engine`, producing UNKNOWN verdicts.
| 2026-11-03 | T027 | Honest measurement extended: `myav research fp-baseline <dir> --malicious-dir <dir>` now measures both false-positive rate and false-negative rate, producing a full confusion matrix (TN/FP/FN/TP), precision, recall. Key lesson: `walk_directory` lives in `myav.pipeline`, not `myav.paths` — wrong import caused ImportError at test collection time.
| 2026-11-03 | T028 | User behaviour baseline: `myav research behaviour-baseline <dir> --learn|--check` learns a baseline of processes, hours, directories, connections and modified files, then checks for deviations. Key lesson: baseline must be persisted in the real state DB (not a temp DB) so `learn` and `check` can share it across CLI invocations.
| 2026-11-03 | T029 | Purpose-specific behavioural detection: `myav research behaviour-detect <path>` runs heuristic detectors for ransomware (canary/bulk-rename), fileless/LOTL (obfuscated scripts) and documents (macros). Key lesson: heuristic detectors have false positives — results are alerts only, labelled as research, never shipped as Core protection.
| 2026-11-03 | T030 | ML with scientific rigour: `myav research ml-baseline --train-dir <dir> --test-dir <dir> [--temporal]` trains a logistic regression on EMBER-style features with temporal evaluation, reports FPR/FNR/precision/recall/confusion matrix — never bare accuracy. Key lesson: `EvaluationResult.to_dict()` must include `"command"` key for JSON output consistency with other research commands.
| 2026-11-03 | T031 | Lightweight sandbox: `myav research sandbox <file> [--duration N]` executes a file in isolation with resource limits, monitors process spawns/file modifications/autostart changes, detects sandbox evasion (timing checks, VM artifacts, user interaction requirements), reports behavioural timeline. Key lesson: sandbox must apply resource limits (RLIMIT_AS, RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_NPROC) to prevent escape or denial of service.
| 2026-11-05 | T032 | Campaign correlation graphs: `myav research campaign-graph [--days N]` builds a graph linking file → process → connection → startup entry, reports clusters with heuristic risk scores. Key lesson: connected-component analysis on a small event graph is straightforward; the challenge is populating the graph from real watcher/scheduler events rather than example data.
| 2026-11-06 | T034 | GUI desktop: `myav research gui` launches a Tkinter GUI with tabs for Scan, Quarantine, Reports, Config, Research. Tkinter (stdlib) used — zero new dependencies. GUI is read-only/alerting only — nothing ships as Core protection. Tkinter not available in headless environments; tests skip gracefully.
