---
project: myav
created: 2026-11-01
current_sprint: sprint-01
current_ticket: T001
tier: AES-heavy
---

# Kanban — myav

> Source of truth for project state. Agents update this file, not their memory.
> Tier: **AES-heavy** — architectural, system-level, security-sensitive.

## Backlog

| ID | Title | Priority | Notes |
|----|-------|----------|-------|
| T002 | Project skeleton: config, paths, state, CLI | high | after T001 |
| T003 | ClamAV engine adapter | high | |
| T004 | YARA engine + pinned rule pack | high | license: DRL 1.1 |
| T005 | VirusTotal hash-only lookup | medium | needs operator key |
| T006 | Verdict fusion + quarantine + restore | high | "never delete" guarantee |
| T007 | Write watcher (Downloads/Desktop/USB) | high | |
| T008 | Startup inventory + new-entry alert | medium | |
| T009 | Task Scheduler integration | high | systemd offline |
| T010 | Plain-English reports | medium | |
| T011 | EICAR self-test + live verification | high | proof of FR-9 |
| T012 | Operator runbook + final docs | medium | |

## In Progress

| ID | Title | Phase |
|----|-------|-------|
| T001 | System dependency install (operator-run) | plan → awaiting operator go |

## Review

| ID | Title | Reviewer |
|----|-------|----------|
| — | — | — |

## Done

| ID | Title | Verified by |
|----|-------|-------------|
| T000 | AES project bootstrap (scaffold + docs + kanban) | `ls`, `git log` |

## Blocked

| ID | Title | Blocked by |
|----|-------|------------|
| — | — | — |

## Learning History

| Date | Ticket | Insight |
|------|--------|---------|
| 2026-11-01 | T000 | WSL2 here has **systemd offline** and **cron not running** — all scheduling must go through Windows Task Scheduler; verified with `systemctl is-system-running` → `offline`. |
| 2026-11-01 | T000 | `C:` has **3.8 GiB free (100 % used)** — signatures (≈350 MiB), quarantine, and reports must live on ext4 only. |
| 2026-11-01 | T000 | Windows Defender real-time is **ON** and scans WSL files: EICAR tests can be intercepted. Design for `INCONCLUSIVE`, never disable Defender. |
