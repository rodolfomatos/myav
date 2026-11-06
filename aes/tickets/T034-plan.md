---
ticket: T034
title: GUI desktop (Tkinter) — research track
sprint: research-01
priority: high
status: done
created: 2026-11-06
---

# T034 — GUI desktop (Tkinter) — research track

## Context

The myav CLI is powerful but requires terminal familiarity. A GUI makes the tool accessible to non-technical operators and provides a single surface for scanning, quarantine management, report reading, configuration, and research-track measurement visualization.

Per operator decisions:
- **Framework:** Tkinter (stdlib, zero new dependencies, pure Python like the rest of myav)
- **Scope:** Both scanning/quarantine/reports **and** configuration (watch dirs, schedule, YARA pack, VT key)
- **Research track:** Show all research measurements (FP baseline, behaviour baseline, behaviour-detect, ML baseline, sandbox, campaign graph)
- **Model:** Separate process — `myav gui` reads the state DB and config, never shares memory with the scanner

## Acceptance Criteria

- [ ] `src/myav/research/gui.py` created: Tkinter-based GUI application
- [ ] `myav gui` CLI command added to research subcommands
- [ ] Main window with tabs: Scan, Quarantine, Reports, Config, Research
- [ ] **Scan tab:** trigger `myav full-scan` / `myav scan PATH`, show progress, display results
- [ ] **Quarantine tab:** list quarantined files, restore, purge (with --yes confirmation)
- [ ] **Reports tab:** list and view saved markdown reports
- [ ] **Config tab:** view/edit watch dirs, schedule, YARA rules status, VT key (masked)
- [ ] **Research tab:** buttons to run fp-baseline, behaviour-baseline, behaviour-detect, ml-baseline, sandbox, campaign-graph; display results
- [ ] `--json` output not applicable (GUI is interactive)
- [ ] Nothing ships as protection: GUI is a frontend over existing CLI commands
- [ ] Tests cover: GUI launches, tabs render, scan triggers, quarantine list renders, research buttons call subcommands (mocked)
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/research/gui.py`, CLI `myav gui`, tests.

**Out:** standalone GUI executable (pyinstaller), real-time watcher integration, macOS/Windows native look-and-feel beyond Tkinter defaults.

## Rollback

Git revert. Nothing installed or configured is changed.

## Known Risks

- Tkinter look-and-feel is dated on some platforms; acceptable for MVP research tool
- GUI running long scans may block the Tkinter event loop; use threading for scan commands
- Tkinter not available in minimal headless environments (CLI remains the fallback)
