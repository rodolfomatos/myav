---
ticket: T007
title: Write watcher for Downloads, Desktop, USB volumes
sprint: sprint-01
priority: high
status: pending
created: 2026-11-01
---

# T007 — Watcher

## Context

`inotify-tools` is absent and installing it is unnecessary: `watchdog` gives inotify in-process.
USB volumes in WSL appear as `/mnt/<letter>` mounts (no udisks, no udev) → watch the mount table.

## Acceptance Criteria

- [ ] Watches `~/Downloads` and `~/Desktop` recursively; creates the dirs if missing **only** with
  `--create-dirs`, never silently
- [ ] Detects new mounts under `/mnt/*` within 10 s and adds/removes watchers
- [ ] Excludes `/mnt/c`, `/mnt/wsl*`, `/proc`, `/sys`, `/dev`, `~/.local/share/myav/quarantine`
- [ ] Settle window (default 2 s after last write) before scanning; handles partial writes
- [ ] Event coalescing by inode+size+sha256; same file scanned once per content
- [ ] Bounded queue (default 256) with a "dropped event" counter in the report
- [ ] File vanishing before scan → `vanished`, logged at debug, not an error
- [ ] Worker pool (default 2) so a big file does not block the queue
- [ ] `--once` mode scans the current backlog and exits (used by tests)
- [ ] End-to-end test: drop file → scan recorded in `state.db` ≤ 10 s
- [ ] Runs unprivileged; no root needed
- [ ] Graceful SIGTERM: drains in-flight scans, writes report

## Scope
**In:** `src/myav/watcher.py`, `pipeline.py`, mount detection, tests.
**Out:** execution blocking (fanotify), Windows-side watching.

## Rollback
Stop the process; no persistent state beyond logs/state.db.

## Known Risks
- WSL2 stops the distro after idle; the watcher dies with it. Windows Task Scheduler at logon
  restarts it (T009).
- inotify watch limit (`fs.inotify.max_user_watches`, default 65536) can be hit on huge trees.
  Watcher must catch `OSError` and report `watch-limit-reached` instead of crashing.
