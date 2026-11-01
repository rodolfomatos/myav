# Handoff — 2026-11-01 — T000 bootstrap

## State

- AES project scaffolded in `/opt/myav` (python, git initialised, AES hooks installed).
- Planning artifacts written: `CLAUDE.md`, `docs/{VISION,REQUIREMENTS,ROADMAP,PERSONAS,ARCHITECTURE,THREAT_MODEL}.md`,
  `aes/kanban.md`, `aes/sprints/sprint-01.md`, `aes/tickets/T001..T012`.
- **No code written yet.** `src/main.py`, `tests/test_main.py` are scaffold placeholders.
- **No system changes made.** Nothing installed, no `/etc` edit, no scheduled task.

## Environment facts captured (re-verify before trusting)

```
Ubuntu 22.04.5 LTS · WSL2 · kernel 6.6.87.1-microsoft-standard-WSL2
systemctl is-system-running → offline        (no systemd)
service cron status         → not running
sudo                        → password required (agent cannot)
RAM 7.6 GiB · / ext4 737 GiB free · C: 3.8 GiB free (100 %)
Windows Defender real-time  → True
python 3.10.12 · gcc 11.4 · git, make, jq, curl present
clamscan/clamdscan/freshclam/yara/inotifywait → MISSING
```

## Blocking decision

T001 needs the operator to run `scripts/install-system.sh` with sudo. Nothing downstream
(T003, T009, T011) can be verified until then. T002/T004/T005/T006/T007/T008/T010 can proceed
with fakes/fixtures.

## Next action

1. Get operator approval for the install plan (explained step by step).
2. Implement T002 (skeleton) — no privileges required.
3. Implement engines against fixtures; only `T011` needs the real machine.
