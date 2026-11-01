---
ticket: T001
title: Install ClamAV + YARA system dependencies (operator-run)
sprint: sprint-01
priority: high
status: blocked
created: 2026-11-01
tier: AES-heavy
---

# T001 — System dependency install

## Context

Nothing is installed: `clamscan`, `clamdscan`, `freshclam`, `clamd`, `yara` all MISSING.
`sudo` requires a password, so the agent cannot install. This ticket produces a reviewed,
idempotent script that the **operator** runs, then verifies the result.

## Acceptance Criteria

- [ ] `dpkg -l` shows `clamav`, `clamav-daemon`, `clamav-freshclam`, `yara` installed
- [ ] `clamscan --version`, `clamdscan --version`, `freshclam --version`, `yara --version` all exit 0
- [ ] `/var/lib/clamav/*.cvd|cld` present and < 24 h old after first `freshclam`
- [ ] `clamd` reachable on `127.0.0.1:3310` (fallback: unix socket `/run/clamav/clamd.ctl`)
- [ ] `myav doctor --only system` reports all engines OK
- [ ] No writes outside `/var/lib/clamav`, `/var/log/clamav`, `/etc/clamav`, `~/.local`
- [ ] Script is idempotent (safe to re-run) and honours `--dry-run`

## Scope

**In scope:** `scripts/install-system.sh` (apt install, clamd TCP loopback drop-in, service start
via `wsl.exe -u root` since systemd is offline), `myav doctor`.

**Out of scope:** YARA rule download (T004), scheduling (T009), any Defender change.

## Dependencies

Operator approval + sudo password. Nothing else.

## Rollback

`sudo apt remove clamav clamav-daemon clamav-freshclam yara` + restore
`/etc/clamav/clamd.conf` from the `.bak` the script writes. Script prints the exact rollback.

## Known Risks

- `apt` pulls ~500 MiB (signature DB). Space is fine on ext4 (737 GiB).
- Enabling clamd TCP on loopback exposes an unauthenticated local scan API. Single-user machine
  → accepted; documented in THREAT_MODEL B8. Unix-socket mode available via config.
- First `freshclam` may be rate-limited by mirror (HTTP 429) → retry with backoff.

## Notes

Ubuntu 22.04 ships ClamAV 0.103; `clamdscan --stream` is available. Debian's daemon unit is
systemd-only, so `service clamav-daemon start` will fail — start `clamd` directly with
`clamd --foreground` under the supervisor.
