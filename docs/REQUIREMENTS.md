# Requirements

Derived from the operator's nine stated needs. `FR-n` maps 1:1 to need *n*.

## Functional

### FR-1 — ClamAV installed, signatures updated nightly
- `clamd`, `clamdscan`, `freshclam`, `clamscan` present and version-reported by `myav doctor`.
- Nightly signature update runs unattended and logs to `~/.local/state/myav/logs/freshclam.log`.
- `myav doctor` reports signature age and **fails** if older than 48 h.
- Update failures are surfaced in the next report; they never silently pass.
- AC: `freshclam` runs at 02:30 local, exit 0, DB timestamp < 24 h afterwards.

### FR-2 — YARA rule pack from a reputable public source
- Rules are pinned to a specific upstream commit; provenance (URL, commit, SHA-256 of archive)
  is recorded in `rules/PROVENANCE.json`.
- Rules are **not** vendored into git; `scripts/fetch-yara.sh` fetches and verifies the pin.
- Compilation is validated at fetch time; a rule that fails to compile aborts the fetch.
- AC: `myav doctor` prints rule count, pack commit, and compile status.

### FR-3 — Watcher for Downloads, Desktop, USB drives
- Watches `~/Downloads` and `~/Desktop` recursively via inotify (`watchdog`).
- Detects newly mounted volumes under `/mnt/*` (excluding `/mnt/c`, `/mnt/wsl*`) and watches them.
- Handles: create, move-into, rename, and modify-after-write (settle window to avoid partial reads).
- Survives a file being deleted before scan (records `vanished`, not an error).
- AC: a file dropped in `~/Downloads` is scanned within 10 s of the write closing.

### FR-4 — On every new file: ClamAV → YARA → VirusTotal hash lookup
- Pipeline order is fixed and short-circuits on MALICIOUS (YARA still runs for attribution only when cheap).
- VirusTotal is **hash-only** (`GET /files/{sha256}` and md5 fallback). No upload endpoint exists in the codebase.
- VT is opt-in: disabled with `UNKNOWN` verdict until a key is configured; never blocks a verdict.
- Rate limit respected (4 requests/min, 500/day on free tier) with a persistent cache.
- AC: with VT unconfigured, a clean file still produces `CLEAN` (clamav+yara) and `vt: not-configured`.
  With a key, a known-bad hash returns `MALICIOUS` from cache without re-querying.

### FR-5 — Flagged files go to quarantine; never delete without asking
- Quarantine move is *verify-then-unlink*: hash before, copy, fsync, hash after, then unlink source.
- Hash mismatch, permission failure, or cross-device error **must not** delete anything; file is left in place and reported.
- Each quarantined item gets a sidecar JSON: original path, size, mode, mtime, sha256, engine evidence, timestamp.
- `myav restore <id>` restores byte-identically to the original path (or `--to`), refusing to overwrite.
- `myav purge` requires `--yes` and prints what it will remove.
- AC: EICAR quarantined → source gone → `restore` → sha256 equals original.

### FR-6 — Startup inventory with new-entry alerting
- Enumerates Windows startup entries read-only (`Win32_StartupCommand`, plus `HKCU`/`HKLM` Run keys)
  and Linux autostart (`~/.config/autostart/*.desktop`, `/etc/xdg/autostart/*.desktop`).
- Persists a baseline; a diff of *new* entries is reported and marked as an alert.
- Read-only: `myav` never writes registry keys or disables startup items.
- AC: adding a fake `.desktop` file to `~/.config/autostart/` produces exactly one "new startup entry" alert.

### FR-7 — Full scan every Sunday at 03:00
- Scheduled outside WSL (Windows Task Scheduler) because systemd is offline in this distro.
- Missed runs execute on next wake ("run as soon as possible after a missed start").
- Scan scope is explicit and configurable; default excludes `/mnt/c` (9p, 3.8 GiB free) and `/proc`,`/sys`,`/dev`.
- AC: task exists, is enabled, next-run-time is the coming Sunday 03:00, and a manual trigger completes.

### FR-8 — Plain-English report after every scan
- Markdown report in `~/.local/state/myav/reports/YYYY-MM-DD-HHMM-<kind>.md`.
- Fixed sections: what ran, what was scanned, what was found, what was quarantined, what needs your attention.
- No unexplained jargon: every signature/rule name is annotated with its engine.
- AC: report renders in a terminal and lists counts + the quarantine table + signature age.

### FR-9 — Proven with EICAR
- `myav selftest --eicar` writes EICAR to a temp dir, scans, asserts MALICIOUS + quarantine + restore + hash match, then cleans up.
- The test must pass on the real machine, not only in CI.
- AC: `make verify-live` exits 0 and prints the assertion table.

## Non-Functional

- **Performance**: watcher end-to-end ≤ 10 s for files ≤ 10 MiB; full scan documented as files/min on declared scope. `clamd` is used for per-file scans (avoids reloading ~250 MiB of signatures per file).
- **Security**: config `0600`; no secrets in repo/logs; quarantine dir `0700`; VT key redacted from all output; no shell interpolation of filenames (`subprocess` argv lists only).
- **Safety**: every destructive operation is gated; default behaviour on any ambiguity is "leave the file alone and report it".
- **Resource limits**: max file size for YARA (default 100 MiB), per-file timeout 60 s, bounded scan queue.
- **Observability**: structured JSONL log (`~/.local/state/myav/logs/myav.jsonl`) plus human report.
- **Maintainability**: pure Python 3.10, no compilation step; each engine adapter independently testable; ≥ 80 % coverage.

## Constraints

- Language: Python 3.10.12 (system interpreter; `venv` at `.venv/`).
- Platform: WSL2 Ubuntu 22.04, systemd offline, cron not running, sudo needs a password.
- Deployment: source install in `/opt/myav` (operator-owned), no root-owned Python packages.
- Dependencies (runtime): `watchdog`, `tomli` (3.10 TOML read). Optional: `yara-python`.
- Dependencies (system, operator-installed): `clamav`, `clamav-daemon`, `yara`.
- No network egress except: `freshclam` mirrors, the pinned YARA pack URL, VirusTotal API.
