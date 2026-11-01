# Requirements

Derived from the operator's nine stated needs. `FR-n` maps 1:1 to need *n*.

This page describes **what MYAV Core actually does**. Where a requirement is only
partially met, the gap is stated in the requirement itself rather than hidden in a
footnote. Research items (behavioural baselines, ML, sandboxing) are not requirements
for Core and are listed in [PROJECT_STATUS.md](../PROJECT_STATUS.md).

---

## Functional

### FR-1 — ClamAV installed, signatures updated nightly

- `clamd`, `clamdscan`, `freshclam`, `clamscan` are detected and version-reported by
  `myav doctor`.
- The daily 02:30 job runs `myav update-signatures`, which prefers the packaged
  `clamav-freshclam` service and falls back to calling `freshclam` directly. Output is
  captured by the scheduler's log files under `~/.local/state/myav/logs/`.
- `myav doctor` reports signature version and age, and marks a database older than **48 h**
  as `warn` (stale). A stale database is recorded as `degraded` in every subsequent report.
- Update failures are printed and returned as a non-zero exit; they are never silently
  swallowed. The next report's **Needs your attention** section shows the stale age.
- AC: `freshclam` runs at 02:30 local, exits 0, and the database timestamp is < 24 h old
  afterwards. Verified by `myav doctor` and `scripts/verify-live.sh`.

### FR-2 — YARA rule pack from a reputable public source

- Rules are pinned to a specific upstream commit; provenance (repository, commit, archive
  SHA-256, file list) is recorded in `PROVENANCE.json` inside the rules directory.
- Rules are **not** vendored into git. `myav rules fetch --accept-license` downloads the
  pinned commit; `--update` is required to move to a newer commit.
- Compilation is validated at fetch time. A rule file that fails to compile is **skipped
  and reported per file**; it does **not** abort the fetch. This is deliberate: YARA 4.1.3
  (Ubuntu 22.04) rejects syntax used by newer rules, and discarding the whole pack because
  of one file would leave the user with no YARA coverage at all.
- `myav rules status` and `myav doctor` print rule-file count, pack commit, and whether a
  compiled cache exists.
- AC: `myav rules fetch --accept-license` writes rules and `PROVENANCE.json`;
  `myav rules status` shows the commit and compile state.

### FR-3 — Watcher for Downloads, Desktop, Documents, USB drives

- Watches every directory in `watcher.watch_dirs` (default `~/Downloads`, `~/Desktop`,
  `~/Documents`) recursively through `watchdog` (inotify / FSEvents /
  `ReadDirectoryChangesW`).
- Polls `/proc/mounts` every 5 s and adds new removable mounts. A mount is treated as
  removable when it is under `/mnt/` (excluding `/mnt/c` and WSL-internal names) or under
  `/media` / `/run/media`.
- Handles create, move-into, rename, and modify-after-write using a settle window
  (`watcher.settle_seconds`, default 2 s) so partial downloads are not scanned.
- A file that disappears before the scan is recorded as `vanished`, not as an error.
- Events are de-duplicated by content hash within a run. A full queue drops events but
  **counts and reports** the drop; nothing is silently ignored.
- AC: a file dropped in `~/Downloads` is scanned after the settle window; manual
  `myav watch --once` proves the same path without a daemon.

### FR-4 — On every new file: ClamAV → YARA → VirusTotal hash lookup

- Pipeline order is fixed: hash → allowlist → ClamAV → YARA → VirusTotal (only when a key
  is configured). All configured engines run; MYAV does not short-circuit on the first
  finding, because corroborating evidence belongs in the report.
- VirusTotal is **hash-only**: the only request is `GET /api/v3/files/{sha256}`. No upload
  endpoint, no request body, no filename, no path.
- VirusTotal is **off by default**. With no key the engine is skipped with
  `not-configured`; the verdict is produced from ClamAV + YARA and is **not** downgraded to
  UNKNOWN. A configured VT error that leaves no other evidence is what produces UNKNOWN.
- Rate limits are respected (default 4 requests/minute, 500/day) and cached with separate
  positive/negative TTLs.
- AC: without a key, a clean file returns `CLEAN` from ClamAV + YARA with
  `virustotal: not-configured`. With a key, a known hash is answered from cache on the
  second scan without another request.

### FR-5 — Flagged files go to quarantine; never delete without asking

- Quarantine is **verify-then-move-then-verify**: hash the source, move it (atomic
  `os.rename` on the same filesystem; copy → fsync → hash → unlink across filesystems),
  set mode `0000`, hash the stored payload, and compare.
- On any mismatch, permission failure, or cross-device error, **nothing is deleted**: the
  source stays in place, the record is marked `partial`, and the report says so.
- Metadata (original path, size, mode, mtime, sha256, verdict, evidence, timestamp) is
  stored in the SQLite state database — not in a sidecar JSON file.
- `myav quarantine restore <id>` re-verifies the payload hash, refuses to overwrite by
  default (`--force` required), and restores mode and mtime.
- `myav quarantine purge <id>` requires `--yes`; without it, it prints what it *would*
  delete and changes nothing.
- AC: EICAR is detected, quarantined, the source is gone, and restore returns a
  byte-identical file.

### FR-6 — Startup inventory with new-entry alerting

- Enumerates, read-only:
  - **Windows (from WSL or native):** `HKCU`/`HKLM` `Run` and `RunOnce` keys via `reg.exe`,
    plus the CIM `Win32_StartupCommand` list via `powershell.exe`.
  - **Linux:** `~/.config/autostart/*.desktop` and `/etc/xdg/autostart/*.desktop`.
  - **macOS:** `~/Library/LaunchAgents` (and a note that Full Disk Access may be needed).
- The first run records a baseline and flags nothing. Later runs diff against it and mark
  **new** entries. `myav boot` exits `11` when new entries are present.
- Read-only: MYAV never writes registry keys, never disables an entry, never removes a
  `.desktop` file.
- If `reg.exe`/`powershell.exe` is unreachable, the output says the surface was not
  enumerated instead of pretending the list was empty.
- AC: adding a fake `.desktop` file to `~/.config/autostart/` produces exactly one new-entry
  alert on the next `myav boot`.

### FR-7 — Full scan every Sunday at 03:00

- Four recurring jobs are rendered per platform:
  - `myav-watch` — at login, user.
  - `myav-nightly` — daily 02:30, signature update.
  - `myav-weekly` — Sunday 03:00, full scan.
  - `myav-clamd` — at login/boot, where the platform needs it.
- Linux uses **systemd user timers** with `Persistent=true`; macOS uses launchd; Windows and
  WSL use Task Scheduler. On WSL without systemd, MYAV writes a PowerShell script that the
  operator runs from Windows; it registers tasks with `-StartWhenAvailable` so a missed run
  happens after wake.
- **Missed-run guarantee is platform-specific:** systemd (`Persistent=true`) and Task
  Scheduler (`StartWhenAvailable`) catch up; launchd does not have an equivalent and a
  sleeping Mac may miss the run.
- Scan scope is explicit and configurable. Default is the watch directories plus removable
  mounts. `/mnt/c` is excluded; `/proc`, `/sys` and `/dev` are never in scope because the
  scope is a positive list, not a filesystem walk.
- AC: `myav schedules status` shows the jobs; a manual `myav full-scan` completes and writes
  a report.

### FR-8 — Plain-English report after every scan

- Markdown report at `~/.local/state/myav/reports/YYYY-MM-DD-HHMM-<kind>.md`.
- Fixed sections: **What ran**, **What was scanned**, **What was found**,
  **What is quarantined**, **Needs your attention**, **How to read this report**.
- Counts reconcile: `scanned == clean + suspicious + malicious + unknown + skipped`.
- Every finding names its engine (`clamav:`, `yara:`, `virustotal:`) and its evidence.
- A clean report never says "safe"; it says what was checked and what CLEAN does not mean.
- AC: the report renders in a terminal and lists counts, evidence, quarantine state and
  signature age.

### FR-9 — Proven with EICAR

- `myav selftest` writes the harmless EICAR test string to a temporary sandbox, hashes it,
  scans it, asserts MALICIOUS, checks the source was removed, verifies the quarantined
  payload hash (after `chmod 600`, because payloads are stored `0000`), restores it, and
  verifies the restored bytes. It then removes its own artefacts.
- There is **no `--eicar` flag**; the command is always the EICAR self-test.
- The test must pass on the real machine, not only in CI. If ClamAV is missing, or Windows
  Defender removes the file before MYAV scans it, the result is `INCONCLUSIVE` (exit `5`),
  never a false PASS.
- AC: `./scripts/verify-live.sh` reports the self-test result, and a PASS means the full
  detect → quarantine → restore chain worked.

---

## Non-Functional

- **Performance:** the watcher scans after `settle_seconds` (default 2 s); `clamd` is
  preferred for per-file scans to avoid reloading signatures. Full-scan throughput has
  **not been measured on a large dataset** and no number is claimed. Measure it on your
  machine with `myav full-scan` and read the duration in the report.
- **Security:** config `0600`; MYAV-owned directories `0700`; no secrets in the repository,
  logs, reports or `--json` output; VT key redacted unless `--reveal` is passed; no shell
  interpolation of filenames (`subprocess` argv lists only).
- **Safety:** every destructive operation is gated; the default on any ambiguity is "leave
  the file alone and report it". Detection never deletes.
- **Resource limits:** YARA skips files above `yara.max_scan_bytes` (default 100 MiB);
  per-file engine timeout 60 s; the watcher queue is bounded and reports drops.
- **Observability:** the human-readable Markdown report is the primary surface, backed by
  the SQLite scan history (`myav report --json`, `myav quarantine list --json`). A
  structured JSONL log is **not implemented**; this was in the original plan and is listed
  as a gap rather than implied.
- **Maintainability:** pure Python 3.10+, no compilation step; each engine adapter is
  independently testable; coverage gate is 80 %, actual coverage is ~94 %.

---

## Constraints

- Language: Python 3.10+ (system interpreter; `venv` at `.venv/`).
- Validated platform: **Linux and WSL2 Ubuntu 22.04**. macOS and native Windows adapters
  exist but are experimental; Android/iOS are companion design only. See
  [PLATFORMS.md](PLATFORMS.md).
- Reference machine had systemd offline and cron not running; this is why the WSL path
  uses Windows Task Scheduler. On a normal Linux system, systemd user timers are used.
- Deployment: source install (operator-owned directory) or `pip install -e .`; no root-owned
  Python packages.
- Dependencies (runtime): `watchdog`, `tomli` (Python < 3.11 only). Optional: `yara-python`.
- Dependencies (system, operator-installed): `clamav`, `clamav-daemon`,
  `clamav-freshclam`, `yara`.
- No network egress except: ClamAV signature mirrors (via `freshclam`), the pinned YARA
  pack on GitHub (only after `--accept-license`), and VirusTotal (only when a key is set).
  See [PRIVACY.md](PRIVACY.md).

---

## Traceability

| Need | Requirement | Implementation | Proof |
|---|---|---|---|
| 1 | FR-1 | `engines/clamav.py`, `cli.cmd_update_signatures`, `scheduler.py` | `myav doctor`, `verify-live.sh` |
| 2 | FR-2 | `rules.py`, `cli.cmd_rules_*` | `tests/test_rules.py`, `myav rules status` |
| 3 | FR-3 | `watcher.py`, `paths.discover_removable_mounts` | `tests/test_watcher.py` |
| 4 | FR-4 | `pipeline.py`, `engines/*` | `tests/test_pipeline.py`, `tests/test_engines.py` |
| 5 | FR-5 | `quarantine.py`, `state.py` | `tests/test_quarantine.py` |
| 6 | FR-6 | `bootwatch.py` | `tests/test_bootwatch.py` |
| 7 | FR-7 | `scheduler.py` | `tests/test_scheduler.py` |
| 8 | FR-8 | `report.py` | `tests/test_report.py` |
| 9 | FR-9 | `selftest.py`, `scripts/verify-live.sh` | `tests/test_selftest.py` |
