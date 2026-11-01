# Changelog

All notable changes to MYAV are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Because this is a security tool, entries that change detection behaviour or a security
invariant are called out explicitly.

---

## [Unreleased]

### Added

- Phase 0 documentation set: research review, technology comparison, threat model,
  capability matrix, dependency and licence review, and the plan
  (`docs/research-review.md`, `docs/DEPENDENCIES.md`).
- Full public documentation: `README.md`, `docs/INSTALLATION.md`,
  `docs/CONFIGURATION.md`, `docs/RUNBOOK.md`, `docs/PLATFORMS.md`, `docs/LIMITATIONS.md`,
  `docs/PRIVACY.md`, `docs/TESTING.md`, `docs/RESEARCH_REFERENCES.md`,
  `docs/COMPANION_PROTOCOL.md`, `docs/FAQ.md`.
- `scripts/install-system.sh` — idempotent privileged installer, dry-run by default,
  supports apt/dnf/pacman/brew, configures `clamd` on loopback only, never calls `sudo`,
  never deletes.
- `scripts/verify-live.sh` — read-only health proof (CLI, doctor, rules, schedules,
  quarantine, EICAR).
- `SECURITY.md`, `CONTRIBUTING.md`, `PROJECT_STATUS.md`, `CHANGELOG.md`, `LICENSE`
  (Apache-2.0), `NOTICE`.
- SBOM and dependency inventory under `docs/sbom/` and `docs/DEPENDENCIES.md`.

### Security

- Self-test now `chmod`s a quarantined payload to `0600` before hashing it. Previously the
  verification step tried to read a mode-`0000` file and failed with `PermissionError`.
  The self-test was therefore unable to prove the "payload hash matches" assertion on a
  correctly quarantined file.
- Self-test no longer reports `INCONCLUSIVE` for a clean scan. A clean result is a real
  failure of the chain (exit `1`); `INCONCLUSIVE` is reserved for the case where the test
  file vanished before scanning (typically Windows Defender on WSL) or ClamAV is absent.
  The old behaviour could have hidden a broken detection chain behind an "inconclusive"
  label.

### Fixed

- Scheduler tests no longer write into the real home directory; the launchd status test now
  uses a temp home. A test artefact at `/home/<user>/Library/LaunchAgents` was created and
  is now prevented by construction.
- Test configuration for coverage pointed at `src` rather than the `myav` package. Coverage
  now measures `myav` and reports ~94%.

---

## [0.1.0] — 2026-11-01

First working Core release. Everything below is implemented and covered by the test suite
(259 tests, ~94% coverage, `ruff` clean).

### Added — scanning

- `myav scan PATH...` — scan files or folders immediately.
- `myav full-scan [PATH...]` — scan the default scope (`~/Downloads`, `~/Desktop`,
  `~/Documents`, removable mounts) and write a plain-English report.
- `--dry-run` on both commands: detect but never move a file.
- `--json` output on every command for scripting.

### Added — engines

- **ClamAV engine**: prefers `clamdscan` (daemon), falls back to `clamscan`; parses
  `FOUND` / `OK` / error output; reports signature version and age; marks a database older
  than 48 hours as stale.
- **YARA engine**: uses `yara-python` when available, otherwise the CLI; maps rule severity
  metadata to `MALICIOUS` / `SUSPICIOUS` thresholds; skips files above `max_scan_bytes`;
  reports per-file compile failures instead of dropping the pack.
- **VirusTotal engine**: hash-only lookup (`GET /api/v3/files/<sha256>`), off by default,
  requires a 64-hex-character key, respects per-minute and per-day limits, caches positive
  and negative results with separate TTLs, never uploads a file.

### Added — verdict fusion

- Explicit severity order: `MALICIOUS > SUSPICIOUS > UNKNOWN > CLEAN`.
- An engine error never produces `CLEAN`.
- A skipped **primary** engine (ClamAV) produces `UNKNOWN`.
- A skipped or failed **secondary** engine produces `CLEAN` plus a `degraded` entry that
  every report must display.
- Stale signatures are recorded as degraded evidence.
- Exit codes are part of the contract: `0/1/2/3/4/5/10/11/12`.

### Added — quarantine

- Suspicious and malicious files are **moved**, not deleted.
- Payloads stored under a random `uuid4` name with extension `.bin`, mode `0000`.
- Hash recorded before the move, verified again after; a mismatch keeps both copies and
  refuses to unlink.
- `myav quarantine list [--all] [--json]`.
- `myav quarantine restore <id> [--to PATH] [--force]` — re-verifies the hash, refuses to
  overwrite by default, restores mode and mtime.
- `myav quarantine purge <id> --yes` — the only irreversible operation; without `--yes` it
  prints what it *would* delete.
- `myav allow add PATH --reason "..."` / `myav allow list` — hash-based allowlist checked
  before engines run.

### Added — watching

- `myav watch [--once] [--create-dirs]` — watches Downloads, Desktop, Documents and
  removable volumes.
- Debounce (`settle_seconds`, default 2 s) so partially written downloads are not scanned.
- De-duplication of identical content within a run.
- Bounded queue; dropped events are counted and reported, never silently ignored.
- Ignores its own quarantine, state, cache and temp directories.

### Added — persistence and reports

- SQLite (WAL) state: scan history, quarantine records, allowlist, startup baseline,
  VirusTotal cache.
- Markdown reports under `~/.local/state/myav/reports/`, with a reconciling count table,
  per-finding evidence (engine, signature or rule, sha256, action), quarantine summary,
  and an **Attention** section for degraded engines and read errors.
- `myav report`, `myav report --list`, `myav report --path FILE`.
- Report retention (`report.retention`, default 90), pruning only MYAV's own files.

### Added — startup inventory

- `myav boot [--json]` — read-only inventory of startup entries.
- Linux: `~/.config/autostart/*.desktop`, systemd user units.
- WSL: Windows registry `Run`/`RunOnce` keys and CIM list via `reg.exe` / `powershell.exe`,
  plus Linux desktop entries.
- macOS: LaunchAgents (notes Full Disk Access when relevant).
- Windows: registry `Run` keys and Startup folder.
- First run records a baseline without alerting; later runs flag **new** entries and exit
  `11`. Never disables anything, never writes to the registry.

### Added — scheduling

- `myav schedules print` / `install [--yes]` / `status [--json]`.
- Four jobs: watcher at login, signature update daily 02:30, full scan Sunday 03:00,
  `clamd` at login.
- systemd user units on Linux, launchd agents on macOS, Task Scheduler XML/script on
  Windows and WSL.
- User-level files are written; root-level units are **printed**, never written.
- Nothing is written unless `--yes` is passed.

### Added — self-test

- `myav selftest` — the EICAR end-to-end proof: write → hash → detect → quarantine →
  verify source gone → restore → verify byte-identical → clean up.
- `INCONCLUSIVE` (exit `5`) when the test file vanishes (Windows Defender on WSL) or
  ClamAV is absent. Never advises disabling Defender.

### Added — configuration

- Single TOML file at `~/.config/myav/config.toml`.
- `0600` enforced **before** parsing; MYAV refuses to read a file other users can read.
- `myav config show [--reveal] [--json]`, `myav config path`,
  `myav config set-vt-key [--key ...]` or `MYAV_VT_API_KEY`, with a non-echoing prompt.
- Validation for severity ordering, absolute watch paths, ports and rate limits.
- Key redacted by default in all output.

### Added — platform model

- Adapters for Linux, WSL2, macOS, Windows, Android and iOS, each declaring a capability
  set. Commands the platform cannot support exit `3` with an explanation instead of
  degrading silently.
- Per-platform data locations (XDG, Application Support, `LOCALAPPDATA`, app containers).
- `/mnt/c` is excluded from the default scope and refused as a write target.

### Added — diagnostics

- `myav doctor` — checks Python, platform, directory permissions, ClamAV, signatures and
  staleness, YARA rules, VirusTotal, free space, schedules; exits `1` on any FAIL.
- `myav platforms [--json]`, `myav version [--json]`.
- `MYAV_PLATFORM` override for testing and companion apps.

### Known limitations at this release

- Detection only; no blocking (user-space tool).
- No archive scanning.
- No memory/fileless/rootkit detection.
- Only Linux and WSL2 validated end-to-end; macOS and native Windows are experimental.
- No mobile app; the companion protocol is a design document.
- No release signing.

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for the full list and
[PROJECT_STATUS.md](PROJECT_STATUS.md) for what is next.
