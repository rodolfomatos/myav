# Architecture

This page explains how MYAV is put together and **why** each part is shaped that way. If
you only read one section, read §3 (verdicts) and §4 (quarantine): those are the two places
where a mistake would hurt you.

---

## 1. Shape

The trigger differs by platform; everything below the trigger is the same code.

```
  Linux:   systemd user timers          WSL:   Windows Task Scheduler
           (watch, 02:30, Sun 03:00)           (same jobs, via wsl.exe)
  macOS:   launchd agents               Windows: Task Scheduler
  Manual:  myav scan / full-scan / watch
                          │
                          ▼
┌──────────────────────────────────────────────────────────────────┐
│ bin/myav  →  python -m myav.cli                                  │
│                                                                  │
│  watch ──► watcher.py ──► pipeline.py ──► verdict.py             │
│                             │                                    │
│              ┌──────────────┼──────────────────┐                 │
│              ▼              ▼                  ▼                 │
│        engines/clamav.py  engines/yara.py  engines/virustotal.py │
│        (clamdscan→         (yara-python→    (hash GET only,      │
│         clamscan)           yara CLI)        off by default)     │
│              └──────────────┼──────────────────┘                 │
│                             ▼                                    │
│                        quarantine.py                             │
│                        (verify → move → verify)                  │
│                             ▼                                    │
│                         report.py                                │
└──────────────────────────────────────────────────────────────────┘
        │                    │                     │
   ~/.config/myav/     ~/.local/state/myav/    ~/.local/share/myav/
   config.toml 0600    reports, state.db,      quarantine/ 0700
                       logs/
```

*Figure 1 — one pipeline, many triggers. The boxes are modules in `src/myav/`.*

The important property: **there is exactly one scan path**. A scheduled scan, a manual scan
and a watcher event all call `pipeline.scan_file`. There is no "fast path" that skips the
quarantine protocol.

---

## 2. Modules

| Module | Responsibility | Must never |
|--------|----------------|-----------|
| `cli.py` | argparse dispatch, output, exit codes | contain policy logic |
| `config.py` | load/validate `config.toml`, defaults, env overrides | log or echo the VT key |
| `paths.py` | XDG/macOS/Windows directories, mount discovery, `/mnt/c` write guard | create a MYAV directory looser than `0700` |
| `state.py` | SQLite: scans, verdicts, quarantine records, allowlist, boot baseline, VT cache | store file contents |
| `hashutil.py` | streamed SHA-256 / MD5 | load a whole file into memory |
| `engines/clamav.py` | `clamdscan` (daemon) with `clamscan` fallback; signature version/age | invoke a shell |
| `engines/yara.py` | `yara-python` with CLI fallback; size cap and timeout | follow symlinks outside scope |
| `engines/virustotal.py` | hash `GET`, rate limits, cache | POST/PUT, or send any bytes |
| `verdict.py` | fuse engine results into one level | downgrade MALICIOUS, or turn an error into CLEAN |
| `quarantine.py` | verify-then-move-then-verify, restore, purge | unlink on any mismatch |
| `watcher.py` | filesystem observers, settle window, mount polling, bounded queue | scan `/mnt/c` |
| `bootwatch.py` | read-only startup enumeration and baseline diff | write the registry or disable an entry |
| `report.py` | Markdown report with reconciling counts | invent a finding, or print "safe" |
| `scheduler.py` | render systemd/launchd/Task Scheduler artefacts | write root-level units, or apply anything without `--yes` |
| `selftest.py` | EICAR detect → quarantine → restore proof | touch the real quarantine directory |
| `pipeline.py` | fixed scan order and the decision to quarantine | delete a file |

---

## 3. Verdict model

There are four outcomes. They are ordered by how much evidence exists, not by how scary
the name sounds.

| Verdict | What it means | Exit code | Quarantine? |
|---------|---------------|-----------|-------------|
| `MALICIOUS` | ClamAV named a malware signature, a high-severity YARA rule fired, or VirusTotal reports ≥ 3 positives | 10 | yes |
| `SUSPICIOUS` | A medium-severity YARA rule fired, or VirusTotal reports 1–2 positives | 11 | yes, tagged `suspicious` |
| `UNKNOWN` | A **primary** engine could not run, the file could not be read, or no engine produced evidence | 12 | no |
| `CLEAN` | Every configured engine ran and none fired | 0 | no |

Fusion rules, in normative order (`src/myav/verdict.py`):

1. **Maximum severity wins:** `MALICIOUS > SUSPICIOUS > UNKNOWN > CLEAN`.
2. **An error never becomes CLEAN.** An engine error maps to `UNKNOWN`.
3. **A skipped primary engine (ClamAV) yields `UNKNOWN`.** MYAV does not call a file clean
   when its strongest engine was blind.
4. **A skipped or failed secondary engine yields `CLEAN` plus a `degraded` entry.** YARA
   or VirusTotal being unavailable is a gap in evidence, not a finding; the report is
   required to display it.
5. **Stale signatures are degraded evidence.** A database older than 48 h is recorded in
   every report, even if the scan is otherwise clean.
6. **No engine at all yields `UNKNOWN`** with the reason `no engine produced evidence`.

Two consequences that are easy to miss:

- A directory scan returns the **worst** verdict found, so one malicious file makes the
  whole command exit `10`.
- `SUSPICIOUS` also quarantines. That is deliberate: a medium-confidence hit is still a
  reason to stop a file from running, and quarantine is reversible.

---

## 4. Quarantine protocol (the "never delete" guarantee)

The rule is simple to state and fiddly to implement: **a file may only leave its original
location after an identical copy exists and has been verified.**

```
sha256_before = hash(path)
if same filesystem:
    os.rename(path, qdir/<uuid>.bin)          # atomic
else:
    copy → fsync(file) → fsync(dir) → verify hash → unlink source
chmod(qdir/<uuid>.bin, 0000)
sha256_after = hash(qdir/<uuid>.bin)          # chmod 600 first, then hash
if sha256_after != sha256_before:
    keep BOTH copies
    mark record "partial"
    do NOT unlink the source
    report the mismatch
    verdict becomes UNKNOWN for that file
write the record (path, size, mode, mtime, sha256, verdict, evidence, timestamp)
           to the SQLite state database
```

*Figure 2 — the quarantine protocol. Metadata lives in SQLite, not in a sidecar file, so a
half-written JSON cannot lie about a payload.*

`restore` re-verifies the payload hash before writing, refuses to overwrite unless `--force`
is passed, restores mode and mtime, and flushes the write before the rename. `purge` is the
only delete path in the entire program and requires `--yes`; without it, it prints what it
*would* remove.

Why so much ceremony for a move? Because the two failure modes that destroy user data are
(a) deleting before the copy is safe and (b) silently matching the wrong file. Both are
explicitly tested (`tests/test_quarantine.py`).

---

## 5. Scheduling

MYAV's four jobs:

| Job | When | Privilege |
|---|---|---|
| watcher | at login, continuous | user |
| signature update | daily 02:30 | root (system database) |
| full scan | Sunday 03:00 | user |
| `clamd` | at boot/login, where needed | root |

Per platform:

| Platform | Mechanism | Missed-run behaviour |
|---|---|---|
| Linux | systemd **user** timers | `Persistent=true` catches up after boot |
| WSL without systemd | Windows Task Scheduler via the generated PowerShell script | `-StartWhenAvailable` catches up after wake |
| WSL with systemd | systemd user timers | as Linux |
| macOS | launchd agents | **no catch-up**; a sleeping Mac can miss the run |
| Windows native | Task Scheduler | depends on task settings |

MYAV **renders** these artefacts; it does not secretly install them. `myav schedules print`
shows the content, `myav schedules install --yes` writes user-level files, and root-level
units are printed for the operator to install. This is the same privilege boundary as the
installer: the program never calls `sudo`.

Why not cron? It dies with the WSL session, has no run-at-login semantic, and no missed-run
catch-up. Why not a resident daemon polling the clock? It duplicates the OS scheduler and is
fragile across WSL shutdowns.

---

## 6. Scan scope

| Scope | Paths | In the default? |
|---|---|---|
| user folders | `watcher.watch_dirs` (default `~/Downloads`, `~/Desktop`, `~/Documents`) | yes |
| removable | mounts under `/media`, `/run/media`, and `/mnt/<letter>` (except `c` and WSL-internal names) | yes, when detected |
| `C:` | `/mnt/c/...` | **no** |

The scope is a **positive list**. MYAV never walks `/`. That is why `/proc`, `/sys` and
`/dev` need no special case: they were never in scope.

`/mnt/c` is excluded for three reasons: reading it through WSL's 9p filesystem is very
slow, MYAV refuses to **write** there (so it could not quarantine a finding), and Windows
Defender already covers it at kernel level. An explicit `myav scan /mnt/c/...` is allowed
read-only; the finding is reported with the action "reported only".

---

## 7. Failure modes designed for

| Failure | Behaviour |
|---|---|
| `clamd` down | fall back to `clamscan`; report slower path as degraded |
| signatures older than 48 h | `degraded: stale-signatures` in every report |
| YARA pack missing | YARA stage skipped and reported, not silently "clean" |
| YARA rule fails to compile | that file is skipped and named; other rules still run |
| VirusTotal unconfigured | skipped as `not-configured`; verdict unaffected |
| VirusTotal rate-limited / offline | skipped or error; verdict unaffected unless it was the only evidence |
| file vanishes before scan | recorded as `vanished`, not an error |
| file unreadable | `UNKNOWN` with the OS error, never `CLEAN` |
| watcher queue full | events dropped, **count reported** |
| WSL shutdown mid-scan | scan not recorded as complete; quarantine move is atomic, so no half-moved file |
| file changes between hash and move | hash-after mismatch keeps both copies and refuses to unlink |

---

## 8. Why this architecture and not another

| Alternative | Rejected because |
|---|---|
| Kernel driver / minifilter for blocking | Different risk profile; a bug takes the machine down. Out of scope (see [LIMITATIONS.md](LIMITATIONS.md) §1) |
| A single monolithic scan function | The quarantine and verdict rules would be untestable in isolation |
| JSON files for state | Concurrent writers and partial writes corrupt them |
| A server database | Absurd for a single-user local tool |
| Cron on WSL | No run-at-login, no catch-up, dies with the distro |
| Uploading files to VirusTotal for a better answer | Violates the privacy promise; the hash lookup is the maximum disclosure |
| Silently degrading when a capability is missing | Users would believe they had protection they do not have. The CLI exits `3` instead |

---

## 9. Data locations

| Platform | Config | State | Data | Cache |
|---|---|---|---|---|
| Linux / WSL | `~/.config/myav` | `~/.local/state/myav` | `~/.local/share/myav` | `~/.cache/myav` |
| macOS | `~/.config/myav` | `~/Library/Application Support/myav` | `~/Library/Application Support/myav` | `~/Library/Caches/myav` |
| Windows | `%APPDATA%\myav` | `%LOCALAPPDATA%\myav\state` | `%LOCALAPPDATA%\myav` | `%LOCALAPPDATA%\myav\cache` |

All MYAV-owned directories are `0700`; the config file is `0600`. The full inventory and
what each file contains is in [PRIVACY.md](PRIVACY.md) §6.

---

## 10. Related reading

- [THREAT_MODEL.md](THREAT_MODEL.md) — what MYAV defends against, and what attacks MYAV.
- [LIMITATIONS.md](LIMITATIONS.md) — the honest boundary of the design.
- [PLATFORMS.md](PLATFORMS.md) — which capability is proven where.
- [REQUIREMENTS.md](REQUIREMENTS.md) — the functional contract this architecture satisfies.
