# Architecture

## 1. Shape

```
                       ┌──────────────────────────────┐
  Windows Task Scheduler│  myav-nightly 02:30 (root)  │
                       │  myav-weekly   Sun 03:00    │
                       │  myav-watch    at logon     │
                       └──────────────┬───────────────┘
                                      │ wsl.exe -d Ubuntu -u …
                                      ▼
┌──────────────────────────────────────────────────────────────────┐
│ bin/myav (launcher) → python -m myav.cli                         │
│                                                                  │
│  watch ──► watcher.py ──► queue ──► pipeline.py ──► verdict.py   │
│                                        │                         │
│              ┌─────────────────────────┼──────────────────────┐  │
│              ▼                         ▼                      ▼  │
│        engines/clamav.py       engines/yara.py    engines/virustotal.py
│        (clamdscan→clamscan)    (yara-python→CLI)  (hash GET only)
│              └─────────────────────────┼──────────────────────┘  │
│                                        ▼                         │
│                                   quarantine.py                  │
│                                   (verify → move → sidecar)      │
│                                        ▼                         │
│                                    report.py                     │
└──────────────────────────────────────────────────────────────────┘
        │                    │                     │
   ~/.config/myav/     ~/.local/state/myav/    ~/.local/share/myav/
   config.toml 0600    logs, reports, state.db  quarantine/ 0700
```

## 2. Modules

| Module | Responsibility | Must never |
|--------|----------------|-----------|
| `cli.py` | argparse dispatch, exit codes, `--json` | contain policy logic |
| `config.py` | load/validate `config.toml`, defaults, env overrides | log the VT key |
| `paths.py` | XDG dirs, WSL mount discovery, `/mnt/*` classification | create dirs with mode > 0700 for quarantine |
| `state.py` | SQLite: scans, verdicts, quarantines, baseline, vt_cache | store file contents |
| `hash.py` | sha256 + md5 streaming | load whole file |
| `engines/clamav.py` | `clamdscan --stream --fd`-style scan; fallback `clamscan` | invoke a shell |
| `engines/yara.py` | compile/scan with size cap + timeout | follow symlinks outside scope |
| `engines/virustotal.py` | hash GET, rate limit, cache | POST/PUT, or send bytes |
| `verdict.py` | fuse evidence into CLEAN/SUSPICIOUS/MALICIOUS/UNKNOWN | downgrade MALICIOUS |
| `quarantine.py` | verify-then-move, sidecar, restore, purge | unlink on any mismatch |
| `watcher.py` | inotify observers, settle window, mount polling | scan files under `/mnt/c` |
| `bootwatch.py` | read-only startup enumeration + baseline diff | write registry / disable entries |
| `report.py` | plain-English markdown | invent findings |
| `selftest.py` | EICAR end-to-end assertions | touch the real quarantine dir |

## 3. Verdict model

| Verdict | Trigger | Exit code | Quarantine? |
|---------|---------|-----------|-------------|
| `MALICIOUS` | ClamAV FOUND with a signature, or YARA match on a rule with `severity >= 7`, or VT positives ≥ 3 | 10 | yes |
| `SUSPICIOUS` | VT positives 1–2, or YARA severity 4–6, or scanner error on a file > 0 bytes | 11 | yes, tagged `suspicious` |
| `UNKNOWN` | engines unavailable / file unreadable / VT not configured | 12 | no |
| `CLEAN` | all configured engines ran and none fired | 0 | no |

Fusion rule: **maximum severity wins**; absence of evidence is never reported as clean.
A scanner error is `UNKNOWN`, never `CLEAN`.

## 4. Quarantine protocol (the "never delete" guarantee)

```
sha256_before = hash(path)
if same-filesystem:  os.rename(path, qdir/id)        # atomic
else:                copy → fsync(file) → fsync(dir) → verify hash → unlink source
sha256_after  = hash(qdir/id)
if sha256_after != sha256_before:
    keep BOTH, do not unlink source, verdict = UNKNOWN, alert operator
write qdir/id.json (original path, hashes, evidence, ts, mode, mtime)
```

`restore` verifies `sha256(qdir/id) == sidecar.sha256` before writing, refuses to overwrite,
and re-hashes after. `purge` is the only delete path and requires `--yes`.

## 5. Scheduling decision (systemd offline)

Verified: `systemctl is-system-running` → `offline`; `service cron status` → not running.

Chosen: **Windows Task Scheduler** driving `wsl.exe -d Ubuntu`.

| Task | Schedule | User | Command |
|------|----------|------|---------|
| `myav-clamd` | at logon | root | `myav inner clamd-start` |
| `myav-nightly` | 02:30 daily | root | `myav inner update-sigs` |
| `myav-watch` | at logon | rodolfo | `myav inner watch-loop` |
| `myav-weekly` | Sunday 03:00 | rodolfo | `myav full-scan --report` |

Rejected alternatives:
- **systemd in WSL** (`/etc/wsl.conf` + `wsl --shutdown`): requires a distro restart, still needs a
  Windows-side trigger to start the distro at logon, and adds a system-wide change for no scheduling gain.
- **cron started from `.profile`**: dies with the WSL session, no run-at-logon, no missed-run catch-up.
- **A resident daemon polling the clock**: duplicates the OS scheduler, fragile across WSL shutdowns.

## 6. Scopes

| Scope name | Paths | Default in |
|------------|-------|------------|
| `home` | `~/Downloads`, `~/Desktop`, `~/Documents`, `/opt/myav` | watch, full-scan |
| `usb` | `/mnt/*` except `c`, `wsl`, `wslg`, `host` | watch, full-scan |
| `windows` | `/mnt/c/Users/*/Downloads`, `/mnt/c/Users/*/Desktop` | **off** (9p slow, 3.8 GiB free, Defender covers it) |

## 7. Failure modes we design for

- `clamd` down → fallback `clamscan` (slower), report degraded.
- Signature age > 48 h → `degraded: stale-signatures` in every report.
- YARA pack missing → YARA stage reported `skipped-missing-rules`, not `clean`.
- VT unconfigured / rate-limited / offline → `vt: unavailable`, verdict still produced.
- Watcher restart → no duplicate quarantine (idempotent by sha256).
- WSL shutdown mid-scan → scan marked `aborted`; nothing partially quarantined (move is atomic).
