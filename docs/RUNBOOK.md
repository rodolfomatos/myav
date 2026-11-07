# Runbook — what to do when MYAV speaks

This is the practical manual. [INSTALLATION.md](INSTALLATION.md) gets MYAV running;
this page is what you read afterwards, especially when something happens.

Read the first two sections once. Bookmark section 4 (alerts) — that is the part you
will need at 23:40 on a bad day.

---

## 1. The four verdicts, and what each one actually means

MYAV refuses to say "safe". It says one of four things. Learning these four words is
the whole mental model.

| Verdict | Exit code | Plain meaning | What you should do |
|---|---|---|---|
| **CLEAN** | `0` | No engine found anything known. **Not** a promise that the file is harmless. | Nothing. Keep going. |
| **SUSPICIOUS** | `11` | At least one engine fired, but with weaker evidence (a YARA rule at medium severity). | Read the evidence. If you did not expect the file, treat it as bad. |
| **MALICIOUS** | `10` | ClamAV named a known malware signature, or a high-severity rule fired. | The file was moved to quarantine. Read section 4. |
| **UNKNOWN** | `12` | An engine could not run, timed out, or the file could not be read. MYAV does not know. | Read the reason. Usually a missing daemon or a permission problem. |

Two rules follow from that table:

1. **CLEAN is evidence, not a guarantee.** A brand-new sample that nobody has seen
   before will come back CLEAN. That is a limit of signature scanning, not a bug.
2. **UNKNOWN is not CLEAN.** If ClamAV is down, MYAV says UNKNOWN. A tool that said
   CLEAN while blind would be worse than no tool.

The same mapping applies to files. A scan of many files returns the *worst* verdict it
found, so a folder with one MALICIOUS file exits `10` even if the other 499 are clean.

---

## 2. The commands you will actually use

```text
myav doctor                    health check — start here when anything is odd
myav scan PATH...              scan files or folders now
myav full-scan                 scan the default scope and write a report
myav report                    print the most recent report
myav report --list             list all saved reports
myav quarantine list           what is currently quarantined
myav quarantine restore ID     put a file back
myav allow add PATH --reason   mark a known-good file as trusted
myav intel update --name F --source URL   cache a threat-intel feed (opt-in)
myav intel check INDICATOR     look up one hash/URL/domain/IP offline
myav boot                      show startup entries and flag new ones
myav schedules status          are the recurring jobs installed?
```

`myav --help` and `myav <command> --help` explain every option. Nothing is hidden
behind an undocumented flag.

### The default scope

`myav full-scan` with no arguments scans:

- `~/Downloads`
- `~/Desktop`
- `~/Documents`
- removable volumes mounted under `/media`, `/run/media`, and (on WSL) `/mnt/<letter>`
  except `/mnt/c`

`/mnt/c` is excluded on WSL on purpose: it is slow to read through the 9p filesystem
and writing there is guarded. You can still scan a specific Windows path explicitly:

```bash
myav scan /mnt/c/Users/you/Downloads/somefile.exe
```

That is a one-off. MYAV will not quarantine anything on `C:` — it refuses to write
there — so a malicious file found on `C:` is reported, not moved. You must remove it
from Windows yourself. The report says so.

---

## 3. The morning routine

MYAV runs on its own. Your job is mostly reading.

### After a scheduled scan

```bash
myav report
```

The report is written in plain English and has the same shape every time:

```text
MYAV scan report — full  (Sunday 03:00)
Started:  2026-11-01 03:00:02
Finished: 2026-11-01 03:07:41   (7m 39s)

What ran
  ClamAV      1.5.4, signatures 27400 (4h old)
  YARA        4218 rules in 212 files
  VirusTotal  hash-only lookups enabled

Result
  | verdict    | files |
  |------------|-------|
  | MALICIOUS  |     1 |
  | CLEAN      | 18422 |
  | **total**  | **18423** |

Findings
  1. ~/Downloads/invoice.exe
     verdict  MALICIOUS
     evidence clamav:Win.Trojan.Agent-1234567
     sha256   a3f1…9c2e
     action   quarantined (id 7f3a91c2, restore with `myav restore 7f3a91c2`)

Quarantine
  ...

Attention
  (empty when nothing needs you)
```

Read three things, in this order:

1. **Result** — is there anything that is not CLEAN?
2. **Attention** — did an engine fail, get stale, or did the queue drop files?
3. **Findings** — if there are any, read the evidence and act (section 4).

If every line is CLEAN and Attention is empty, you are done.

---

## 4. When something is found

### Step 1 — do not panic, and do not run the file

A MALICIOUS verdict means a signature matched. Signature matches are usually right and
occasionally wrong. In both cases the file has already been moved to quarantine, so it
cannot run by accident.

### Step 2 — read the evidence line

```text
evidence clamav:Win.Trojan.Agent-1234567
```

- `clamav:` means the ClamAV signature database matched. The name after the colon is
  the malware family ClamAV believes it is.
- `yara:RuleName` means a YARA rule matched. YARA rules describe *shapes*, so a match
  is weaker evidence. Check the rule's severity in the report.
- `virustotal:12/70` (only if you configured a key) means twelve of seventy engines on
  VirusTotal call the hash malicious. That is strong corroboration.

### Step 3 — decide: restore, allowlist, or purge

**Case A — you are sure it is malware.** Leave it in quarantine. Optionally destroy it:

```bash
myav quarantine list
myav quarantine purge 7f3a91c2 --yes
```

`purge` is the only irreversible command in MYAV. Without `--yes` it prints what it
*would* delete and changes nothing.

**Case B — it is a false positive (a program you trust).** Restore it, then make sure
MYAV does not flag it again:

```bash
myav quarantine restore 7f3a91c2          # returns it to the original path
myav allow add ~/Downloads/tool.exe --reason "vendor installer, verified 2026-11-01"
```

The allowlist works by **content hash**, not by filename. If the file changes by one
byte, it is scanned again. That is deliberate: an attacker cannot rename malware to
match your allowlist.

**Case C — you do not know.** Leave it in quarantine and investigate before deciding.
Quarantine is reversible indefinitely; there is no timer. You can:

```bash
myav quarantine list --json    # see the sha256 and record details
```

and search that hash on the web. Because MYAV never uploads the file, this is your
choice to make.

### Step 4 — check whether it came back

If the file is restored or was never quarantined, the watcher will see it again if it
changes. Check the report's Attention section for repeated hits on the same path.

---

## 5. When MYAV says UNKNOWN

UNKNOWN means evidence is missing. The report names the missing piece. Common causes:

| Report says | Meaning | Fix |
|---|---|---|
| `clamav: error (connection refused)` | `clamd` is not running | `myav clamd-start`, or let `clamscan` fall back |
| `clamav: skipped (not installed)` | ClamAV is not on `PATH` | Re-run the installer (section 4 of INSTALLATION.md) |
| `yara: skipped (rules missing)` | No rule pack fetched | `myav rules fetch --accept-license` |
| `unreadable: permission denied` | The file belongs to another user or root | Scan it as the owner, or accept the gap |
| `clamav: signature database is older than 48h` | The updater has not run | `sudo myav update-signatures` |
| `no engine produced evidence` | Every engine was skipped | Run `myav doctor` |

**Do not treat an UNKNOWN as a pass.** Fix the cause or record that you accepted the
gap. The weekly report will keep showing it until it is fixed.

---

## 6. The watcher (real-time folder monitoring)

The watcher runs at login and scans files as they finish being written in the watched
folders.

```bash
myav watch --once          # scan what is already there, then exit
myav watch                 # keep running (usually started by the scheduler)
myav watch --json          # machine-readable summary
```

What it does:

- waits `settle_seconds` (default 2 s) after the last write, so a half-downloaded file
  is not scanned;
- ignores its own quarantine, state and cache directories;
- de-duplicates identical content already scanned in this run;
- drops events when the queue is full, and **reports the drop count**. It never
  silently ignores a file.

What it does **not** do: it does not block the write. The file exists for a moment
before it is scanned. MYAV is a detector.

On WSL, the watcher is started by a Windows Task Scheduler entry that calls back into
WSL. See section 8.

---

## 7. Startup entries (`myav boot`)

On first run MYAV records every program that starts at login as a baseline. On later
runs it compares:

```bash
myav boot
```

```text
Startup entries: 47
First run — baseline recorded. Nothing is flagged yet.
```

or, after something new appears:

```text
Startup entries: 48

NEW since the last check
  1. name      Updater
     location  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
     command   C:\Users\you\AppData\Roaming\updater.exe
```

A new startup entry is **SUSPICIOUS by default** — that is why `myav boot` exits `11`
when it finds one. It is not proof of infection; legitimate software adds entries when
it updates. Investigate the command path. If you did not install it, treat it as hostile.

MYAV only **reports**. It never disables an entry and never writes to the registry.
Removing persistence is your decision, made with your operating system's own tools.

On WSL, the startup surface that matters is Windows, so MYAV reads the Windows registry
and CIM list through `powershell.exe` and `reg.exe`. If those are unreachable, the
report says so instead of pretending the list was empty.

---

## 8. Schedules on WSL

WSL often runs with systemd disabled. In that case `myav schedules install` cannot use
systemd timers, so it writes a PowerShell script and prints its path:

```bash
myav schedules install --yes
myav schedules status
```

```text
scheduler: task-scheduler
installed: (none yet)
note: run the PowerShell script from Windows:
  ~/.local/state/myav/schedules/install-myav-tasks.ps1
```

Review the script, then run it from **PowerShell on Windows**:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\wsl$\Ubuntu\home\you\.local\state\myav\schedules\install-myav-tasks.ps1
```

It creates four tasks for your Windows user:

| Task | Trigger | Action |
|---|---|---|
| `myav-watch` | at logon | runs `myav watch` inside WSL |
| `myav-nightly` | daily 02:30 | runs `myav update-signatures` |
| `myav-weekly` | Sunday 03:00 | runs `myav full-scan` |
| `myav-clamd` | at logon | starts `clamd` inside WSL |

Tasks are set to `MultipleInstances IgnoreNew`, so a slow scan cannot stack up.

Check them from Windows:

```powershell
schtasks /Query /TN "myav-*" /V /FO LIST
```

**Important:** the 02:30 and 03:00 jobs only run if the machine is awake. Windows Task
Scheduler can wake a sleeping PC only if you enable "Wake the computer to run this
task" in the task properties. MYAV does not change power settings.

---

## 9. Reports and retention

Reports are Markdown files:

```text
~/.local/state/myav/reports/YYYY-MM-DD-HHMM-<kind>.md
```

`myav report` prints the newest. `myav report --list` shows all. `myav report --path FILE`
prints one specific file.

MYAV keeps the newest `report.retention` files (default 90) and removes older **MYAV
report files** when it writes a new one. It does not touch anything else in that folder.

To keep a report forever, copy it out of the folder.

---

## 10. Updating signatures by hand

```bash
sudo myav update-signatures
```

Root is needed because ClamAV's signature database lives in a system directory. MYAV
itself never calls `sudo`; you do. If you run it without root, it detects the permission
error and tells you to ask the operator, rather than failing obscurely.

Check the result:

```bash
myav doctor
```

A signature database older than 48 hours is reported as stale, and the verdict records
it as degraded. That is how MYAV avoids the "old database, confident CLEAN" failure.

---

## 11. Emergency: is the scanner itself healthy?

```bash
./scripts/verify-live.sh
```

Read-only. It checks the CLI, `doctor`, rule pack, schedules, quarantine database and the
EICAR chain, then prints PASS / WARN / FAIL counts and a verdict. It changes nothing and
deletes nothing.

A healthy run ends with:

```text
Verdict: HEALTHY.
```

or

```text
Verdict: WORKING, with warnings.
```

Warnings are optional steps (YARA pack not fetched, schedules not installed). FAIL means
the detection chain is broken — fix it before trusting a CLEAN report.

---

## 12. Quick reference card

```bash
# health
myav doctor
./scripts/verify-live.sh

# scan
myav scan ~/Downloads/file.zip
myav full-scan
myav full-scan ~/Projects

# findings
myav report
myav quarantine list
myav quarantine restore <id>
myav quarantine purge <id> --yes
myav allow add <path> --reason "why"

# persistence
myav boot
myav boot --json

# schedules
myav schedules status
myav schedules print
myav schedules install --yes

# engines
sudo myav update-signatures
myav clamd-start
myav rules status
myav rules fetch --accept-license

# config
myav config show
myav config set-vt-key
```

Exit codes: `0` clean, `1` failure, `2` usage, `3` platform/root required,
`4` configuration, `5` self-test inconclusive, `10` malicious, `11` suspicious,
`12` unknown.
