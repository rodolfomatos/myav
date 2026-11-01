# Installing MYAV

This page assumes you have never installed a security tool before. It explains **what** each
step does, **why** it is needed, what you should see, and what to do when it does not work.

If a word is unfamiliar, [docs/FAQ.md](FAQ.md) has a glossary at the end.

---

## 0. The mental model (read this first)

Installing MYAV has three layers. They are separate because they need different levels of
permission.

| Layer | What it is | Who can install it | Why it is separate |
|---|---|---|---|
| **Python package** | The MYAV code and its two small Python dependencies | You, as a normal user, inside a virtual environment | It touches only your home directory |
| **Engines** | ClamAV and YARA, installed by the operating system package manager | A user with administrator rights (`root`) | They write to `/usr`, `/etc` and a system-wide signature database |
| **Recurring jobs** | The watcher at login, the nightly update, the Sunday scan | You, as a normal user | They are per-user scheduler entries |

MYAV never asks for `root` to scan your files. `root` is needed only once, for the engines.
That is the whole reason `scripts/install-system.sh` exists.

> **Why not just run everything as root?** Because a scanner that runs as root can damage the
> whole machine if it has a bug. MYAV’s Python code runs unprivileged on purpose.

---

## Which kind of equipment do you have?

Find your row. The **validated** column is honest: it says where the project has actually been
run end-to-end, not where the code merely compiles.

| Your equipment | What you get | Status | Follow |
|---|---|---|---|
| **Ubuntu / Debian / Linux PC** | Full scanner, watcher, scheduled jobs | **Validated** (live engines need the one privileged step in §4) | §1 → §10 on this page |
| **Windows PC using WSL2** (Ubuntu inside Windows) | Full scanner *for the Linux side*, plus a Windows-side watcher trigger | **Validated** on Ubuntu 22.04 / WSL2 | §1 → §10, then read “Windows note” in §4 |
| **Mac (Intel or Apple Silicon)** | Full scanner through Homebrew | Adapter present, **experimental** | §1, §4 “macOS note”, §8 “macOS note” |
| **Windows PC, native (no WSL)** | Scanner using Windows ClamAV/YARA builds | Adapter present, **experimental**; not yet validated | “Native Windows (experimental)” below |
| **Android phone** | Companion only (sends scans to a desktop); **no app is shipped** | Design only | [PLATFORMS.md](PLATFORMS.md) |
| **iPhone / iPad** | Not supported; iOS does not allow a third-party app to watch other apps’ files | Design only | [PLATFORMS.md](PLATFORMS.md) |

> **What “experimental” means.** The Python code has a platform adapter and automated tests for
> the file locations and scheduler commands, but the maintainers have not run the full
> detect → quarantine → restore chain on that operating system. Use it, report what breaks,
> and do not rely on it as your only protection.

> **What “validated” means here.** The unit and integration test suite runs on Linux. The live
> ClamAV/YARA proof is completed by the operator with `scripts/install-system.sh --apply` and
> `scripts/verify-live.sh`; see §4, §5 and §7.

**If you are unsure:** choose Ubuntu/WSL2. It is the path with the most testing and the path
the screenshots and examples in this documentation use.

---

## 1. Check your computer

Open a terminal. On Windows, open **Ubuntu** from the Start menu (that is WSL). Type:

```bash
uname -s
python3 --version
```

You should see something like:

```text
Linux
Python 3.10.12
```

- `Linux` means Linux or WSL. Continue.
- `Darwin` means macOS. Continue; step 2 differs slightly.
- `Python 3.10` or newer is required. If your version is older, install a newer Python first.

Check that the usual user folders exist:

```bash
ls -d ~/Downloads ~/Desktop ~/Documents
```

If one is missing, MYAV will simply skip it. You can create it later.

---

## 2. Get the code and create a private workspace

```bash
git clone https://github.com/rodolfomatos/myav.git
cd myav
python3 -m venv .venv
.venv/bin/pip install -e .
```

**What this does, line by line:**

1. `git clone` downloads the project.
2. `cd myav` moves into the project folder.
3. `python3 -m venv .venv` creates a *virtual environment*: a private folder containing its own
   Python and packages. Nothing is installed system-wide. If you delete `.venv/`, MYAV’s Python
   dependencies disappear with it and your system is unchanged.
4. `.venv/bin/pip install -e .` installs MYAV in *editable* mode. The `myav` command always runs
   the code in this folder, which is useful while the project is young.

**Expected output:** the last line ends with `Successfully installed myav-...`.

**If it fails:**

| Message | Meaning | Fix |
|---|---|---|
| `python3: command not found` | Python is not installed | `sudo apt install python3 python3-venv` (Ubuntu/WSL) |
| `ensurepip is not available` | The venv module is missing | `sudo apt install python3-venv` |
| `No module named pip` | The venv was created without pip | Delete `.venv`, install `python3-venv`, try again |

Test the command before installing anything else:

```bash
.venv/bin/myav version
```

You should see something like `myav 0.1.0 (Python 3.10.12, Linux)`.

---

## 3. Run the dry run (no changes)

The installer is safe to run without permission because **it changes nothing by default**.

```bash
./scripts/install-system.sh --dry-run
```

Read the output. Each line that starts with `WOULD RUN:` is a command the installer would
execute. Nothing is hidden. You will see roughly:

```text
1/6 — Detecting the platform
  operating system: Linux
  distribution:     ubuntu
  running as root:  no
  mode:             DRY RUN

2/6 — Installing ClamAV and YARA
  packages to install: clamav clamav-daemon clamav-freshclam yara
  WOULD RUN: apt-get update
  WOULD RUN: env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ...
```

If the package list looks wrong for your distribution, stop and open an issue. Do not guess.

---

## 4. Install the engines (one privileged step)

This step is performed by **you or the administrator of the machine**, not by the AI agent
that may have helped you set this up. The installer refuses to call `sudo` itself; that is a
deliberate safety property.

```bash
sudo ./scripts/install-system.sh --apply
```

**What it installs and why:**

| Package | Why it is needed |
|---|---|
| `clamav` | The scanner binary (`clamscan`) |
| `clamav-freshclam` | The updater for the signature database |
| `clamav-daemon` | `clamd`, which keeps signatures in RAM so scans are fast |
| `yara` | Pattern-matching engine for rules that describe malware *shapes* |

**What it changes:**

- Adds the packages above through your distribution’s package manager.
- Writes `/etc/clamav/clamd.conf.d-myav`, which makes `clamd` listen only on
  `127.0.0.1:3310` and on a local socket. It does **not** open a network port to the world.
- Keeps a one-time backup of the previous ClamAV daemon configuration as
  `/etc/clamav/clamd.conf.bak`. It never deletes it.
- Starts `clamav-freshclam` and `clamav-daemon` **if systemd is running**. On WSL it usually is
  not; the script explains this and starts `clamd` directly instead.

**What it does not change:**

- It does not disable Windows Defender or any other antivirus.
- It does not change firewall rules.
- It does not write anything under `/mnt/c` (the Windows disk).
- It does not add `sudoers` rules.

**Expected output:** each check in section 5 reports `found: ...`.

### macOS note

On macOS the installer uses Homebrew:

```bash
brew install clamav yara
brew services start clamav
```

If Homebrew is missing, install it from <https://brew.sh> first. The installer will tell you
and stop without changing anything.

The macOS adapter exists and is tested for file locations and launchd rendering, but the full
live chain is **experimental**. After installing, run `myav doctor` and `myav selftest` and
expect the same output described in §5 and §7. If `clamd` is not found, check
`brew --prefix clamav`; Homebrew sometimes installs the daemon outside the default `PATH`.

### Windows note (recommended: WSL2)

MYAV’s validated Windows path is **WSL2 with an Ubuntu distribution**. Install Ubuntu from the
Microsoft Store, open it, and follow the Linux instructions above. Windows Defender keeps
protecting the Windows side; MYAV watches the Linux side and triggers from Windows Task
Scheduler.

### Native Windows (experimental, no WSL)

This path runs MYAV as a normal Windows program. It is **experimental**: the adapter exists,
but the full chain has not been validated by the maintainers. Read it as a recipe to try and
report back, not as a supported guarantee.

1. **Install Python 3.10 or newer for Windows.** Get it from <https://www.python.org/downloads/>.
   During setup, tick **Add python.exe to PATH**. Verify in PowerShell:

   ```powershell
   python --version
   ```

2. **Install ClamAV for Windows.** Download the official installer from
   <https://www.clamav.net/downloads> and install it. Add its folder (usually
   `C:\Program Files\ClamAV`) to `PATH`, then verify:

   ```powershell
   clamscan --version
   ```

3. **Install YARA for Windows.** Download the release zip from
   <https://github.com/VirusTotal/yara/releases>, extract it somewhere permanent, and add that
   folder to `PATH`. Verify:

   ```powershell
   yara --version
   ```

4. **Get MYAV and create a private workspace** in PowerShell:

   ```powershell
   git clone https://github.com/rodolfomatos/myav.git
   cd myav
   python -m venv .venv
   .venv\Scripts\pip install -e .
   .venv\Scripts\myav version
   ```

5. **Read the health check.** Windows does not use POSIX permissions; MYAV relies on the
   per-user `%APPDATA%` folder instead and does **not** require `chmod`:

   ```powershell
   .venv\Scripts\myav doctor
   ```

6. **Fetch rules and prove the chain**, exactly as in §6 and §7:

   ```powershell
   .venv\Scripts\myav rules fetch --accept-license
   .venv\Scripts\myav selftest
   ```

7. **Schedules.** `myav schedules print` writes a PowerShell script. Review it, then run it:

   ```powershell
   .venv\Scripts\myav schedules print
   powershell -NoProfile -ExecutionPolicy Bypass -File <path-to-script>
   ```

   The script creates four Task Scheduler entries for the current user. On native Windows the
   commands call the MYAV executable directly; they do **not** go through `wsl.exe`.

8. **Tell us what happened.** Open an issue with the output of `myav doctor` and
   `myav selftest` (redact any key). That is how this path becomes validated.

---

## 5. Verify the engines are visible

```bash
clamscan --version
yara --version
.venv/bin/myav doctor
```

`myav doctor` is the health check. Read it like a checklist:

```text
OK    Python >= 3.10: 3.10.12
OK    Platform adapter: Linux (linux)
OK    Private directories (0700)
OK    ClamAV signatures: version 27400, age 2h
WARN  YARA rules: none fetched — run `myav rules fetch --accept-license`
WARN  VirusTotal: not configured (optional)
OK    Free space for quarantine: 12.4 GiB
WARN  Scheduled jobs: not installed — run `myav schedules install`
```

- **OK** — nothing to do.
- **WARN** — optional or not yet done. The tool still works.
- **FAIL** — MYAV cannot protect the machine correctly until this is fixed.

`doctor` exits with code `0` when there is no `FAIL`, and `1` when there is at least one. That
makes it usable in scripts.

**If ClamAV says “not installed” after step 4:** close and reopen the terminal, then run
`hash -r`. Package managers sometimes update the shell’s command cache.

---

## 6. Fetch the YARA rules

The rule pack is **not** in this repository. It is downloaded from a pinned upstream commit,
so the same commit is used everywhere.

```bash
.venv/bin/myav rules fetch --accept-license
```

**Why the extra flag?** The upstream pack (`Neo23x0/signature-base`) uses the Detection Rule
License 1.1: free for non-commercial use, with conditions. MYAV refuses to download it until
you explicitly acknowledge that. Read the licence before accepting if you plan commercial use.

**What happens:**

1. MYAV asks GitHub for the latest commit of the pack.
2. It downloads that exact tarball.
3. It extracts only `*.yar` and `*.yara` files, refusing path traversal.
4. It compiles each file with `yarac`. Files that fail are kept and reported, not silently
   dropped.
5. It writes `PROVENANCE.json` with the commit, archive SHA-256, licence and timestamp.

Check it:

```bash
.venv/bin/myav rules status
```

**If compilation fails for every file:** your YARA version may be older than the rules. MYAV
records the per-file errors. You can still use ClamAV-only scanning; YARA becomes `skipped`
and the report says so instead of pretending it ran.

---

## 7. Prove the whole chain (EICAR)

EICAR is a harmless 68-byte string that every antivirus agrees to flag. It is the standard
way to prove that detection, quarantine, restoration and reporting work **without using real
malware**.

```bash
.venv/bin/myav selftest
```

A healthy result:

```text
EICAR self-test

result   assertion
-------- ----------------------------------------------------
PASS     test file written
PASS     test file hash recorded
PASS     verdict is MALICIOUS
PASS     ClamAV named the Eicar signature
PASS     source file was removed
PASS     quarantine record created
PASS     payload exists
PASS     payload hash matches the original
PASS     payload is not executable
PASS     restore returned a path
PASS     restored file hash matches
PASS     no test artefacts left in the sandbox

RESULT: PASS
```

### If you see INCONCLUSIVE (exit code 5)

```text
INCONCLUSIVE: the EICAR file disappeared before myav could scan it. Windows Defender
real-time protection does this to files inside WSL. ...
```

This is **not** a MYAV bug. Windows Defender scans files inside WSL and removes EICAR before
MYAV can read it. **Do not disable Defender to make this test pass.** Defender doing its job
is a good thing. Use `myav scan` on a harmless file instead, and trust the unit tests for the
detection chain. See [TESTING.md](TESTING.md) for the fixture-based proof.

---

## 8. Install the recurring jobs

```bash
.venv/bin/myav schedules print          # see every file that would be written
.venv/bin/myav schedules install --yes  # write the user-level ones
```

Four jobs are created:

| Job | When | What it does |
|---|---|---|
| `myav-watch` | at login, stays running | scans new files in the watched folders |
| `myav-nightly` | daily at 02:30 | runs `freshclam` to refresh signatures |
| `myav-weekly` | Sunday at 03:00 | full scan of the default scope, writes a report |
| `myav-clamd` | at login | starts the fast scanner daemon |

Only the **user-level** files are written by this command. The root-level ClamAV unit is
printed for you to install manually, because MYAV never writes to system directories.

```bash
.venv/bin/myav schedules status
```

**On WSL, systemd is often offline.** In that case `myav schedules` prints a PowerShell script
under `~/.local/state/myav/schedules/install-myav-tasks.ps1`. It uses Windows Task Scheduler
to call back into WSL. Review it with a text editor, then run it from PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File <path-to-script>
```

This is the only reliable trigger when `systemd` is not available.

**On macOS**, `myav schedules install --yes` writes three launchd agents under
`~/Library/LaunchAgents/` and prints the `launchctl load -w` command for each. launchd has no
“catch up after sleep” equivalent, so a laptop that is asleep at 03:00 may skip that week’s
full scan. Run `myav full-scan` manually when you notice a gap.

**On native Windows**, the generated PowerShell script registers the same four jobs with Task
Scheduler using `-StartWhenAvailable`, so a missed run happens after the machine wakes.

**What “install” means here.** `schedules install` writes **user-level** files only. Anything
that needs administrator rights is printed, not written. This is the same rule as the engine
installer: MYAV never escalates by itself.

---

## 9. First real scan

```bash
.venv/bin/myav full-scan
```

This scans `~/Downloads`, `~/Desktop`, `~/Documents` and removable mounts, writes a report to
`~/.local/state/myav/reports/`, and prints it. Nothing is deleted; detected files are moved to
quarantine and can be restored.

To scan one folder without the full report ceremony:

```bash
.venv/bin/myav scan ~/Downloads
```

### A safe, honest first test

Create a harmless file, scan it, and read the report:

```bash
echo "hello from myav" > ~/Downloads/hello.txt
.venv/bin/myav scan ~/Downloads/hello.txt
.venv/bin/myav report
```

You should see `CLEAN` and a report that says a clean verdict means “nothing known was found”,
not “this file is safe”.

---

## 10. Day-to-day operation

| I want to… | Command |
|---|---|
| Check health | `myav doctor` |
| Scan a file/folder | `myav scan PATH` |
| Weekly-style full scan now | `myav full-scan` |
| Read the latest report | `myav report` |
| List quarantined files | `myav quarantine list` |
| Restore a file | `myav quarantine restore <id>` |
| Permanently delete a quarantined file | `myav quarantine purge <id> --yes` |
| Allowlist a false positive | `myav allow add PATH --reason "why"` |
| See new startup entries | `myav boot` |
| Update signatures now | `sudo myav update-signatures` |
| See what schedules exist | `myav schedules status` |

Full explanations, including what to do when an alert appears, are in
[docs/RUNBOOK.md](RUNBOOK.md).

---

## Troubleshooting index

| Symptom | Section |
|---|---|
| `doctor` says ClamAV not installed | [5](#5-verify-the-engines-are-visible) |
| `selftest` says INCONCLUSIVE | [7](#if-you-see-inconclusive-exit-code-5) |
| YARA rules fail to compile | [6](#6-fetch-the-yara-rules) |
| `freshclam` says permission denied | [RUNBOOK.md](RUNBOOK.md) |
| Schedules not running on WSL | [8](#8-install-the-recurring-jobs) |
| Report says UNKNOWN | [RUNBOOK.md](RUNBOOK.md) |
| I think MYAV itself is insecure | [SECURITY.md](../SECURITY.md) |

---

## Uninstalling

There is no uninstall script because uninstalling a security tool must be a conscious act.
The pieces are:

1. Remove the scheduled jobs: `myav schedules status`, then remove the files it lists.
2. Restore or export anything in quarantine first: `myav quarantine list`.
3. Remove this folder (which also removes `.venv/`).
4. Optionally remove the engines: `sudo apt remove clamav clamav-daemon clamav-freshclam yara`.
5. Optionally remove MYAV’s state: `~/.config/myav`, `~/.local/state/myav`,
   `~/.local/share/myav`, `~/.cache/myav`.

Nothing is hidden outside those locations. The installer does not create a system user, a
system-wide config, or a service that survives after you remove the scheduler entries.
