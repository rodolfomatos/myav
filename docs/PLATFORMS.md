# Platforms — what works where, and how you can tell

MYAV is **designed** for many platforms and **validated** on one family. Those are
different claims, and this page keeps them apart.

The code has adapters for Linux, WSL2, macOS, Windows, Android and iOS. Only Linux and
WSL2 have been run end-to-end against real ClamAV and YARA with the live EICAR test.

---

## 1. Capability matrix

A capability is something the platform can actually do. The CLI asks the adapter before
running a command and exits `3` with a clear message when the answer is no — it never
pretends to have scanned something.

| Capability | Linux | WSL2 | macOS | Windows | Android | iOS |
|---|---|---|---|---|---|---|
| Scan files on demand | Yes | Yes | Yes | Yes | Yes | Yes (share sheet) |
| Watch folders in real time | Yes | Yes | Yes | Yes | **No** | **No** |
| Background daemon (`clamd`) | Yes | Yes | Yes | Yes | n/a | n/a |
| Recurring scheduler | systemd user | Windows Task Scheduler | launchd | Task Scheduler | WorkManager (planned) | **No** |
| Startup inventory | .desktop + systemd | registry + CIM + .desktop | LaunchAgents | registry + Startup folder | n/a | n/a |
| Reversible quarantine | Yes | Yes | Yes | Yes | Yes (app sandbox) | Yes (app sandbox) |
| System package install | Yes | Yes | Homebrew | MSI/manual | app store | app store |
| **Validated end-to-end** | **Yes** | **Yes** | Experimental | Experimental | Not built | Not built |

Legend:

- **Yes** — implemented and exercisable on this platform.
- **No** — impossible under the platform's security model.
- **Experimental** — code exists but has not been proven on real hardware.
- **Not built** — design and protocol only.

---

## 2. Linux

**Status: validated (reference platform).**

| Item | Value |
|---|---|
| Detection | ClamAV via `clamdscan` (daemon) or `clamscan` (fallback); YARA via `yara-python` or CLI |
| Watching | `inotify` through `watchdog` |
| Scheduling | systemd **user** units (`~/.config/systemd/user/`) |
| Startup inventory | `~/.config/autostart/*.desktop`, systemd user units |
| Data locations | XDG: `~/.config/myav`, `~/.local/state/myav`, `~/.local/share/myav`, `~/.cache/myav` |
| Root needed | Only for the engine install and the system-wide signature database |

The watcher and CLI run unprivileged. `clamd` is a system service because it holds the
signature database.

Tested distributions at the time of writing: Ubuntu 22.04 (WSL2 and native). The
installer also handles Debian, Fedora/RHEL-family, and Arch-family package names; those
paths are implemented but should be verified on your distribution.

---

## 3. WSL2 (the validated Windows path)

**Status: validated (reference machine).**

WSL2 is a real Linux kernel running inside a lightweight VM on Windows. MYAV runs as a
normal Linux program. Two things differ from native Linux:

### 3.1 Scheduling

WSL often runs with systemd disabled. When it is off, `myav schedules install` cannot use
systemd timers. It writes a PowerShell script instead and prints its path. You run it from
Windows, once:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\wsl$\Ubuntu\home\you\.local\state\myav\schedules\install-myav-tasks.ps1
```

That creates four Windows tasks that call back into WSL with `wsl.exe -d <distro>`. This
is the only reliable trigger when systemd is unavailable.

If you have enabled systemd (`systemd=true` in `/etc/wsl.conf`), the normal Linux path
works instead.

### 3.2 The `C:` drive

`/mnt/c` is **excluded** from the default scan scope and **write-forbidden** for MYAV.

| Operation | On `/mnt/c` |
|---|---|
| Default scan | No (excluded) |
| Explicit `myav scan /mnt/c/...` | Yes, read-only |
| Quarantine (move) | Refused |
| Any state/report/cache write | Refused |

Why: reading `C:` through 9p is slow; writing there risks filling the Windows disk, which
is exactly what happened on the machine this project was built on (C: was full). The guard
raises an explicit error rather than failing halfway through a move.

### 3.3 Removable drives

WSL exposes no udev/udisks. A USB stick appears as a mount under `/mnt/<letter>`. MYAV
treats **any** `/mnt/<letter>` that is not `c` and not a WSL-internal mount (`/mnt/wsl`,
`/mnt/wslg`, `/mnt/host`) as removable. That is a heuristic: a second internal NTFS volume
looks identical to a USB stick. MYAV scans both, which is safe, if occasionally more work
than you expected.

### 3.4 Windows Defender interaction

Defender scans files inside the Linux filesystem too. It can remove an EICAR file before
MYAV sees it, producing `INCONCLUSIVE` on the self-test. That is Defender working. **Do not
disable it.**

---

## 4. macOS

**Status: experimental.**

| Item | Value |
|---|---|
| Engines | ClamAV and YARA via Homebrew (`brew install clamav yara`) |
| Watching | FSEvents through `watchdog` |
| Scheduling | launchd agents in `~/Library/LaunchAgents/` |
| Startup inventory | LaunchAgents; **Full Disk Access** may be required for some paths |
| Data locations | `~/.config/myav` (config), `~/Library/Application Support/myav` (state/data), `~/Library/Caches/myav` |
| Root needed | Engine install only |

What is not proven: the launchd plist output has not been loaded on real macOS, the
FSEvents watcher has not been exercised against a real download, and Gatekeeper/notarization
is not addressed (MYAV is run from source).

If you run it, please run `./scripts/verify-live.sh` and report the result.

Known friction:

- macOS may prompt for **Full Disk Access** before MYAV can read some folders. Grant it to
  the terminal application, not to Python directly.
- Homebrew installs ClamAV without a running daemon by default. `brew services start clamav`
  is required for the fast path; otherwise MYAV falls back to `clamscan`.

---

## 5. Windows (native)

**Status: experimental.**

| Item | Value |
|---|---|
| Engines | Official ClamAV and YARA Windows builds, expected on `PATH` |
| Watching | `ReadDirectoryChangesW` through `watchdog` |
| Scheduling | Task Scheduler (`schtasks`) |
| Startup inventory | Registry `Run`/`RunOnce` keys, Startup folder, scheduled tasks |
| Data locations | `%APPDATA%\myav` (config), `%LOCALAPPDATA%\myav` (state/data/cache) |
| Root needed | Engine install and the signature database |

What is not proven: path handling on drive letters, the watcher under Windows file
semantics (rename/delete races), and Task Scheduler XML quoting. The code paths exist and
are unit-tested with injected platform values, but they have not run on a Windows machine.

**Recommendation:** use WSL2. It is the validated path. Native Windows is here so the
architecture does not have to be rewritten later, not because it is ready.

---

## 6. Android (companion)

**Status: not built — design only.**

Android's security model prevents a normal app from watching another app's files or
scanning the whole filesystem.

| Capability | Reality on Android |
|---|---|
| Scan files the user picks | Yes, via the Storage Access Framework |
| Scan shared storage on a schedule | Partially, with `MANAGE_EXTERNAL_STORAGE` (Play Store restricted) |
| Watch all file writes in real time | **No** — needs Device Owner / privileged app |
| Quarantine inside app sandbox | Yes |
| Quarantine another app's file | Generally **no** |

The intended design is a **companion**: the phone sends a file hash to a desktop MYAV over
a local link and shows the answer. The protocol is specified in
[COMPANION_PROTOCOL.md](COMPANION_PROTOCOL.md). No app exists yet.

---

## 7. iOS (companion)

**Status: not built — design only.**

iOS is stricter still:

- no background filesystem access;
- no persistent process;
- no scanning of other apps' containers;
- a share-sheet extension can scan **one user-picked file at a time**.

Capabilities: on-demand scan of a picked file, and a quarantine result inside the app's
own container. That is the entire honest surface. A "full phone antivirus" on iOS is not
possible for a third-party app, and any product claiming otherwise is describing something
else.

---

## 8. How the adapter decides

At startup MYAV detects the platform from `sys.platform`, `/proc/version` (for WSL),
environment markers (`WSL_DISTRO_NAME`, `ANDROID_ROOT`), and then asks the adapter what it
can do.

You can see the result:

```bash
myav platforms
myav platforms --json
```

```text
Platform: Linux (linux)
  scan-files           yes
  watch-files          yes
  daemon               yes
  scheduler            systemd-user
  startup-inventory    yes
  quarantine           yes
  system-packages      yes
```

For testing and for companion apps, the platform can be forced:

```bash
MYAV_PLATFORM=wsl myav platforms
MYAV_PLATFORM=ios myav scan ~/file.txt
```

`MYAV_PLATFORM` is an override, not a lie detector: it changes which adapter is used, so
the CLI will refuse commands the forced platform cannot do. That is how the capability
matrix is enforced in code rather than in documentation.

### Why refuse instead of degrade silently

If MYAV silently skipped watching on Android, a user would believe they had real-time
protection they do not have. A clear "this platform cannot watch files" is more useful
than a green checkmark. Exit code `3` means exactly that.

---

## 9. Data locations, side by side

| Platform | Config | State | Data | Cache |
|---|---|---|---|---|
| Linux | `~/.config/myav` | `~/.local/state/myav` | `~/.local/share/myav` | `~/.cache/myav` |
| WSL2 | same as Linux | same | same | same |
| macOS | `~/.config/myav` | `~/Library/Application Support/myav` | `~/Library/Application Support/myav` | `~/Library/Caches/myav` |
| Windows | `%APPDATA%\myav` | `%LOCALAPPDATA%\myav\state` | `%LOCALAPPDATA%\myav` | `%LOCALAPPDATA%\myav\cache` |
| Android | app-private files dir | app-private files dir | app-private files dir | app cache dir |
| iOS | app container | app container | app container | app cache dir |

All MYAV-owned directories are created `0700`. The config file is `0600`.

---

## 10. What "validated" would require for a new platform

To move a platform from **experimental** to **validated**, someone must run and publish:

1. `./scripts/install-system.sh --dry-run` and `--apply` successfully.
2. `myav doctor` with no FAIL.
3. `myav rules fetch --accept-license` and a successful compile count.
4. `myav selftest` returning PASS (not INCONCLUSIVE).
5. A full scan of a real folder with a written report.
6. The scheduled jobs actually firing at the configured times.
7. `myav boot` on first run, then a deliberate new startup entry detected on the second.

That is the checklist. It is intentionally concrete so "works on my machine" cannot be
mistaken for "validated".

---

## Summary

| If you are on… | Do this |
|---|---|
| Linux | Follow [INSTALLATION.md](INSTALLATION.md) directly |
| Windows | Install WSL2 + Ubuntu, then follow [INSTALLATION.md](INSTALLATION.md) |
| macOS | Follow [INSTALLATION.md](INSTALLATION.md), expect experimental edges |
| Windows with no WSL | It compiles in principle; treat it as a research task |
| Android / iOS | Read [COMPANION_PROTOCOL.md](COMPANION_PROTOCOL.md); there is no app yet |
