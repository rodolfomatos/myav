# FAQ — quick answers, plus a glossary

Short answers to the questions people actually ask. Each points at the document that
explains it properly.

If your question is "is this file safe?", the answer is in
[LIMITATIONS.md](LIMITATIONS.md) §2 and it is not the answer you want.

---

## Getting started

**Do I need to be a programmer?**
No. You need to be able to copy and paste commands into a terminal. Every command in
[INSTALLATION.md](INSTALLATION.md) is explained line by line.

**What is a terminal?**
The text window where you type commands. On Windows, open **Ubuntu** from the Start menu
(that is WSL). On Linux, it is usually `Ctrl+Alt+T`. On macOS, it is Terminal.app.

**What is WSL?**
Windows Subsystem for Linux. It runs a real Linux system inside Windows, with its own
files and its own programs. MYAV's validated Windows path is WSL2 with Ubuntu.

**Do I need to disable Windows Defender?**
**No, and do not.** Defender is a better real-time protector than MYAV. If Defender
removes the EICAR test file before MYAV sees it, MYAV says INCONCLUSIVE — that is
Defender doing its job, not a MYAV bug. See [TESTING.md](TESTING.md) §4.

**Do I need a VirusTotal account?**
No. ClamAV and YARA are enough to scan. VirusTotal is an optional second opinion, off by
default. [CONFIGURATION.md](CONFIGURATION.md) §4 explains how to add one if you want it.

**Does MYAV cost anything?**
MYAV is Apache-2.0, free. ClamAV, YARA and VirusTotal's public API are free for normal
use. The optional YARA rule pack has its own licence (DRL 1.1) — check it for commercial
use.

---

## How it works

**What is a signature?**
A fingerprint of known malware. ClamAV's database contains millions of these. If a file
matches, it is almost certainly that malware. If it does not match, it may still be
malware that nobody has fingerprinted yet.

**What is a YARA rule?**
A description of a *pattern*: "contains this PowerShell download command", "has this
webshell header", "looks like a miner config". Rules catch families and variants that
signatures miss, but they are weaker evidence, which is why MYAV has severity thresholds.

**Why does MYAV say CLEAN and then my antivirus finds something?**
Different engines, different databases, different dates. CLEAN means "no engine I have
found anything known in this file". It does not mean "safe". See
[LIMITATIONS.md](LIMITATIONS.md) §2.

**Why does the report say UNKNOWN?**
An engine did not run. The most common cause is that `clamd` is not running, or ClamAV is
not installed. The report names the cause. [RUNBOOK.md](RUNBOOK.md) §5 is the fix table.

**Why does `myav doctor` exit with code 1?**
Because at least one check is a FAIL — usually ClamAV not installed yet. Exit code 1 is
the tool telling the truth, not a crash. Run the installer.

**Does MYAV run as root?**
The Python code runs as **your normal user**. Root is used only by the one-time installer
script and by the system-wide signature update. MYAV itself never calls `sudo`; you do.
See [THREAT_MODEL.md](THREAT_MODEL.md) §C.

**Can MYAV protect my whole team?**
Not centrally. It is per-machine and per-user by design. A central console is out of
scope; see [LIMITATIONS.md](LIMITATIONS.md) §15.

---

## Quarantine

**Where do quarantined files go?**
`~/.local/share/myav/quarantine/`, with a random name like `7f3a91c2….bin` and mode
`0000` so they cannot be executed by accident.

**Does MYAV ever delete my files?**
Only `myav quarantine purge <id> --yes`, which you must type explicitly. Without `--yes`
it prints what it *would* delete and changes nothing. Scans never delete; they move.

**I think a file was a false positive. What do I do?**
Restore it and allowlist it:

```bash
myav quarantine restore <id>
myav allow add ~/Downloads/tool.exe --reason "vendor installer, verified 2026-11-01"
```

The allowlist is by **content hash**, so renaming the file does not bypass the scan.
[RUNBOOK.md](RUNBOOK.md) §4 explains all three cases.

**How long are quarantined files kept?**
Forever, until you restore or purge them. There is no automatic expiry.

**Are quarantined files encrypted or uploaded?**
Neither. They stay on your disk with mode `0000`. Root can read them; a backup running as
root may copy them. See [PRIVACY.md](PRIVACY.md) §8.

---

## Privacy and network

**Does MYAV send my files anywhere?**
No. Not to the project, not to VirusTotal, not anywhere. A VirusTotal lookup sends only
the SHA-256 hash, and only if you set a key. See [PRIVACY.md](PRIVACY.md).

**What does MYAV send to VirusTotal?**
One HTTPS `GET` containing the file's SHA-256 hash and your API key. No file, no name, no
path, no size.

**Can I use MYAV completely offline?**
Yes for scanning. Signature updates need a ClamAV mirror. You can copy
`/var/lib/clamav/*` from another machine if you need a fully air-gapped setup.

**Does MYAV have telemetry?**
No. There is no analytics, no crash reporting, no update check against this project.

**Where is my VirusTotal key stored?**
`~/.config/myav/config.toml`, mode `0600`. MYAV refuses to read the file if other users
can read it. The key never appears in reports or logs.

---

## Platform questions

**Does it work on Windows?**
Yes, through WSL2, which is the validated path. A native Windows adapter exists but is
experimental. See [PLATFORMS.md](PLATFORMS.md) §5.

**Does it work on a Mac?**
The code has a macOS adapter (launchd, FSEvents, Homebrew), but it is experimental until
someone validates it. [PLATFORMS.md](PLATFORMS.md) §4 lists exactly what is unproven.

**Does it work on a phone?**
Not yet. Android and iOS are documented as companion tiers with a shared protocol; no app
exists. On iOS, a "full phone antivirus" is not possible for a third-party app at all.
See [COMPANION_PROTOCOL.md](COMPANION_PROTOCOL.md).

**Why doesn't it scan my `C:` drive?**
Slow (9p filesystem), and MYAV refuses to write there, so it could not quarantine a
finding. Defender already covers `C:` at kernel level. You can scan a specific path
read-only if you want. [PLATFORMS.md](PLATFORMS.md) §3.2.

**Can I install it on a server with no GUI?**
Yes. Linux servers are the easiest case — systemd user units, no desktop needed. Use
`myav scan` and `myav full-scan --json` for scripting.

---

## Scheduling

**When does it scan?**
Signatures update daily at 02:30; the full scan runs Sunday at 03:00. The watcher runs from
login.

**Nothing ran on Sunday. Why?**
Usually the machine was asleep. The scheduler cannot fire while suspended unless you
enable "wake the computer" in the task properties. MYAV does not change power settings.
Check the report timestamp; if it is older than a week, run `myav full-scan` manually.
[RUNBOOK.md](RUNBOOK.md) §8.

**On WSL, `myav schedules install` printed a PowerShell script. Is that a bug?**
No. WSL often has no systemd, so the only reliable trigger is Windows Task Scheduler. The
script registers four Windows tasks that call back into WSL.

---

## Troubleshooting

**"clamscan: command not found"**
The engines are not installed. The one-time installer is the fix; it needs root, so a human
with the administrator password runs it:

```bash
sudo ./scripts/install-system.sh --apply
```

**"freshclam: permission denied"**
The signature database is system-owned. Run `sudo myav update-signatures`, or fix the
installer step. MYAV will not call sudo for you.

**"configuration problem: config.toml is mode 0644"**
Other users can read a file that may hold an API key. Fix it:

```bash
chmod 600 ~/.config/myav/config.toml
```

**"YARA rules fail to compile"**
Your YARA may be older than the rules (Ubuntu 22.04 ships 4.1.3). MYAV reports per-file
failures instead of pretending. ClamAV-only scanning still works; the report shows YARA as
degraded.

**"myav: refusing unsafe location"**
You asked MYAV to write under `/mnt/c` on WSL. It will not. Choose another destination.

**The report is empty / no findings but I expected some**
Check the report's **Attention** section. An engine that was skipped produces UNKNOWN, not
a finding. Also confirm the files are inside the scan scope.

**How do I uninstall?**
There is no uninstall script on purpose. [INSTALLATION.md](INSTALLATION.md) §Uninstalling
lists the five places anything was written. Restore quarantined files first.

---

## Project questions

**Why "My Adaptive Antivirus" if it is not adaptive yet?**
The name describes the direction, not a shipped feature. Core is deterministic and
explainable. The adaptive parts (baselines, ML, graph analysis) are Research and are not
sold as protection. See [PROJECT_STATUS.md](../PROJECT_STATUS.md).

**Can I contribute?**
Yes. [CONTRIBUTING.md](../CONTRIBUTING.md) explains the workflow, the test requirements,
and the rules that keep the project honest.

**How do I report a security bug?**
Privately, per [SECURITY.md](../SECURITY.md). Do not open a public issue for a
vulnerability.

**Why is there so much documentation?**
Because a security tool that cannot explain itself cannot be trusted. Every claim in the
README points at a page that shows the evidence or states the limit.

---

## Glossary

| Term | Plain meaning |
|---|---|
| **API key** | A password that identifies you to a service, so it can count your requests |
| **clamd** | ClamAV's background service; keeps signatures in memory so scans are fast |
| **clamscan** | ClamAV's one-shot scanner; starts fresh for every file, slower |
| **CLEAN** | "No known malware found". Not a guarantee of safety |
| **EICAR** | A harmless 68-byte test string every antivirus agrees to detect |
| **false positive** | A legitimate file wrongly flagged as malware |
| **hash / SHA-256** | A 64-character fingerprint computed from a file's bytes |
| **launchd** | macOS's background job manager (the macOS equivalent of systemd) |
| **MALICIOUS** | A known-bad signature or high-severity rule fired |
| **quarantine** | A folder where suspicious files are moved, disabled, and kept reversible |
| **signature** | A fingerprint of known malware stored in a database |
| **systemd** | Linux's background service and timer manager |
| **Task Scheduler** | Windows' background job manager |
| **TOCTOU** | "Time of check to time of use": the file changed between scan and action |
| **UNKNOWN** | An engine could not run, so MYAV does not know |
| **WSL** | Windows Subsystem for Linux: a real Linux inside Windows |
| **YARA rule** | A description of a suspicious pattern, weaker evidence than a signature |
| **`~`** | Shorthand for your home folder, e.g. `/home/you` |
| **`0600` / `0700`** | File permission bits: owner read/write (and owner execute for directories), nobody else |
