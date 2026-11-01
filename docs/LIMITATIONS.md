# Limitations — what MYAV cannot do, and why

This page exists because security tools that overstate themselves are dangerous. Every
limitation below is intentional, measured, or a known gap with a plan. None of them is
hidden in a footnote.

If a claim is not on this page or in [ARCHITECTURE.md](ARCHITECTURE.md), MYAV does not
make it.

---

## 1. MYAV detects; it does not block

This is the most important limitation, so it is first.

When you open a file, the operating system loads it. MYAV watches folders and scans
files, but it runs in **user space**. It cannot intercept the `open()` call, the
`execve()` call, or a memory-mapped load. A file can therefore run before the scan
finishes.

| What a kernel-level AV does | What MYAV does |
|---|---|
| Blocks execution until a verdict exists | Scans after the bytes settle; reports the verdict |
| Intercepts every process start | Watches three folders plus removable mounts |
| Sees network connections | Has no network monitor |
| Hooks file read/write in the kernel | Uses `inotify`/FSEvents/`ReadDirectoryChangesW` events |

MYAV could become a blocker only by shipping a kernel driver or a Windows minifilter.
That is a different project with a different risk profile (a bug in a kernel driver
takes the whole machine down). It is **not** on the roadmap for the Core tool.

**Practical consequence:** if you download something and run it immediately, MYAV may
report it after it has already started. Keep the quarantine habit: do not run unknown
downloads until the report says CLEAN.

---

## 2. Signature scanning cannot see a brand-new file

ClamAV compares bytes against a database of known malware. If nobody has ever submitted
that exact file, no signature exists, and MYAV returns CLEAN.

This is not a defect to be fixed by tuning. It is how signatures work. The public
research on malware polymorphism is clear about the ceiling (see
[RESEARCH_REFERENCES.md](RESEARCH_REFERENCES.md)).

What partially compensates:

- **YARA rules** look for shapes (a PowerShell download cradle, a webshell header, a
  miner configuration) rather than exact bytes. They catch some new samples.
- **VirusTotal lookups** add other engines' opinions *if the hash is already known*.
  They tell you nothing about a file nobody has seen.

What does not compensate: hope.

---

## 3. The Windows `C:` drive is not scanned by default

On WSL, MYAV excludes `/mnt/c`.

Reasons, in order:

1. Reading `C:` through WSL's 9p filesystem is slow — often ten to fifty times slower
   than ext4. A full scan would take hours and hammer the disk.
2. MYAV refuses to **write** under `/mnt/c` (quarantine moves files, which is a write).
   A malicious file found there could not be quarantined.
3. The Windows side already has Defender, which is a real kernel-level AV with
   real-time protection. Duplicating that badly is not useful.

You can scan a specific Windows path explicitly with `myav scan /mnt/c/...`. The report
will show the finding, but the action will be "reported only" because quarantine cannot
move it. Removing it is a Windows task.

---

## 4. No archive scanning in v1

MYAV scans a `.zip`, `.7z`, `.tar` or `.docx` as **one opaque file**. It does not open it
and scan the contents.

Consequences:

- A malicious executable inside a downloaded ZIP is not detected until it is extracted.
  Once extracted into a watched folder, the watcher scans it normally.
- ClamAV itself can scan archives, but MYAV drives it in a mode that treats the file as
  bytes. Archive-aware scanning adds decompression-bomb risk and a memory budget that
  v1 does not have.

Workaround for now: extract, then scan. The watcher usually catches the extraction
automatically because the files land in Downloads.

---

## 5. No memory scanning, no fileless malware, no rootkits

MYAV reads files from disk. It does not:

- inspect process memory;
- detect code injected into a legitimate process;
- detect a fileless attack that lives only in the registry or in PowerShell memory;
- detect a kernel-mode rootkit (it cannot see below the kernel, by definition).

These are the domains of EDR products and dedicated rootkit scanners. MYAV does not
claim them, and no amount of YARA rules changes that.

---

## 6. Behavioural detection is Research, not Core

The blueprint includes behavioural baselines, machine learning, graph analysis and a
sandbox. **None of that ships in the Core tool.** They are described as research in
[RESEARCH_REFERENCES.md](RESEARCH_REFERENCES.md) and tracked in
[PROJECT_STATUS.md](../PROJECT_STATUS.md).

Why the split is explicit: a half-trained anomaly detector produces alerts nobody can
act on, and alert fatigue is how real infections get ignored. Core stays deterministic
and explainable. Research must earn its way in with measured false-positive rates.

---

## 7. Only Linux/WSL is validated end-to-end

The code contains adapters for Linux, WSL, macOS, Windows, Android and iOS. Only
**Linux and WSL2** have been run against real ClamAV and YARA with the live EICAR test.

| Platform | Status | What "not validated" means concretely |
|---|---|---|
| Linux | Validated | Full chain proven |
| WSL2 | Validated | Full chain proven, scheduling via Windows Task Scheduler |
| macOS | Experimental | Code paths exist; launchd output and FSEvents watcher untested on real hardware |
| Windows (native) | Experimental | Paths, `ReadDirectoryChangesW` and Task Scheduler output untested |
| Android | Companion, unbuilt | Documented protocol only; no app written |
| iOS | Companion, unbuilt | Share-sheet design only; no app written |

Do not deploy the experimental paths on a machine you depend on and assume they work.
[PLATFORMS.md](PLATFORMS.md) lists exactly which capability is proven where.

---

## 8. YARA rule quality is not guaranteed by MYAV

MYAV downloads `Neo23x0/signature-base` at a pinned commit and records the provenance.
It does not audit the rules.

- A rule can be wrong and flag a legitimate file. That is a **false positive**, and the
  quarantine is reversible for exactly this reason.
- A rule can be too broad and flag many files. Severity thresholds
  (`yara.malicious_severity`, `yara.suspicious_severity`) let you tune the line between
  MALICIOUS and SUSPICIOUS, but they do not make a bad rule good.
- YARA 4.1.3 (the version in some distributions) rejects syntax used by newer rules.
  MYAV reports per-file compile failures instead of silently dropping the pack.

The rule pack's licence (Detection Rule License 1.1) is free for non-commercial use.
**Check it before commercial deployment.** MYAV does not relicense it.

---

## 9. VirusTotal is optional and tells you little about a new file

Even with a key:

- You get **other engines' opinions**, not a scan by MYAV.
- A file that VirusTotal has never seen returns "not found". That is not a clean bill of
  health; it means nobody has submitted it.
- The free API is rate-limited (4 requests/minute, 500/day by default). MYAV counts and
  backs off; heavy scanning will hit the limit.
- A hash reveals that *somebody* has a file with that fingerprint. That is a small
  privacy disclosure, documented in [PRIVACY.md](PRIVACY.md).

It is off by default for these reasons.

---

## 10. The allowlist is a real hole you create yourself

`myav allow add PATH` trusts a file **by content hash**, forever, on every future scan.

- If you allowlist a legitimate installer, that is correct and useful.
- If you allowlist something you did not verify, MYAV will never warn you again about
  that exact file.
- A hash is not a signature of intent: the same bytes are either trustworthy or not.

The allowlist is audited (it is stored with a timestamp and reason in the state
database), but MYAV cannot second-guess your decision. Treat `myav allow` as a
security-relevant action, because it is.

---

## 11. Quarantine is not encryption

Quarantined payloads are stored with mode `0000` and a random `.bin` name. That stops
accidental execution by a normal user. It does **not**:

- encrypt the bytes — anyone with root can read them;
- protect against a root-level attacker;
- stop a backup tool (running as root) from copying them elsewhere.

Quarantine is containment against accident and casual malware, not a vault.

---

## 12. The scheduler needs the machine awake

A 03:00 scan does not happen if the computer is asleep and the scheduler is not allowed
to wake it. MYAV does not change power settings. On a laptop that is closed overnight,
expect the scan to run late or be missed.

Mitigation: `myav schedules status` shows what is installed; check the report timestamp
to see when the last full scan actually ran. If it is older than a week, run
`myav full-scan` manually.

---

## 13. Alerts are only as good as your reading of them

MYAV writes reports, not pop-ups with a big red button. If nobody reads the report, a
finding sits in quarantine unnoticed. That is a design choice (no noisy desktop
notifications, no browser pop-ups), and it has a cost.

Minimum discipline: read `myav report` after each weekly scan, or check
`myav quarantine list` weekly. Both are one command.

---

## 14. No automatic response

MYAV does not:

- kill a process;
- block a network connection;
- disable a startup entry;
- delete a file without `--yes`;
- change firewall rules;
- reinstall or "repair" anything.

Every response is a human decision. That is slower and safer than automated remediation,
which is how antivirus products delete people's work.

---

## 15. Things that are explicitly out of scope

| Out of scope | Why |
|---|---|
| Network intrusion detection | Different data source, different tool |
| Email gateway scanning | Server-side concern |
| Browser extension scanning | Platform-specific, rapidly changing |
| Full disk encryption checks | Configuration auditing, not malware detection |
| Compliance certification (HIPAA, PCI) | MYAV is a tool, not an auditor |
| Cloud multi-tenant management | Local-first is the design |

---

## Summary in one paragraph

MYAV is a **local, explainable, signature-and-pattern detector** with a reversible
quarantine and a readable report. It is not a blocker, not an EDR, not a rootkit
scanner, not validated on every platform, and not smarter than the signatures and rules
you feed it. It is honest about all of that in every report — which is the property that
makes it safe to deploy.
