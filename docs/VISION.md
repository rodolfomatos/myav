# Vision

## Problem

Files that land on this machine — downloads, desktop drops, USB volumes — are trusted by
default. Windows Defender covers the Windows filesystem with commercial signatures, but it
gives no visibility into the Linux side of WSL, no YARA-level rules for Linux/script malware,
no readable audit trail, and no automatic quarantine with provenance.

The operator cannot answer three basic questions:
1. *What arrived on this machine in the last week, and was it checked?*
2. *What is currently quarantined, where did it come from, and can I get it back?*
3. *Did anything new start itself at boot since I last looked?*

## Solution

`myav` is a local-first antivirus built only from open-source components:

- **ClamAV** (`clamd`) for signature detection — the same engine family used by mail gateways.
- **YARA** with a pinned public rule pack (Neo23x0 `signature-base`) for behavioural/pattern rules.
- **VirusTotal hash lookup** (never upload) for reputation on files that are already known to VT.
- A **write watcher** over `~/Downloads`, `~/Desktop`, and mounted USB volumes.
- **Reversible quarantine** with sidecar metadata; `myav restore` always works.
- A **startup inventory** that diffs Windows startup entries and Linux autostarts.
- **Plain-English reports** after every scan.

Every verdict carries its evidence: which engine fired, which rule/signature, which hash.

## Value

- The operator can audit *everything that was checked* — including what came back clean.
- Detection is not a black box: ClamAV signature names and YARA rule names are surfaced.
- Nothing is destroyed. Worst case, a false positive is moved and restored in one command.
- The tool is honest about its limits: it is a WSL-side scanner, not a Windows AV.

Success criteria:
- EICAR is detected **and quarantined** end to end, and restored byte-identically.
- A new startup entry appears in the report within one check cycle.
- Weekly full scan completes within a documented time budget on the declared scope.
- Zero writes to `/mnt/c`.
