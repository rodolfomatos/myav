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

- **ClamAV** (`clamd` / `clamscan`) for signature detection — the same engine family used by mail gateways.
- **YARA** with a pinned public rule pack (Neo23x0 `signature-base`) for pattern rules.
- **VirusTotal hash lookup** (never upload) for reputation on files that are already known to VT.
- A **write watcher** over `~/Downloads`, `~/Desktop`, `~/Documents`, and mounted USB volumes.
- **Reversible quarantine** with metadata stored in a SQLite state database; `myav quarantine restore` always works.
- A **startup inventory** that diffs Windows startup entries (via `reg.exe` / CIM) and Linux/macOS autostarts.
- **Plain-English reports** after every scan.

Every verdict carries its evidence: which engine fired, which rule/signature, which hash.

## Value

- The operator can audit *everything that was checked* — including what came back clean.
- Detection is not a black box: ClamAV signature names and YARA rule names are surfaced.
- Nothing is destroyed. Worst case, a false positive is moved and restored in one command.
- The tool is honest about its limits: it is a user-space scanner, not a kernel driver. It does not block execution; it detects and reports.

Success criteria:
- EICAR is detected **and quarantined** end to end, and restored byte-identically.
- A new startup entry appears in the report within one check cycle.
- Weekly full scan completes within a documented time budget on the declared scope.
- Zero writes to `/mnt/c`.

## Product structure

The project is deliberately split into two tracks so that a working product exists before
research is finished:

| Track | What it is | Status |
|---|---|---|
| **MYAV Core** | Antivirus scanning, YARA, file watching, quarantine, scheduled scans, startup inventory, plain-English reports, platform adapters. Deterministic, testable, offline. | Implemented and validated on Linux/WSL2. |
| **MYAV Research** | Behavioural baselines, Machine Learning, graph analysis, sandbox integration, scientific evaluation. Described as a roadmap; no shipped code claims to provide these yet. | Design only. See [RESEARCH_REFERENCES.md](RESEARCH_REFERENCES.md) and [PROJECT_STATUS.md](../PROJECT_STATUS.md). |

This separation is the project's central promise: **no research idea is presented as a protection you actually have.**
