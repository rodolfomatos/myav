# MYAV — My Adaptive Antivirus

**A local-first antivirus and endpoint monitor that explains itself.**

MYAV scans files for known malware, watches the folders where new files arrive, keeps a
reversible quarantine, and writes a plain-English report after every scan. It is built from
open-source parts, runs on your own computer, and never uploads file contents anywhere unless
you explicitly allow it.

> **What “local-first” means, in plain words.** The detective work happens on your machine,
> using files and databases stored on your machine. There is no company server, no account,
> no telemetry. If your internet cable is unplugged, MYAV still scans.

---

## Start here (the 60-second version)

1. **Read what MYAV is and is not** — [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
2. **Install it** — [docs/INSTALLATION.md](docs/INSTALLATION.md).
3. **Check it works** — `./bin/myav doctor` then `./bin/myav selftest`.
4. **Use it** — [docs/RUNBOOK.md](docs/RUNBOOK.md).
5. **Configure it (including VirusTotal)** — [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

If you only read one file after this one, read `docs/LIMITATIONS.md`. It is short and it
prevents the most common misunderstanding: **MYAV detects, it does not block.**

---

## What it does

| Capability | What actually happens | Where it is explained |
|---|---|---|
| Signature scanning | ClamAV compares file bytes with a database of known malware | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Pattern scanning | YARA rules look for shapes (scripts, webshells, miner configs) | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Nightly updates | `freshclam` refreshes the signature database at 02:30 | [docs/INSTALLATION.md](docs/INSTALLATION.md) |
| Folder watching | New files in Downloads, Desktop, Documents and USB mounts are scanned | [docs/RUNBOOK.md](docs/RUNBOOK.md) |
| Reversible quarantine | Suspicious files are moved, hash-verified, stored non-executable, and can be restored | [docs/RUNBOOK.md](docs/RUNBOOK.md) |
| Weekly full scan | Sunday 03:00, with a written report | [docs/RUNBOOK.md](docs/RUNBOOK.md) |
| Startup inventory | Lists programs that start at login and flags new ones | [docs/PLATFORMS.md](docs/PLATFORMS.md) |
| Optional hash reputation | VirusTotal is asked about a file **hash only**, never the file | [docs/CONFIGURATION.md](docs/CONFIGURATION.md) |
| Plain-English reports | Counts, evidence, quarantine list, and what to do next | [docs/RUNBOOK.md](docs/RUNBOOK.md) |

## What it does **not** do

- It does not stop a program from running. It is a detector, not a driver-level blocker.
- It does not scan the Windows `C:` drive from WSL. That is intentional and enforced.
- It does not upload files. VirusTotal lookups send a hash, and only if you configure a key.
- It does not claim to catch zero-days, kernel malware, or fileless attacks reliably.
- It does not delete anything automatically. Quarantine is a move, and it is reversible.

The full list, including the reasons, is in [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

---

## The two halves of MYAV

MYAV is deliberately split so that a useful product exists before the research is finished.

**MYAV Core** — the part you can install today:
signature scanning, YARA, file watching, quarantine, scheduled scans, startup inventory,
plain-English reports, and the platform adapters. It is deterministic, testable, and offline.
It lives in [`src/myav/`](src/myav/) and is documented in this repository.

**MYAV Research** — the experimental track:
behavioural baselines, machine learning, graph analysis, sandbox integration, and scientific
evaluation. It is described as a roadmap, not sold as a working feature. See
[docs/RESEARCH_REFERENCES.md](docs/RESEARCH_REFERENCES.md) and
[docs/PROJECT_STATUS.md](docs/PROJECT_STATUS.md).

This separation is the project’s central promise: **no research idea is presented as a
protection you actually have.**

---

## Works on which equipment?

MYAV is written to run anywhere Python and the two engines run. The honest status column says
where it has actually been proven, not where it merely compiles.

| Equipment | What you get | Status | Start here |
|---|---|---|---|
| **Linux PC** (Ubuntu, Debian, Fedora, Arch) | Full scanner, watcher, scheduled jobs | **Validated** (run the live proof once) | [Install on Linux](docs/INSTALLATION.md#which-kind-of-equipment-do-you-have) |
| **Windows PC with WSL2** (Ubuntu) | Full scanner for the Linux side; Windows Task Scheduler triggers it | **Validated** on Ubuntu 22.04 / WSL2 | [Install with WSL2](docs/INSTALLATION.md#windows-note-recommended-wsl2) |
| **Mac** (Intel or Apple Silicon) | Full scanner via Homebrew and launchd | **Experimental** adapter | [Install on macOS](docs/INSTALLATION.md#macos-note) |
| **Windows PC, native** | Scanner using Windows ClamAV/YARA builds | **Experimental**, not yet validated | [Native Windows recipe](docs/INSTALLATION.md#native-windows-experimental-no-wsl) |
| **Android phone** | Companion that asks a desktop to scan; **no app is shipped** | Design only | [Mobile tiers](docs/PLATFORMS.md) |
| **iPhone / iPad** | Not supported: iOS forbids watching other apps’ files | Design only | [Mobile tiers](docs/PLATFORMS.md) |

**Short version for a normal laptop:** Python 3.10+, ClamAV, YARA, and one of Linux / WSL2 /
macOS. The first fully validated platform is Linux and WSL2. If your system is not listed, the
code may still run; open an issue and say what happened.

The capability matrix in [docs/PLATFORMS.md](docs/PLATFORMS.md) states exactly what is proven
where, including which scheduler each platform uses and what happens to a missed scan.

---

## Install in four commands

### Linux or WSL2 (validated)

```bash
git clone https://github.com/rodolfomatos/myav.git
cd myav
python3 -m venv .venv && .venv/bin/pip install -e .
./scripts/install-system.sh --dry-run     # read what will happen
```

Then ask the human with the administrator password to run:

```bash
sudo ./scripts/install-system.sh --apply
```

and finally, as your normal user:

```bash
./bin/myav doctor
./bin/myav rules fetch --accept-license
./bin/myav selftest
```

### macOS (experimental)

```bash
git clone https://github.com/rodolfomatos/myav.git
cd myav
python3 -m venv .venv && .venv/bin/pip install -e .
./scripts/install-system.sh --dry-run
sudo ./scripts/install-system.sh --apply
./bin/myav doctor && ./bin/myav selftest
```

### Native Windows (experimental)

```powershell
git clone https://github.com/rodolfomatos/myav.git
cd myav
python -m venv .venv
.venv\Scripts\pip install -e .
.venv\Scripts\myav doctor
```

Full instructions for every platform, including the Windows ClamAV/YARA setup and what to do
when a step fails, are in [docs/INSTALLATION.md](docs/INSTALLATION.md). Configuration —
including the optional VirusTotal key, explained as if you have never heard of an API — is in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

---

## Project principles

1. **Explain before acting.** Every privileged step is printed before it runs.
2. **Never delete without confirmation.** Quarantine is reversible; purge needs `--yes`.
3. **Local by default.** External lookups are opt-in and hash-only.
4. **Say “I don’t know.”** A missing engine produces `UNKNOWN`, never a false `CLEAN`.
5. **No invented science.** References are real and verifiable; unverified ideas are labelled.
6. **Small, testable modules.** The test suite is part of the product, not an afterthought.

---

## Documentation map

| Document | Answers the question |
|---|---|
| [README.md](README.md) | What is this? |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | How do I install it on my machine? |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | What does each setting do? How do I get a VirusTotal key? |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | What do I do when it alerts? How do I restore a file? |
| [docs/PLATFORMS.md](docs/PLATFORMS.md) | Does it work on Windows/macOS/mobile? |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How is it built, and why in this order? |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What attacks does it consider, including against itself? |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | What can it **not** do? |
| [docs/PRIVACY.md](docs/PRIVACY.md) | What data leaves my computer? |
| [docs/TESTING.md](docs/TESTING.md) | How do I know it works? |
| [docs/RESEARCH_REFERENCES.md](docs/RESEARCH_REFERENCES.md) | What science is this based on? |
| [docs/COMPANION_PROTOCOL.md](docs/COMPANION_PROTOCOL.md) | How would a phone talk to it? |
| [docs/FAQ.md](docs/FAQ.md) | Quick answers to common questions |
| [SECURITY.md](SECURITY.md) | How do I report a vulnerability? |
| [PROJECT_STATUS.md](PROJECT_STATUS.md) | What is done, what is next, what is broken? |
| [CHANGELOG.md](CHANGELOG.md) | What changed? |

---

## Licence

Apache License 2.0. See [LICENSE](LICENSE). The optional YARA pack
(`Neo23x0/signature-base`) has its own licence (Detection Rule License 1.1) and is **never
vendored** into this repository; `myav rules fetch` downloads a pinned copy after you accept it.

---

## A note on honesty

A green shield is easy to draw. MYAV refuses to draw one it cannot justify. If ClamAV is
missing, the report says so. If a signature database is stale, the report says so. If a file
could not be read, the verdict is `UNKNOWN`, not `CLEAN`. That habit is the product.
