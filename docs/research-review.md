# Phase 0 — research review, technology comparison, and the decision to build

This document is the record of the work done **before** any system was changed. It exists
so that the project's direction can be judged on its reasoning rather than on its
enthusiasm.

Phase 0 answers eight questions:

1. What already exists?
2. Which technologies could we build on, and how do they compare?
3. What threats are we actually addressing?
4. What can each platform really do?
5. What is the architecture, and why in that order?
6. What are we depending on, and under what licence?
7. What is the plan, in phases?
8. What did we decide, and what is still unproven?

The short version: **build a small, honest, local detector on top of ClamAV and YARA,
with a reversible quarantine and a readable report; put everything adaptive in a separate
research track; validate one platform end-to-end before claiming another.**

---

## 1. Research review — what already exists

### 1.1 The open-source landscape

| Project | What it is | Strength | Why it is not the whole answer |
|---|---|---|---|
| **ClamAV** | Open-source signature AV engine (Cisco, Apache-2.0) | Mature signature database, `clamd` daemon, cross-platform, free | Signature-only ceiling; not a scheduler, watcher, quarantine UI, or reporting layer |
| **YARA** | Pattern-matching engine for malware rules | Expressive, fast, huge public rule ecosystem | A rule language, not a product; no state, no workflow |
| **signature-base (Neo23x0)** | Large public YARA pack | Practical, maintained, permissive-but-conditional licence | Rules only; licence restricts commercial use; quality varies |
| **ClamTK / ClamAV GUI** | Desktop GUIs for ClamAV | Easy for non-technical users | GUI only; no watcher/scheduler story; limited reporting |
| **chkrootkit / rkhunter** | Rootkit scanners | Different detection surface | Not signature AV; different threat class |
| **OSSEC / Wazuh** | Host intrusion detection | Log/behaviour correlation, central management | Heavy; server-oriented; not a local-first consumer tool |
| **MalwareBazaar / AbuseCH tooling** | Sample feeds | Fresh indicators | Feeds, not a scanner; privacy and legal considerations |
| **ClamAV + systemd + a shell script** | The common DIY approach | Simple | No quarantine protocol, no report contract, no tests, no platform abstraction |

**Conclusion:** the *engines* are solved and free. The missing piece is the **product
layer**: a watcher that debounces, a quarantine that is reversible and hash-verified, a
scheduler that works on WSL, a report a non-expert can read, and an honest capability
model. That is what MYAV Core is.

### 1.2 The closed-source baseline (for comparison only)

Commercial endpoint suites use kernel drivers or minifilters, cloud reputation, and
behavioural engines. They are genuinely stronger at *blocking*. They are also:

- not auditable;
- not local-first (most phone home);
- not free;
- not something a user can modify or verify.

MYAV does not compete on blocking. It competes on **explainability, privacy, and
auditability** — and it says so in [LIMITATIONS.md](LIMITATIONS.md) §1.

### 1.3 What the literature says (summary)

The research review is in [RESEARCH_REFERENCES.md](RESEARCH_REFERENCES.md). The three
findings that shaped the design:

1. **Signature matching has a hard ceiling** against new samples (Kolter & Maloof 2006;
   the general consensus since). → MYAV must never call CLEAN "safe".
2. **ML detectors fail under real base rates and adversarial drift** (Sommer & Paxson
   2010). → no ML in Core.
3. **Malware evaluation is easy to do wrong** (Rossow et al. 2012; Pendlebury et al.
   2019). → no detection-rate claims without a stated methodology.

---

## 2. Technology comparison

### 2.1 Engine choice

| Option | Signature quality | Pattern rules | Daemon | Cross-platform | Licence | Decision |
|---|---|---|---|---|---|---|
| ClamAV | Large, free, updated daily | No | Yes (`clamd`) | Yes | Apache-2.0 | **Primary engine** |
| YARA | No | Yes, excellent | No | Yes | BSD-3-Clause | **Secondary engine** |
| Commercial SDK | Large | Varies | Varies | Varies | Paid, restrictive | Rejected: cost, licence, no audit |
| Build our own signatures | Would start empty | — | — | — | — | Rejected: years of work, worse result |
| VirusTotal only | Other engines' opinions | No | n/a | n/a | API terms | Rejected as primary: needs network, rate-limited, privacy cost |

**Decision:** ClamAV primary, YARA secondary, VirusTotal optional third opinion. This is
also the order of trust: a ClamAV signature is stronger evidence than a YARA heuristic,
which is stronger than "some other engine said so".

### 2.2 Language and runtime

| Option | Fit | Why |
|---|---|---|
| **Python 3.10+** | Chosen | Fast to build, excellent `watchdog`/`sqlite3`/`tomllib`, easy for contributors to audit, no compilation step |
| Go | Considered | Single binary is attractive; weaker YARA/ClamAV library maturity at the time; slower iteration |
| Rust | Considered | Safety and performance; higher contribution barrier for a small project |
| C | Rejected | Memory-safety risk in a security tool is unacceptable |
| Node/Electron | Rejected | Heavy runtime, poor fit for a daemon and a scheduler |

Python's weakness — packaging and startup time — is acceptable for a scheduler-driven tool
that runs a few times a day plus a watcher.

### 2.3 Storage

| Option | Decision |
|---|---|
| **SQLite (WAL)** | Chosen: single file, transactional, queryable, zero administration, stdlib |
| JSON files | Rejected: concurrent writers and partial writes are a corruption risk |
| A server database | Rejected: absurd for a single-user local tool |

### 2.4 Scheduling

| Platform | Mechanism | Why |
|---|---|---|
| Linux | systemd **user** timers | No root needed; survives logout with lingering |
| WSL | Windows Task Scheduler via `wsl.exe` | systemd is often disabled; this is the only reliable trigger |
| macOS | launchd agents | Native mechanism for per-user jobs |
| Windows | Task Scheduler | Native mechanism |

A cron entry was rejected for Linux because systemd timers give better logging and
dependency handling, and because the project already needs a systemd unit for `clamd`.

### 2.5 Watching

| Option | Decision |
|---|---|
| **watchdog** (inotify / FSEvents / `ReadDirectoryChangesW`) | Chosen: one API, three platforms, maintained |
| Polling | Rejected: wasteful on battery; misses short-lived files |
| Fanotify (Linux) | Rejected for v1: requires privileges and is not portable |
| Kernel driver | Out of scope: different risk profile (see LIMITATIONS §1) |

---

## 3. Threat model (summary)

The full model is [THREAT_MODEL.md](THREAT_MODEL.md). Its two halves:

**A. Malware MYAV tries to catch.** Known families (ClamAV), suspicious patterns (YARA),
known-bad reputation (VirusTotal hash), persistence (startup inventory), files arriving
via browser/USB (watcher).

**B. MYAV as an attack surface.** Twelve enumerated threats, each with a mitigation:

- rule supply-chain compromise → pinned commit + archive hash + provenance;
- quarantine as an executable stash → mode `0000`, random names;
- path traversal into quarantine → generated paths, `O_NOFOLLOW`;
- TOCTOU between scan and move → hash-before / hash-after;
- decompression/size DoS → size cap, timeouts, no archives in v1;
- credential leak → `0600`, redaction, a test asserting the key never appears in output;
- privacy leak → hash-only, opt-in;
- privilege abuse → no `sudo` in Python, root only in the installer;
- false positive destroying work → reversible quarantine, allowlist, named evidence;
- world-writable watch dirs → bounded queue, size caps;
- Defender/EICAR race → INCONCLUSIVE, never "disable Defender";
- stale signatures masquerading as protection → age in every report, stale flag.

The B list is the one that matters. A security tool that is itself a soft target makes
the machine worse, not better.

---

## 4. Capability matrix

Proven vs claimed, per platform. The full table is [PLATFORMS.md](PLATFORMS.md) §1.

| Capability | Linux | WSL2 | macOS | Windows | Android | iOS |
|---|---|---|---|---|---|---|
| Scan on demand | Yes | Yes | Yes | Yes | Yes | Share sheet |
| Watch folders | Yes | Yes | Yes | Yes | No | No |
| Daemon | Yes | Yes | Yes | Yes | n/a | n/a |
| Scheduler | systemd | Task Scheduler | launchd | Task Scheduler | planned | No |
| Startup inventory | Yes | Yes (+Windows) | Yes | Yes | n/a | n/a |
| Quarantine | Yes | Yes | Yes | Yes | sandbox | sandbox |
| **Validated** | **Yes** | **Yes** | No | No | No | No |

**Rule adopted:** a capability is only advertised after it is exercised. The CLI asks the
adapter and exits `3` rather than silently degrading.

---

## 5. Architecture (the reasoning, not the diagram)

The diagram is in [ARCHITECTURE.md](ARCHITECTURE.md). The reasoning:

1. **Scan order is trust order.** Hash → allowlist → ClamAV → YARA → VirusTotal → fuse.
   ClamAV goes first because it is the strongest evidence and its failure must produce
   UNKNOWN, not a quiet pass.
2. **Fusion is maximum severity with a special rule.** An error can raise the verdict to
   UNKNOWN but never lower it. A skipped *secondary* engine is degraded evidence, not a
   failure.
3. **Quarantine is verify-then-move, then verify again.** Hash before, move, hash the
   stored payload, compare. A mismatch keeps both copies and refuses to unlink. Deletion
   is never part of detection.
4. **The report is the interface.** Counts must reconcile; a degraded engine must be
   visible; a clean verdict must say what it does not mean.
5. **Platform capability is data, not `if` statements.** One adapter per platform, one
   capability enum, one refusal path.
6. **Nothing privileged in Python.** The installer is a separate script, reviewed line by
   line, dry-run by default.

That ordering is why the codebase has `verdict.py` and `quarantine.py` as the two most
carefully tested modules.

---

## 6. Dependency and licence review

### 6.1 Runtime dependencies

| Dependency | Purpose | Licence | Risk |
|---|---|---|---|
| Python ≥ 3.10 | Runtime | PSF-2.0 | Low |
| `watchdog` | File system events | Apache-2.0 | Low; per-platform backends |
| `tomli` (only on Python < 3.11) | TOML parsing | MIT | Low |
| ClamAV | Signature engine (external binary) | Apache-2.0 (engine), GPL-2.0 (some tools) | Medium: system package, signature DB is large |
| YARA | Pattern engine (external binary) | BSD-3-Clause | Low |
| `yara-python` (optional) | Faster YARA binding | Apache-2.0 | Low; falls back to CLI |

### 6.2 Optional / development dependencies

| Dependency | Purpose | Licence |
|---|---|---|
| `pytest` | Test runner | MIT |
| `pytest-cov` | Coverage | MIT |
| `ruff` | Lint and format | MIT |

### 6.3 Data and rule licences

| Asset | Licence | Obligation |
|---|---|---|
| ClamAV signature database | Own terms (free to use with ClamAV) | Redistribution rules apply if you mirror it |
| `Neo23x0/signature-base` | Detection Rule License 1.1 | **Free for non-commercial use**; review before commercial deployment |
| EICAR test file | Free to use for testing | Not malware; safe to recreate |
| VirusTotal API | VirusTotal terms | Account required; rate limits; hash lookups only |

### 6.4 MYAV's own licence

**Apache-2.0.** Chosen because it is permissive, includes an explicit patent grant, and is
compatible with the engines and libraries above. The rule pack is **not** vendored, so its
conditional licence does not propagate into this repository.

### 6.5 Supply-chain controls

1. YARA pack pinned by commit; archive SHA-256 recorded in `PROVENANCE.json`.
2. No rules in git.
3. Small dependency set, pinned in `pyproject.toml`.
4. SBOM generated (see `docs/sbom/`).
5. Release signing: **not yet implemented** — listed as missing in
   [PROJECT_STATUS.md](../PROJECT_STATUS.md).

---

## 7. Plan

| Phase | Goal | Exit condition |
|---|---|---|
| **0** | Research, comparison, threat model, architecture, dependency review | This document, approved |
| **1** | Core skeleton: paths, config, state, verdict | Unit tests green |
| **2** | Engines: ClamAV, YARA, VirusTotal | Engine tests green with stubs |
| **3** | Pipeline, quarantine, report | Quarantine tests green, including TOCTOU |
| **4** | Watcher, bootwatch, scheduler, CLI | CLI exit-code contract tested |
| **5** | Installer, live verification, docs | `verify-live.sh` healthy on Linux |
| **6** | Public release | Repository public, CI green, docs complete |
| **R** | Research track | Separate; no date; no claims until measured |

Phase 5's live step needs a human with root to run the installer. That is a deliberate
boundary, not a delay: the project does not grant itself privilege.

---

## 8. Decisions and open questions

### Decided

| # | Decision | Rationale |
|---|---|---|
| D1 | Apache-2.0 | Permissive, patent grant, compatible |
| D2 | ClamAV + YARA, VirusTotal optional | Strongest free evidence, in trust order |
| D3 | Python 3.10+ | Fast iteration, auditable, no build step |
| D4 | SQLite (WAL) | Transactions without a server |
| D5 | Quarantine is move + verify, never delete | Reversibility is the safety property |
| D6 | Detection only, no kernel driver | Different risk profile; honesty over marketing |
| D7 | Core vs Research split | No unmeasured feature is sold as protection |
| D8 | Validate Linux/WSL first | One proven platform beats five claimed ones |
| D9 | Installer is a script, dry-run by default, never calls `sudo` | Privilege must be explicit |
| D10 | `/mnt/c` excluded and write-guarded | Slow, and filling C: is a real failure mode |

### Open / unproven

| # | Question | Status |
|---|---|---|
| O1 | Does the macOS adapter work on real hardware? | Unknown; needs validation |
| O2 | Does native Windows path handling hold? | Unknown; needs validation |
| O3 | What is MYAV's false-positive rate on real user files? | Unmeasured |
| O4 | Should archives be scanned in v2? | Open; needs a memory-bomb budget |
| O5 | Is a companion app worth building? | Design only; no demand measured |
| O6 | Would a behaviour baseline help or just add noise? | Research; needs a base-rate study |

### Explicit non-goals

- Kernel-level blocking.
- Network intrusion detection.
- Cloud management console.
- Detection-rate marketing claims.
- Mobile "full antivirus".

---

## 9. Approval gate

Phase 0 ends with a human decision. The questions asked before any system change:

1. Is the threat model honest about what is not covered?
2. Is the Core/Research split real, or marketing?
3. Does the quarantine protocol ever delete a file without confirmation? (No.)
4. Does anything leave the machine by default? (No.)
5. Is the one privileged step reviewable before it runs? (Yes: dry-run default.)
6. Is the first validated platform actually validated, or assumed? (Actually validated:
   unit suite, live verification, EICAR.)
7. Are the references real? (Yes; see RESEARCH_REFERENCES.md.)

The plan was approved on those terms, with the explicit caveat that the live engine
installation requires the machine's operator to run one privileged command.

---

## Summary

Phase 0 concluded that the engines are commodities and the product layer is the work. The
project therefore builds a small, testable, explainable detector with a reversible
quarantine; refuses to claim blocking, adaptivity, or multi-platform validation it does not
have; and keeps every unmeasured idea in a separate research track. The rest of this
repository is the execution of that decision.
