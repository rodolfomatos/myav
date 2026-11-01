# Project status

**Version:** 0.1.0 (Core)
**Last updated:** 2026-11-01
**State:** Core is implemented and tested; Linux/WSL live validation pending one privileged
installer run by the machine's operator.

This page is the single source of truth for "what is done, what is not, and what is being
foolish to assume". If another document disagrees with this one about status, this one wins.

---

## 1. At a glance

| Area | Status | Evidence |
|---|---|---|
| Core scanning pipeline | **Done** | `pytest`: 259 tests, ~94% coverage |
| ClamAV engine | **Done** (stubbed in tests) | `tests/test_engines.py` |
| YARA engine | **Done** (stubbed in tests) | `tests/test_engines.py`, `tests/test_rules.py` |
| VirusTotal engine (hash only) | **Done** (stubbed) | `tests/test_engines.py` |
| Verdict fusion | **Done** | `tests/test_engine_verdict.py` |
| Quarantine (move, verify, restore) | **Done** | `tests/test_quarantine.py` |
| Watcher | **Done** (fake observer in tests) | `tests/test_watcher.py` |
| Startup inventory | **Done** | `tests/test_bootwatch.py` |
| Scheduler rendering | **Done** | `tests/test_scheduler.py` |
| Reports | **Done** | `tests/test_report.py` |
| CLI + exit codes | **Done** | `tests/test_cli.py` |
| Installer script | **Written, dry-run verified** | `bash -n`, `--dry-run` output |
| Live verification script | **Written** | `scripts/verify-live.sh` |
| Documentation set | **Done** | `README.md`, `docs/*.md` |
| Linux/WSL live EICAR proof | **Blocked on operator** | Needs `sudo ./scripts/install-system.sh --apply` |
| Public GitHub release | **Pending** | Repository creation + push |
| macOS validation | **Not started** | Experimental adapter only |
| Native Windows validation | **Not started** | Experimental adapter only |
| Mobile apps | **Not started** | Design doc only |
| Research track (ML/behaviour/sandbox) | **Not started** | References only |

---

## 2. What is genuinely finished

"Finished" here means: implemented, tested, documented, and not dependent on a missing
piece.

### 2.1 The detection pipeline

`src/myav/pipeline.py` scans a file in a fixed order: hash → allowlist check → ClamAV →
YARA → VirusTotal (if configured) → fused verdict → quarantine (if warranted). The order is
the trust order, and every step is covered by tests.

### 2.2 Verdict fusion

`src/myav/verdict.py` implements the normative rules:

- maximum severity wins;
- an engine error never yields `CLEAN`;
- a skipped primary engine yields `UNKNOWN`;
- a skipped secondary engine yields `CLEAN` + a `degraded` entry;
- stale signatures are recorded as degraded.

The report is structurally unable to hide a degraded engine.

### 2.3 Quarantine

`src/myav/quarantine.py` implements verify-then-move-then-verify:

1. hash the source;
2. move it to a generated name;
3. set mode `0000`;
4. hash the stored payload and compare;
5. on mismatch, keep both copies and refuse to unlink;
6. restore re-verifies, refuses to overwrite, restores mode and mtime.

`purge` is the only irreversible operation and requires `--yes`.

### 2.4 Platform capability model

`src/myav/platforms/base.py` defines one adapter per platform and a `Capability` enum. The
CLI asks before acting and exits `3` when a capability is missing. This is why "silently
degraded" cannot happen.

### 2.5 Documentation

Every promised document exists:

`README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `SECURITY.md`, `INSTALLATION.md`,
`CONFIGURATION.md`, `TESTING.md`, `PRIVACY.md`, `LIMITATIONS.md`, `RESEARCH_REFERENCES.md`,
`CHANGELOG.md`, `PROJECT_STATUS.md`, plus `RUNBOOK.md`, `PLATFORMS.md`,
`COMPANION_PROTOCOL.md`, `FAQ.md`, `CONTRIBUTING.md`, `LICENSE`, `NOTICE`, and the Phase-0
`research-review.md`.

---

## 3. What is not finished (be precise)

### 3.1 Live engine proof — blocked on a human

The tests use stubs. Real ClamAV and YARA are not installed yet on the reference machine,
because installing them requires root, and the project's rules forbid the agent from
running `sudo`.

**Exactly what is needed:**

```bash
sudo ./scripts/install-system.sh --apply
./scripts/verify-live.sh
```

`verify-live.sh` will report PASS/WARN/FAIL and end with a verdict. Until that runs, the
honest statement is:

> Detection logic is proven by tests; the real engines are wired but have not been proven
> on this machine.

This is a blocker for the phrase "validated on Linux", not for using the tool.

### 3.2 macOS and native Windows

The adapters exist and are unit-tested with injected platform values. They have not run on
real hardware. Listed as **experimental** everywhere they appear.

To validate: run the seven-step checklist in [docs/PLATFORMS.md](docs/PLATFORMS.md) §10.

### 3.3 Mobile

Design only. [docs/COMPANION_PROTOCOL.md](docs/COMPANION_PROTOCOL.md) is a contract, not an
implementation. `myav companion` does not exist.

### 3.4 Archive scanning

Not implemented. A `.zip` is scanned as one opaque file. [docs/LIMITATIONS.md](docs/LIMITATIONS.md) §4.

### 3.5 Release engineering

Missing:

- signed releases / checksums;
- automated SBOM publication as an artefact (the file is committed, not generated per
  release);
- reproducible builds;
- a dependency-vulnerability scanner in CI.

These are listed as gaps rather than implied by CI running tests.

### 3.6 Research track

Not started. No baseline, no ML model, no sandbox, no graph analysis. Described in
[docs/RESEARCH_REFERENCES.md](docs/RESEARCH_REFERENCES.md) as directions, with the bar any
future model must clear (temporal evaluation, stated false-positive rate, base-rate
honesty).

---

## 4. Known bugs and sharp edges

| # | Issue | Impact | Workaround | Status |
|---|---|---|---|---|
| 1 | YARA 4.1.3 (Ubuntu 22.04) rejects some newer rules | Some rules fail to compile | MYAV reports per-file failures; ClamAV still runs | Open, upstream |
| 2 | WSL EICAR test returns `INCONCLUSIVE` when Defender removes the file | Self-test cannot prove the chain on some WSL setups | Use `myav scan` on a harmless file; never disable Defender | Expected behaviour |
| 3 | `myav doctor` exits `1` until ClamAV is installed | Scripts may treat this as fatal | It is correct: a FAIL means protection is incomplete | Expected |
| 4 | A full scan of a very large home directory can take a long time | No progress bar for the full scan | Use `myav scan PATH` on a narrower scope | Open, low priority |
| 5 | No archive scanning | Malware inside a ZIP is found only after extraction | Extract into a watched folder | Documented limitation |
| 6 | Watcher can miss files created and deleted within the settle window | Short-lived temp files may not be scanned | Accepted: scanning a deleted file is not useful | By design |

Nothing on this list is hidden from users; each is stated where it matters.

---

## 5. What is being worked on next

In order, with no dates promised:

1. **Complete live validation** on Linux/WSL (blocked on the operator's privileged step).
2. **Publish the repository** publicly with CI green and the documentation map complete.
3. **Harden the installer** for Fedora and Arch after someone validates those paths.
4. **Add a per-file progress line** for long full scans.
5. **Evaluate archive scanning** with a memory-bomb budget before promising it.
6. **Write the first validation report** for macOS or Windows, whoever gets there first.

Research track items are deliberately not in this list. They start only after Core is
validated and published.

---

## 6. How to read the status honestly

Three sentences that summarise the project:

1. **The logic is real:** 259 tests, ~94% coverage, and the dangerous modules (quarantine,
   verdict, config, rules) have adversarial tests.
2. **The engines are wired but unproven on this machine:** one privileged command, run by a
   human, closes that gap.
3. **Everything adaptive, mobile, or multi-platform beyond Linux/WSL is a documented
   intention, not a shipped capability.**

If a future version of this page cannot repeat those three sentences accurately, the
project has started lying to itself.

---

## 7. Verification commands

Run these to check the claims above:

```bash
# 1. Logic
.venv/bin/python -m pytest
.venv/bin/python -m ruff check src tests

# 2. Packaging and CLI
.venv/bin/myav version
.venv/bin/myav platforms
.venv/bin/myav doctor          # exits 1 until the engines are installed

# 3. Installer safety
bash -n scripts/install-system.sh
./scripts/install-system.sh --dry-run

# 4. Live (needs root, operator)
sudo ./scripts/install-system.sh --apply
./scripts/verify-live.sh
```

Expected today: 1–3 pass; 4 is the pending step.
