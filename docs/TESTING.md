# Testing — how you know MYAV works

A security tool that has not been tested is a rumour. This page explains what is tested,
how to run the tests yourself, and — more importantly — what the tests **cannot** prove.

There are three layers:

1. **Unit and integration tests** — fast, hermetic, run on any machine, no ClamAV needed.
2. **Live verification** — runs against the real engines installed on your machine.
3. **The EICAR self-test** — proves the full chain with a harmless test file.

---

## 1. Run the test suite

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest
```

Expected: all tests pass and coverage stays above 80%.

With lint:

```bash
.venv/bin/python -m ruff check src tests
```

Expected: `All checks passed!`

Run one file, or one test, while developing:

```bash
.venv/bin/python -m pytest tests/test_quarantine.py -v
.venv/bin/python -m pytest tests/test_pipeline.py::test_vt_failure_does_not_downgrade -v
```

---

## 2. What the tests actually cover

| Area | File | What is proven |
|---|---|---|
| Verdict fusion | `tests/test_engine_verdict.py` | Severity ordering; an engine error never becomes CLEAN; a skipped primary engine becomes UNKNOWN; a skipped secondary engine becomes CLEAN + degraded |
| Engines | `tests/test_engines.py` | ClamAV output parsing (`FOUND`/`OK`/error), daemon-then-binary fallback, YARA severity mapping, VirusTotal response handling and rate limits |
| Pipeline | `tests/test_pipeline.py` | Scan order, allowlist short-circuit, hash-before/hash-after, VT failure does not downgrade, dry-run keeps the file |
| Quarantine | `tests/test_quarantine.py` | Random payload names, mode `0000`, hash verification, restore refuses to overwrite, TOCTOU mismatch keeps both copies |
| State | `tests/test_state.py` | Schema creation, scan history, allowlist, boot baseline first-run semantics, VT cache |
| Config | `tests/test_config.py` | `0600` enforcement, `~` expansion, severity validation, key redaction, TOML errors |
| Paths | `tests/test_util_paths.py` | `/mnt/c` write refusal, removable-mount classification, directory modes |
| Reports | `tests/test_report.py` | Counts reconcile (`scanned == clean + suspicious + malicious + unknown`), a clean scan never says "safe", degraded engines are visible, retention pruning |
| Rules | `tests/test_rules.py` | Path-traversal refusal during extraction, per-file compile failures, provenance written, licence gate |
| Scheduler | `tests/test_scheduler.py` | systemd/launchd/Task Scheduler rendering, nothing written without `yes=True`, root units printed not written |
| Bootwatch | `tests/test_bootwatch.py` | CIM and registry parsing, desktop-file parsing, first-run baseline, new-entry detection |
| Self-test | `tests/test_selftest.py` | EICAR success path, INCONCLUSIVE when ClamAV missing, INCONCLUSIVE when the file vanishes, real failure when detection misses |
| Watcher | `tests/test_watcher.py` | Ignore rules, settle/debounce, dedupe, queue overflow counting, once-mode scan |
| CLI | `tests/test_cli.py` | Every command, exit-code contract, exception translation, redaction |

### The test fixtures are adversarial on purpose

`tests/conftest.py` gives every test a **temporary home directory**. No test can touch
your real `~/.config/myav`, your real quarantine, or your real database. That is not
politeness — a test suite that quarantines your files is itself malware.

The fixture `StubClam` can return MALICIOUS, CLEAN, or be unavailable. This lets the suite
prove the detection *protocol* without installing ClamAV, which is why CI works on a bare
runner.

---

## 3. Live verification on your machine

The unit tests use stubs. To prove the real engines work, run:

```bash
./scripts/verify-live.sh
```

It is read-only. It checks:

| Check | What it proves |
|---|---|
| `myav version` | the CLI starts and finds its interpreter |
| `myav doctor` | every dependency is visible |
| `myav rules status` | the YARA pack exists |
| `myav schedules status` | recurring jobs are installed |
| `myav quarantine list` | the state database is readable |
| `myav selftest` | ClamAV really detects, quarantines and restores EICAR |

Output ends with a verdict:

```text
PASS: 8   WARN: 2   FAIL: 0
Verdict: WORKING, with warnings.
```

- **HEALTHY** — everything proven.
- **WORKING, with warnings** — optional steps missing; detection works.
- **NOT HEALTHY** — fix the FAIL lines before trusting any CLEAN report.

---

## 4. The EICAR self-test, in detail

EICAR is a 68-byte ASCII string that every antivirus agrees to detect. It is **not**
malware; it cannot execute. It is the standard way to test an AV product without
handling real samples.

```bash
myav selftest
```

The test proves twelve things, in order:

```text
PASS  test file written
PASS  test file hash recorded
PASS  verdict is MALICIOUS
PASS  ClamAV named the Eicar signature
PASS  source file was removed
PASS  quarantine record created
PASS  payload exists
PASS  payload hash matches the original
PASS  payload is not executable
PASS  restore returned a path
PASS  restored file hash matches
PASS  no test artefacts left in the sandbox
```

That sequence is the whole product in miniature: **detect → move → verify → restore →
verify → clean up**. If any assertion fails, the chain is broken somewhere specific.

### Why you might see INCONCLUSIVE (exit 5)

On WSL, Windows Defender scans files inside the Linux filesystem too. It often removes
the EICAR file between the moment MYAV writes it and the moment MYAV scans it. MYAV then
has nothing to detect and reports:

```text
INCONCLUSIVE: the EICAR file disappeared before myav could scan it. Windows Defender
real-time protection does this to files inside WSL. This is not a myav bug.
```

**Do not disable Defender to make the test pass.** Defender doing its job is good. Instead:

```bash
myav scan ~/Downloads/some-harmless-file.txt   # proves the CLI and engines run
```

and trust the fixture-based tests for the detection protocol.

---

## 5. What the tests cannot prove

This is the honest section.

| Not proven by the suite | Why | How to cover it |
|---|---|---|
| Real malware detection accuracy | The suite uses stubs; shipping real samples is a legal and safety problem | Use EICAR; optionally test with the `eicar.com` file from a lab |
| False-positive rate against your files | Only your files can tell you that | Run `myav full-scan` and read the report; allowlist genuine false positives |
| Performance on a large disk | CI runners are small | Run a full scan and read the duration in the report |
| macOS / Windows native behaviour | No CI hardware | Run `scripts/verify-live.sh` on those systems |
| Kernel-level attacks | Out of scope by design | Not covered — see [LIMITATIONS.md](LIMITATIONS.md) |
| That a CLEAN file is safe | Signature scanning cannot prove a negative | Not covered, and no tool can |

The last row is the one that matters. **A passing test suite does not mean your machine is
clean.** It means MYAV's logic behaves as specified.

---

## 6. Continuous integration

The repository ships CI configuration for GitHub Actions
(`.github/workflows/`) and generic runners (`.woodpecker.yml`, `.gitlab-ci.yml`). The
pipeline runs:

```text
ruff check src tests
pytest --cov=src --cov-fail-under=80
```

CI does **not** install ClamAV or YARA. It tests the logic, not the engines. The live
engines are verified by `scripts/verify-live.sh` on a real machine.

That split is deliberate: CI must be fast and reproducible; engine installation must be
inspectable and privileged.

---

## 7. Adding a test

When you change behaviour, add a test that would fail before the change. Two rules:

1. **Use the temp-home fixtures.** Never write to the real home.
2. **Assert the contract, not the implementation.** For example, assert that a skipped
   primary engine yields UNKNOWN, not that a particular function was called.

Example — a test for a new allowlist short-circuit:

```python
def test_allowlisted_hash_skips_engines(paths, state, config, platform, tmp_path):
    target = tmp_path / "trusted.bin"
    target.write_text("trusted")
    state.allow(sha256_file(target), reason="test")
    engines = make_engines(platform, clam=StubClam(MALICIOUS))
    outcome = scan_file(target, engines, config, paths, state)
    assert outcome.verdict.level == "CLEAN"
    assert not outcome.quarantined
```

Run it, watch it pass, then break the implementation on purpose and watch it fail. A test
you have never seen fail is a test you cannot trust.

---

## 8. Reproducing a bug report

If you report a bug, include:

```bash
myav version
myav doctor
myav platforms
```

and, for a scan bug, the report with paths redacted. Never paste your VirusTotal key.

A minimal reproduction is worth more than a paragraph. If you can turn it into a failing
test, the fix is usually obvious.

---

## Summary

| Layer | Command | Needs ClamAV? | Proves |
|---|---|---|---|
| Unit/integration | `pytest` | No | Logic and contracts |
| Lint | `ruff check` | No | Style and common errors |
| Live verification | `./scripts/verify-live.sh` | Yes | Real engines on this machine |
| EICAR | `myav selftest` | Yes | Detect → quarantine → restore chain |

Run the first two on every change. Run the last two on every machine before you trust it.
