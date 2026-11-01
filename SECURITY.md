# Security policy

MYAV is a security tool. A vulnerability in it is more serious than the same bug in an
ordinary program, because users install it precisely when they are worried about
compromise.

This page explains what counts as a vulnerability, how to report one privately, and what
you can expect.

---

## 1. Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately, in this order of preference:

1. **GitHub private vulnerability reporting** — on the repository page, *Security* →
   *Report a vulnerability*. This creates a private advisory visible only to maintainers.
2. If that is unavailable, email the maintainer listed in `pyproject.toml` / the
   repository profile, with `MYAV SECURITY` in the subject.

Include:

- a description of the issue and why it matters;
- the affected version (`myav version`) and platform (`myav platforms`);
- reproduction steps, ideally a minimal one;
- the impact you believe it has;
- whether you want public credit.

**Never include:**

- your VirusTotal API key;
- real malware samples;
- personal file paths from a report (redact them).

If a sample is necessary, use EICAR or a synthetic file and describe what it represents.

---

## 2. What counts as a vulnerability

### In scope

| Class | Examples |
|---|---|
| **Quarantine integrity** | A crafted path escapes the quarantine directory; restore overwrites an unrelated file; a payload can be executed from quarantine; a TOCTOU window is exploitable |
| **Privilege escalation** | Anything in MYAV that lets an unprivileged user gain root, or that makes the installer do so accidentally |
| **Command / argument injection** | A filename or YARA rule that becomes shell syntax; `subprocess` called with `shell=True` on untrusted input |
| **Path traversal** | Rule extraction writing outside the rules directory; report or log paths escaping their directory |
| **Credential disclosure** | The VirusTotal key appearing in logs, reports, `--json` output without `--reveal`, error messages, or process arguments |
| **Privacy violation** | Any network request that sends file contents, file names, or paths; any request made with VirusTotal disabled |
| **Rule supply-chain** | Accepting an archive without verifying the pinned commit/hash; extracting outside the intended tree |
| **Unsafe defaults** | A default that exposes `clamd` beyond loopback; a world-readable config; a scheduler entry that runs as root unnecessarily |
| **Denial of service** | A local file that makes MYAV consume unbounded memory or CPU beyond the documented size/time caps |
| **Dependency vulnerability** | A known-vulnerable pinned dependency with a plausible exploit path |

### Out of scope

| Class | Why |
|---|---|
| "MYAV did not detect my malware sample" | Signature scanning has a documented ceiling; see [LIMITATIONS.md](../docs/LIMITATIONS.md) §2 |
| "MYAV is not a real-time blocker" | Documented design; see [LIMITATIONS.md](../docs/LIMITATIONS.md) §1 |
| Missing features (archive scan, behaviour analysis) | Roadmap, not vulnerability |
| Attacks requiring root already | Root can do anything; see the trust boundary in [THREAT_MODEL.md](../docs/THREAT_MODEL.md) §C |
| Reports containing paths | Expected; reports are local files. Redact before sharing |
| Windows Defender removing EICAR | Expected; the self-test reports INCONCLUSIVE |
| Native Windows/macOS adapter bugs | Still security-relevant — report them; they are just not *validated* |

If you are unsure, report it. A false alarm costs a conversation; a missed one costs
someone's files.

---

## 3. What you can expect

| Stage | Target |
|---|---|
| Acknowledgement | Within 7 days |
| Initial assessment (in scope? severity?) | Within 14 days |
| Fix or mitigation plan for high severity | Within 30 days |
| Public disclosure | Coordinated, after a fix is available, default 90 days |

These are targets for a small project, not a contractual SLA. If a fix takes longer, you
will be told why rather than left waiting.

### Severity guide

| Severity | Example | Response |
|---|---|---|
| **Critical** | Quarantine escape that executes code; key exfiltration to a third party | Fix immediately, release, advisory |
| **High** | Restore overwrites an arbitrary file; installer privilege bug | Fix before next release |
| **Medium** | Redaction gap in a rarely used output path; a DoS with a plausible local trigger | Fix in the next release |
| **Low** | Information disclosure with no practical impact; hardening suggestion | Fix when convenient, documented |

---

## 4. Security properties MYAV claims (and how they are enforced)

These are the promises worth attacking. Each has a test or a code path you can read.

| Property | Enforced by | Test |
|---|---|---|
| The config is never world-readable | `config.py` checks mode before parsing | `tests/test_config.py` |
| MYAV dirs are `0700` | `paths.ensure_dirs` | `tests/test_util_paths.py`, `myav doctor` |
| Quarantined payloads are `0000` | `quarantine.quarantine` | `tests/test_quarantine.py` |
| Restore never overwrites without `--force` | `quarantine.restore` | `tests/test_quarantine.py` |
| A TOCTOU mismatch keeps both copies and refuses to unlink | `quarantine.quarantine` hash-after | `tests/test_quarantine.py` |
| Nothing is written under `/mnt/c` | `paths.assert_writable_location` | `tests/test_util_paths.py` |
| Rule extraction refuses traversal | `rules._safe_extract` | `tests/test_rules.py` |
| The VT key never appears in output | redaction in `config.public_dict` / `cli` | `tests/test_config.py`, `tests/test_cli.py` |
| No `sudo` inside Python | code review + `grep` in CI | repository-wide |
| VirusTotal is off without a key | `engines/virustotal.py` `configured` property | `tests/test_engines.py` |
| An engine error never yields CLEAN | `verdict.fuse` | `tests/test_engine_verdict.py` |
| A skipped primary engine yields UNKNOWN | `verdict.fuse` | `tests/test_engine_verdict.py` |

If a report or a behaviour contradicts one of these, that is a bug — and the test that
should have caught it is also a bug.

---

## 5. Hardening recommendations for operators

MYAV is one layer. Use it as one layer.

1. **Keep the operating system patched.** MYAV cannot detect a kernel exploit that never
   writes a file.
2. **Keep Windows Defender (or your platform AV) enabled.** MYAV does not replace it.
3. **Do not run MYAV as root.** Only the installer and the signature update need root.
4. **Review the installer before applying it.** It is short and commented, and
   `--dry-run` is the default.
5. **Back up before you rely on quarantine.** Quarantine is a move, and a move is a change.
6. **Read the report weekly.** A finding nobody reads is not a finding.
7. **Check the rule provenance** after each fetch (`myav rules status`) — commit and
   archive hash are recorded.
8. **Keep the API key out of shell history.** Prefer the prompt or `MYAV_VT_API_KEY`.
9. **Restrict who can write to your watched folders.** A world-writable Downloads folder
   is an invitation.
10. **Treat `myav allow` as a security action.** It is a permanent trust decision.

---

## 6. Known limitations that are not vulnerabilities

For clarity, because they are reported repeatedly:

- **No blocking.** Documented in [LIMITATIONS.md](../docs/LIMITATIONS.md) §1.
- **No archive scanning.** §4.
- **No detection of new samples.** §2.
- **No kernel-level visibility.** §5.
- **INCONCLUSIVE on WSL EICAR.** Expected Defender behaviour.
- **Experimental macOS/Windows.** [PLATFORMS.md](../docs/PLATFORMS.md).

A report that MYAV "failed" on one of these will be closed with a pointer to the relevant
section — not because the concern is invalid, but because it is a known design boundary
that is already stated in public.

---

## 7. For contributors: security-relevant code

Changes to these files get extra review, and a change that weakens their invariants will be
rejected even if tests pass:

| File | Invariant |
|---|---|
| `src/myav/quarantine.py` | Never unlink without a verified copy; never derive a path from user input |
| `src/myav/verdict.py` | An error never becomes CLEAN; severity never decreases |
| `src/myav/config.py` | `0600` before parse; never log the key |
| `src/myav/rules.py` | Pinned commit; safe extraction; per-file compile reporting |
| `src/myav/paths.py` | `/mnt/c` write refusal; `0700` directories |
| `scripts/install-system.sh` | Dry-run default; no `sudo`; no deletion |
| `src/myav/engines/virustotal.py` | Hash only; no body upload; rate limits respected |

If you change one of them, add a test that fails without your change. If you cannot think
of one, the change probably is not safe.

---

## 8. Coordinated disclosure

When a fix is ready:

1. A GitHub Security Advisory is published with credit (unless you prefer otherwise).
2. `CHANGELOG.md` records the fix under **Security**.
3. If the issue affects users who cannot upgrade immediately, `PROJECT_STATUS.md` names the
   mitigation.

No legal action will be taken against researchers who act in good faith, test on their own
systems, and report privately. Do not test against systems you do not own or have explicit
permission to test.
