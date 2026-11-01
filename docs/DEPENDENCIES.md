# Dependencies and licences

MYAV keeps its dependency set deliberately small. Every addition is a potential
supply-chain risk, and a security tool should not have a large attack surface made of
other people's code.

This page lists every dependency, why it exists, its licence, and the risk it carries.

---

## 1. Runtime dependencies (installed with the package)

| Package | Version constraint | Purpose | Licence | Risk notes |
|---|---|---|---|---|
| **Python** | `>=3.10` | Runtime | PSF-2.0 | Required by environment, not this project |
| **watchdog** | `>=3.0,<6.0` | Filesystem events (inotify / FSEvents / `ReadDirectoryChangesW`) | Apache-2.0 | Per-platform native backends; a bug could miss events. Mitigated by `--once` scans and the weekly full scan |
| **tomli** | `>=2.0,<3.0` (Python < 3.11 only) | TOML parsing | MIT | Replaced by stdlib `tomllib` on 3.11+ |

That is the complete runtime set. There is no web framework, no CLI framework, no ORM, no
HTTP client library — the standard library covers `argparse`, `sqlite3`, `urllib`,
`hashlib`, `tarfile`, `subprocess`, `json` and `tomllib`.

**Why no `requests`?** `urllib.request` is enough for two `GET` calls. Fewer dependencies
means fewer advisories to track.

**Why no `click`/`typer`?** `argparse` is stdlib and stable. The CLI is not the interesting
part of a security tool.

---

## 2. External programs (not installed by pip)

These are system packages. MYAV invokes them as subprocesses; it does not embed them.

| Program | Package (Debian/Ubuntu) | Purpose | Licence | Required? |
|---|---|---|---|---|
| `clamscan` | `clamav` | One-shot signature scan | GPL-2.0 (engine) | Yes (fallback) |
| `clamdscan` | `clamav-daemon` | Fast scan through the daemon | GPL-2.0 | Recommended |
| `clamd` | `clamav-daemon` | Signature daemon, loopback only | GPL-2.0 | Recommended |
| `freshclam` | `clamav-freshclam` | Signature database updater | GPL-2.0 | Yes (for updates) |
| `yara` | `yara` | Pattern scanning CLI | BSD-3-Clause | Yes (fallback) |
| `yarac` | `yara` | Rule compiler | BSD-3-Clause | Yes (for the rule pack) |
| `systemctl` | `systemd` | Scheduler on Linux | LGPL-2.1 | Platform |
| `schtasks` | Windows | Scheduler on WSL/Windows | Proprietary OS | Platform |
| `launchctl` | macOS | Scheduler on macOS | Proprietary OS | Platform |
| `reg.exe`, `powershell.exe` | Windows | Startup inventory from WSL | Proprietary OS | Optional |
| `brew` | Homebrew (macOS) | Engine install on macOS | BSD-2-Clause | Optional |

MYAV does not redistribute any of these. The installer calls the system package manager;
the user's distribution supplies the binaries and their licences.

---

## 3. Development dependencies

Not installed for end users.

| Package | Purpose | Licence |
|---|---|---|
| `pytest` | Test runner | MIT |
| `pytest-cov` | Coverage measurement | MIT |
| `ruff` | Lint and format | MIT |
| `setuptools` | Build backend | MIT |

---

## 4. Optional Python binding

| Package | Purpose | Licence | Fallback |
|---|---|---|---|
| `yara-python` | In-process YARA scanning (faster, no subprocess per file) | Apache-2.0 | The `yara` CLI |

`yara-python` is **not** in `pyproject.toml`. It is detected at runtime; if import fails,
the engine uses the CLI. This keeps the mandatory dependency set at two packages.

---

## 5. Data and content licences

| Asset | Licence | Redistributed by MYAV? | Obligation |
|---|---|---|---|
| ClamAV signature database | ClamAV terms (free to use with ClamAV) | No — installed by the system | Do not mirror without checking terms |
| `Neo23x0/signature-base` | Detection Rule License 1.1 | **No — fetched at a pinned commit after `--accept-license`** | Free for non-commercial use; review before commercial deployment |
| EICAR test string | Free to use for testing | Yes, assembled at runtime from parts | None; it is a test artefact, not malware |
| MITRE ATT&CK (referenced) | CC BY 4.0 for the knowledge base | No | Attribution if quoted at length |

The rule pack is deliberately **never vendored**. That keeps its conditional licence out
of this repository and makes the provenance auditable (`PROVENANCE.json` records the commit
and archive SHA-256).

---

## 6. MYAV's own licence

**Apache License 2.0.** Reasons:

- permissive, compatible with the engines and libraries above;
- an explicit patent grant, which matters for anything security-adjacent;
- a clear contribution model (see [CONTRIBUTING.md](../CONTRIBUTING.md) §8);
- no copyleft obligation on users who integrate MYAV into a product.

The full text is in [LICENSE](../LICENSE). Attribution notices are in [NOTICE](../NOTICE).

---

## 7. Supply-chain controls currently in place

| Control | Where | What it prevents |
|---|---|---|
| Pinned YARA pack commit | `rules.py` (`PROVENANCE.json`) | A silent rule change between fetches |
| Archive SHA-256 recorded | `rules.py` | A swapped tarball |
| No rules in git | `.gitignore`, policy | Licence contamination and unreviewed content |
| Small dependency set | `pyproject.toml` | A large transitive attack surface |
| Version ranges with upper bounds | `pyproject.toml` | Accidental major-version breakage |
| Extraction refuses traversal | `rules._safe_extract` | A malicious archive writing outside its directory |
| TLS for every network call | `urllib` defaults | Passive interception |
| Config `0600` before parse | `config.py` | Key exposure to other local users |
| SBOM committed | `docs/sbom/` | Unknown transitive components |

---

## 8. Gaps (honest list)

| Gap | Consequence | Plan |
|---|---|---|
| No release signing | A compromised download cannot be distinguished from a real one | Add Sigstore/cosign in a later release |
| No automated dependency scanning in CI | A new advisory is found by a human, not a robot | Add `pip-audit` or Dependabot |
| SBOM is generated manually | It can drift from `pyproject.toml` | Generate per release in CI |
| No reproducible builds | Bit-for-bit verification is not possible | Future work |
| `watchdog` native backends are opaque | Event semantics vary by platform | Mitigated by `--once` and the weekly full scan |

These are listed in [PROJECT_STATUS.md](../PROJECT_STATUS.md) §3.5 as well. They are not
pretended away.

---

## 9. Adding a dependency: the checklist

1. Is it necessary, or does the standard library do it?
2. Is the licence compatible with Apache-2.0 (and with redistribution)?
3. How many transitive dependencies does it pull in?
4. Who maintains it, and how recently?
5. Does it open a network connection or execute subprocesses? If so, it needs a privacy and
   security review.
6. Add it to this file, the SBOM, and `pyproject.toml` with an upper bound.
7. Add a test that fails if the dependency's behaviour changes in a way MYAV relies on.

If any answer is uncomfortable, do not add it.
