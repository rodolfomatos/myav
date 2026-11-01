# Contributing to MYAV

Thank you for considering it. This project has an unusual constraint that shapes every
contribution rule:

> **It is a security tool, and it refuses to overstate itself.**

That means a contribution is judged on two axes, not one: does it work, and does it stay
honest? A feature that detects more but claims more than it proves will be rejected.

---

## 1. Before you write code

Open an issue first if your change is more than a typo. Describe:

- the problem, in user terms;
- what you propose;
- what test would prove it works.

For anything touching quarantine, verdict fusion, config permissions, rule fetching, or
the installer, expect a design discussion before code. Those files have invariants that
are not obvious from reading them once (see [SECURITY.md](SECURITY.md) §7).

Good first contributions:

- documentation fixes, especially where a step assumes knowledge the reader may not have;
- a failing test for a bug you found;
- support for a distribution in `scripts/install-system.sh`;
- a platform validation report (see [docs/PLATFORMS.md](docs/PLATFORMS.md) §10).

---

## 2. Development setup

```bash
git clone https://github.com/rodolfomatos/myav.git
cd myav
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/pip install pytest pytest-cov ruff
```

Run everything:

```bash
.venv/bin/python -m pytest
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check src tests
```

Expected: all tests pass, coverage above 80% (currently ~94%), no lint findings.

Optional, if you have the engines installed:

```bash
./scripts/verify-live.sh
```

---

## 3. The rules of the codebase

### 3.1 Tests are part of the change

Every behaviour change needs a test that **fails before your change** and passes after.
A test you have never seen fail is a test you cannot trust.

- Use the `home`, `paths`, `state`, `config`, `platform` fixtures from `tests/conftest.py`.
- Never write to the real `~/.config/myav`, the real quarantine, or the real database.
  A test suite that quarantines your files is itself malware.
- Prefer asserting the contract over the implementation. "A skipped primary engine yields
  UNKNOWN" is a contract. "`fuse` called `_ENGINE_TO_LEVEL`" is not.

### 3.2 No new runtime dependency without a reason

The dependency set is deliberately tiny. Adding one requires:

- a licence compatible with Apache-2.0;
- a note in [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) and the SBOM;
- a justification in the pull request: what it replaces, and why stdlib is not enough.

### 3.3 Never call `sudo` from Python

Privilege is granted explicitly by the operator. If a command needs root, it explains and
exits `3`. The installer script is the only place that assumes privilege, and it refuses to
escalate itself.

### 3.4 Never delete without explicit confirmation

Detection never deletes. Quarantine moves. `purge` requires `--yes` and says what it will
destroy before doing it. Any PR that unlinks a user file as a side effect of scanning will
be rejected.

### 3.5 Do not add network calls casually

The only permitted destinations are documented in [docs/PRIVACY.md](docs/PRIVACY.md) §2:
ClamAV mirrors, GitHub for the rule pack, and VirusTotal for hash lookups. A new network
call is a privacy change and needs a documentation update plus a test proving it is
opt-in.

### 3.6 Exit codes are a contract

| Code | Meaning |
|---|---|
| 0 | success / clean |
| 1 | command failed |
| 2 | usage error |
| 3 | platform cannot do that / root required |
| 4 | configuration invalid or unsafe |
| 5 | self-test inconclusive |
| 10 | malicious found |
| 11 | suspicious found |
| 12 | unknown (evidence missing) |

Do not renumber them. Scripts and users depend on them.

### 3.7 Style

- Python 3.10+, `from __future__ import annotations`.
- Line length 100, enforced by `ruff`.
- Type hints on public functions.
- Comments explain *why*, not *what*. If the code says what it does, the comment should
  say why it must.
- Docstrings on modules that encode a policy (verdict, quarantine, rules).

---

## 4. Documentation rules

Documentation is a deliverable, not an afterthought.

1. **Assume zero prior knowledge** for installation and configuration pages. If a step
   requires knowing what a "hash" is, define it or link to the glossary.
2. **Feynman style**: say what it is, why it matters, what it looks like when it works,
   and what to do when it does not.
3. **Never claim a capability that is not tested.** If macOS is experimental, the page says
   experimental.
4. **Real references only.** No invented DOIs or URLs. If you cannot verify a citation,
   remove it.
5. **Update the map.** If you add a document, add it to the README documentation table.

---

## 5. Pull request checklist

- [ ] Tests added or updated, and they fail without the change.
- [ ] `pytest` green.
- [ ] `ruff check` and `ruff format --check` green.
- [ ] Coverage not reduced below 80%.
- [ ] Docs updated if behaviour, configuration, or output changed.
- [ ] `CHANGELOG.md` updated under **Unreleased**.
- [ ] No secrets, no real malware, no personal paths.
- [ ] Security-relevant files reviewed against [SECURITY.md](SECURITY.md) §7.
- [ ] If a limitation changed, [docs/LIMITATIONS.md](docs/LIMITATIONS.md) updated.

---

## 6. Commit messages

Conventional-ish, plain English:

```text
quarantine: verify payload hash after the move, not only before

A file could be replaced between hashing and moving. Hashing the stored copy
closes the window; a mismatch now keeps both copies instead of unlinking.

Adds test_quarantine_toctou_keeps_both.
```

Rules:

- First line: `area: imperative summary`, under 72 characters.
- Body: why, not what.
- Reference the issue if there is one.

Do not sign commits with a tool you do not control, and do not add co-author trailers for
tools that did not contribute.

---

## 7. Reviewing

Reviewers are asked to be hostile in the useful sense:

- Find the case the tests miss.
- Ask what happens when the engine is down, the file vanishes, or the disk is full.
- Ask what the report *claims* versus what was proven.
- Reject a feature that cannot be explained to a non-expert.

Agreement is not the goal. A correct "no" is more valuable than a polite "yes".

---

## 8. Licence of contributions

By contributing, you agree that your contribution is licensed under Apache-2.0, the same
as the project. Do not paste code from projects with incompatible licences. If you adapt
code, say where it came from in the commit message and confirm the licence is compatible.

The YARA rule pack is **not** part of this repository and is never vendored. Do not add
rules with a licence that would restrict MYAV's users.

---

## 9. Code of conduct

Be technical, be direct, do not be cruel. Disagreement about code is expected; contempt for
people is not. Harassment, doxxing, and publishing someone's private file paths or keys are
grounds for removal.

---

## 10. Where to start

| I want to… | Read |
|---|---|
| Understand the design | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Understand the threat model | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) |
| Know what is not built | [PROJECT_STATUS.md](PROJECT_STATUS.md) |
| Run the tests | [docs/TESTING.md](docs/TESTING.md) |
| Report a vulnerability | [SECURITY.md](SECURITY.md) |
| See the roadmap | [docs/ROADMAP.md](docs/ROADMAP.md) |

Thank you for reading this far. The fact that you did is a good sign.
