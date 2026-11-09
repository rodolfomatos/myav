---
ticket: T039
title: CI baseline — dev tooling and deterministic tests
sprint: research-01
priority: high
status: in-progress
created: 2026-11-09
---

# T039 — CI baseline: dev tooling and deterministic tests

## Context

Every push since T035 has failed CI at the first step (`make lint`) because
`make setup` installs the runtime package only; `ruff` is never installed on the
runner. The failure is infrastructure, not product: the same commit passes
`ruff check src tests` on the operator machine.

The full local suite also has two environment/date-dependent failures that would
block a green CI once lint is fixed:

- `tests/test_campaign_graph.py` builds `example_events()` with fixed
  `2026-11-01` timestamps and filters them through a rolling 7-day window; after
  2026-11-08 the whole campaign falls outside the window and the graph is empty.
- `tests/test_rules.py::test_compile_pack_without_yarac` intends to simulate a
  missing `yarac` but passes `yarac=""`, which `compile_pack` treats as "not
  supplied" and replaces with `shutil.which("yarac")`; on a machine with
  `yarac` installed the test fails.

A red CI trains the operator to ignore CI. This ticket restores a meaningful
baseline: `make setup && make lint && make test` must pass from a clean checkout.

## Acceptance Criteria

- [x] `pyproject.toml` declares a `dev` optional-dependency group containing
      `pytest`, `pytest-cov` and `ruff`.
- [x] `make setup` installs the dev group (with or without `uv`).
- [x] `example_events()` uses timestamps relative to "now" so the demo campaign
      is always inside the default window; existing graph tests pass without
      freezing the clock.
- [x] `test_compile_pack_without_yarac` removes `yarac` deterministically instead
      of relying on the host not having it.
- [x] Clean-venv reproduction of CI (`pip install -e ".[dev]"`; `make lint`;
      `make test`) passes with no pre-existing failures.
- [x] `pytest` resolves `tests/test_main.py` (`from src.main import main`) under
      the bare `pytest` entry point used by the Makefile, not only under
      `python -m pytest`.
- [x] The suite isolates `XDG_*`/`MYAV_PLATFORM` from the host, so a runner that
      exports XDG paths cannot redirect `Config.load(home=...)` outside the
      temporary home.
- [x] `ruff check src tests` clean; coverage ≥ 80%.
- [x] Docs that describe contributor setup (`docs/TESTING.md`,
      `CONTRIBUTING.md`) use the dev extra.
- [ ] CI run for the T039 commit is green.

## Build & Verify Evidence

Diffstory:

- `pyproject.toml`: `[dev]` extra (`pytest`, `pytest-cov`, `ruff`) and
  `pythonpath = ["src", "."]`. The extra is the single declaration of dev tools;
  the second path fixes bare `pytest` collection of `tests/test_main.py`.
- `Makefile`: `make setup` runs `uv sync --extra dev` or falls back to
  `python -m pip install -e ".[dev]"`. No other target changed.
- `campaign_graph.py`: `example_events()` timestamps are now relative to
  `now - 1 hour`; the six offsets are unchanged. No graph algorithm change.
- `tests/test_rules.py`: the missing-`yarac` test now monkeypatches
  `shutil.which`; the production branch under test is unchanged.
- `docs/TESTING.md`, `CONTRIBUTING.md`: contributor setup uses `.[dev]`; stale
  hard-coded pass counts removed from the expected output.
- `tests/conftest.py`: autouse fixture removes `XDG_*` and `MYAV_PLATFORM` from
  the test environment. This is test isolation, not a production change.
- Intentionally untouched: `ci.yml`, `src/main.py`, the legacy `test_main.py`
  assertions, all runtime dependencies, all detection code.

Evidence (2026-11-09):

- Clean venv, exact `make setup`: installed `pytest-9.2.0`, `pytest-cov-7.1.0`,
  `ruff-0.17.4`; `make lint` → `All checks passed!`.
- Clean venv `make test` → `516 passed`, coverage `88.61%`, no failures.
- Clean venv `make check` → `516 passed`, `All checks passed!`.
- Local venv `.venv/bin/python -m pytest -q` → `516 passed`, coverage `88.61%`.
- Simulated runner environment (`XDG_*` exported to a throwaway directory):
  before the conftest fixture `tests/test_config.py` → `7 failed, 10 passed`
  (byte-for-byte the CI failure set); after the fixture `17 passed`, and the
  full clean-venv `make test` → `516 passed`, coverage `88.61%`.
- Pre-existing, out of scope: `ruff format --check src tests` reports 32 files
  would be reformatted (repo-wide drift, not a CI gate). Recorded as backlog
  item T040.

## Scope

**In:** `pyproject.toml`, `Makefile`, `src/myav/research/campaign_graph.py`,
`tests/test_rules.py`, `docs/TESTING.md`, `CONTRIBUTING.md`, `aes/*`.

**Out:** changing the CI provider or workflow structure, adding runtime
dependencies, pinning tool versions in the workflow, rewriting the campaign-graph
algorithm, fixing unrelated tests.

## Hostile Analysis

INSIGHTS CONSULTED: T032 (campaign graph), T037 (offline intel), T038 (web dashboard).

ASSUMPTIONS I'M MAKING:
- [KNOWN] CI fails because `make setup` installs only runtime deps — evidence:
  run 42528833803 log `make: ruff: No such file or directory`; `Makefile:12`
  (`uv sync || pip install -e .`); `pyproject.toml` has no dev extras;
  `.github/workflows/ci.yml` runs `make setup` then `make lint`.
- [KNOWN] The campaign graph tests are date-dependent — evidence:
  `src/myav/research/campaign_graph.py:313` fixes six timestamps on 2026-11-01;
  `_is_within_window` at line 92 compares them with `datetime.now`; today is
  2026-11-09, so the 7-day window is empty.
- [INFERRED] CI does not have `yarac`, so `test_compile_pack_without_yarac`
  currently passes there, but the test still asserts the wrong mechanism and is
  red on operator machines with YARA installed — evidence: local run
  `tests/test_rules.py::test_compile_pack_without_yarac` fails,
  `rules.compile_pack` line 98 uses `yarac or shutil.which("yarac")`.
- [ASSUMED] `pytest`, `pytest-cov` and `ruff` are the only dev tools required by
  the suite — impact if false: the clean-venv run fails at import/collection and
  the missing package is added to the extra in the same ticket.
- [UNKNOWN] Whether GitHub's runner image changes its preinstalled packages
  between now and the next push — mitigated by making every required tool an
  explicit dependency instead of relying on the image.

WHAT WASN'T SPECIFIED (that matters):
- Whether CI is intended to be a required gate or best-effort. The workflow
  exists and has failed for four consecutive tickets; restoring it is the only
  way the "verified by CI" claim becomes meaningful.
- Whether `uv` should remain supported in `make setup`. It is not installed on
  the runner and there is no `uv.lock`; keeping the fallback costs nothing.

ALTERNATIVES I DIDN'T CHOOSE (and why):
- Install `ruff` with `pip install ruff` inside `ci.yml`: rejected — splits the
  contract between Makefile and workflow; local `make setup` would still lack
  the tools.
- Pin an exact `ruff` version in CI: rejected — no lockfile, and the project
  already accepts a moving floor; version pinning is a separate decision.
- Freeze the clock in the campaign-graph tests: rejected — `build_campaign_graph`
  calls `datetime.now` internally with no injection point; adding one is a
  larger API change than making demo data relative.
- Delete `test_compile_pack_without_yarac`: rejected — the missing-`yarac`
  branch is real behaviour and deserves a test.

INVITE CONTRADICTION:
- If `make test` still fails in the clean venv for a reason other than the two
  known tests, my scope is incomplete; the reproduction must be run before
  claiming the fix.
- If `example_events()` relative timestamps break any consumer that assumes
  stable dates, the graph tests would not catch it; grep shows the timestamps
  are only used by the demo command and tests.

RISKS & SIDE EFFECTS:
- `make setup` now installs three extra packages for every developer; runtime
  installs (`pip install myav`) are unchanged.
- Relative demo timestamps change the JSON output of
  `myav research campaign-graph`; that is intended and documented in the ticket.
- A clean-venv run may expose further hidden dependencies; those are in scope
  only if they block `make test`.

COST OF BEING WRONG: LOW/MEDIUM — developer tooling and demo data, no runtime
detection path and no state schema change.

REASONING SKELETON FOR KEY CLAIMS:
CI fails at lint → `make setup` installs runtime only → no `ruff` on runner
→ add dev extra and install it. After lint, tests run → fixed-date demo data is
outside the rolling window → make timestamps relative → graph tests stable.

SCOPE BOUNDARIES DECLARATION:
This analysis covers the CI contract, the two known red tests and contributor
setup docs. It deliberately excludes the CI provider configuration, release
publishing, and unrelated pre-existing warnings.

## Discovered During Build

- The clean-venv run exposed a second blocker: `make test` invokes bare `pytest`,
  which does not put the repository root on `sys.path`, so
  `tests/test_main.py` (`from src.main import main`) fails at collection with
  `ModuleNotFoundError: No module named 'src'`. It is in scope because it blocks
  the acceptance criterion; fixed by adding `"."` to the pytest `pythonpath`
  instead of weakening the test.
- The first real CI run after the fix (42591320477) reached the test step and
  exposed a third blocker: GitHub runners export `XDG_CONFIG_HOME`,
  `XDG_STATE_HOME`, `XDG_DATA_HOME` and `XDG_CACHE_HOME`, and `Config.load(home=...)`
  resolves paths through `detect_platform`, which honours them. Seven
  `tests/test_config.py` tests read the runner's real config instead of the
  temporary home. Reproduced locally by exporting XDG paths; fixed with an
  autouse environment-isolation fixture in `tests/conftest.py`.

## Design Decisions

1. **One source of truth for dev tools.** `pyproject.toml` gets a `[dev]` extra;
   the Makefile and docs install `-e ".[dev]"`. CI does not list packages.
2. **Keep `uv` support.** `make setup` tries `uv sync --extra dev` then falls
   back to `pip install -e ".[dev]"`. The runner uses the fallback.
3. **Demo data is relative.** `example_events()` anchors to
   `datetime.now(timezone.utc) - 1 hour`; the same six events stay inside any
   positive window without a clock-injection API.
4. **Test the branch, not the host.** `test_compile_pack_without_yarac`
   monkeypatches `shutil.which` to return `None`, so it is green on every
   machine regardless of installed tools.

## Known Risks

- A future dependency added to tests but not to `[dev]` will break CI again.
  Mitigation: the clean-venv reproduction is the acceptance gate, and the
  failure mode is immediate and obvious.
- `uv sync --extra dev` creates `uv.lock` on machines with uv; that is uv's
  normal behaviour and outside this ticket's scope.
