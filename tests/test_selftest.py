"""The EICAR end-to-end proof.

These tests use a stub ClamAV so they run on any machine. They assert the *protocol*:
detect → quarantine → source gone → restore → byte-identical → cleanup, and the honest
INCONCLUSIVE result when ClamAV is absent.
"""

from __future__ import annotations

from pathlib import Path

from conftest import StubClam, make_engines

from myav import selftest
from myav.engine import CLEAN, MALICIOUS
from myav.pipeline import Outcome


def test_eicar_bytes_is_the_standard_string() -> None:
    payload = selftest.eicar_bytes()
    assert payload.startswith(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}")
    assert b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in payload
    assert len(payload) == 68


def test_selftest_success_path(config, paths, state, platform) -> None:
    engines = make_engines(platform, clam=StubClam(MALICIOUS, "Eicar-Test-Signature"))
    result = selftest.run_eicar_selftest(config, paths, state, engines)

    assert result.inconclusive is None
    assert result.exit_code == 0
    names = [assertion.name for assertion in result.assertions]
    assert "verdict is MALICIOUS" in names
    assert "ClamAV named the Eicar signature" in names
    assert "payload hash matches the original" in names
    assert "restored file hash matches" in names
    assert "no test artefacts left in the sandbox" in names
    assert all(assertion.passed for assertion in result.assertions)
    assert result.ok


def test_selftest_reports_inconclusive_without_clamav(config, paths, state, platform) -> None:
    clam = StubClam(available=False)
    engines = make_engines(platform, clam=clam)
    result = selftest.run_eicar_selftest(config, paths, state, engines)

    assert result.inconclusive is not None
    assert result.exit_code == 5
    assert result.ok is False
    assert "ClamAV is not installed" in result.inconclusive


def test_selftest_fails_cleanly_when_engines_miss(config, paths, state, platform) -> None:
    engines = make_engines(platform, clam=StubClam(CLEAN))
    result = selftest.run_eicar_selftest(config, paths, state, engines)

    assert result.inconclusive is None
    assert result.exit_code == 1
    failed = [assertion for assertion in result.assertions if not assertion.passed]
    assert {assertion.name for assertion in failed} >= {"verdict is MALICIOUS"}


def test_selftest_inconclusive_when_file_vanishes(
    config, paths, state, platform, monkeypatch
) -> None:
    engines = make_engines(platform, clam=StubClam(MALICIOUS, "Eicar-Test-Signature"))

    def vanish(*args, **kwargs):
        outcome = Outcome(path=Path("/nowhere"))
        outcome.skipped = "vanished"
        return outcome

    monkeypatch.setattr(selftest, "scan_file", vanish)
    result = selftest.run_eicar_selftest(config, paths, state, engines)

    assert result.inconclusive is not None
    assert "Defender" in result.inconclusive
    assert result.exit_code == 5


def test_render_and_as_dict() -> None:
    result = selftest.SelfTestResult(assertions=[selftest.Assertion("one", True, "detail")])
    text = result.render()
    assert "PASS" in text
    assert "RESULT: PASS" in text
    assert result.as_dict()["ok"] is True
    assert result.as_dict()["assertions"][0]["name"] == "one"


def test_render_inconclusive() -> None:
    result = selftest.SelfTestResult(inconclusive="no clamav")
    text = result.render()
    assert "INCONCLUSIVE: no clamav" in text
    assert "RESULT: INCONCLUSIVE" in text
    assert result.exit_code == 5
