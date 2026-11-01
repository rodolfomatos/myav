from __future__ import annotations

import pytest

from myav.engine import CLEAN, ERROR, MALICIOUS, SKIPPED, SUSPICIOUS, EngineResult
from myav.verdict import (
    EXIT_CODES,
    LEVEL_CLEAN,
    LEVEL_MALICIOUS,
    LEVEL_SUSPICIOUS,
    LEVEL_UNKNOWN,
    Verdict,
    fuse,
)


def test_engine_result_validates_status() -> None:
    with pytest.raises(ValueError):
        EngineResult(engine="x", status="banana")


def test_engine_result_fired_and_roundtrip() -> None:
    result = EngineResult(engine="clamav", status=MALICIOUS, signature="Eicar", primary=True)
    assert result.fired
    assert not EngineResult(engine="x", status=CLEAN).fired
    assert not EngineResult(engine="x", status=SKIPPED).fired
    restored = EngineResult.from_dict(result.as_dict())
    assert restored == result


def test_engine_result_defaults_meta_is_not_shared() -> None:
    first = EngineResult(engine="a", status=CLEAN)
    second = EngineResult(engine="b", status=CLEAN)
    first.meta["x"] = 1
    assert second.meta == {}


def test_fuse_all_clean() -> None:
    verdict = fuse([EngineResult(engine="clamav", status=CLEAN, primary=True)])
    assert verdict.level == LEVEL_CLEAN
    assert verdict.exit_code == 0
    assert not verdict.should_quarantine


def test_fuse_malicious_wins_over_everything() -> None:
    verdict = fuse(
        [
            EngineResult(engine="clamav", status=CLEAN, primary=True),
            EngineResult(engine="yara", status=SUSPICIOUS),
            EngineResult(engine="vt", status=MALICIOUS, signature="9/70 engines"),
        ]
    )
    assert verdict.level == LEVEL_MALICIOUS
    assert verdict.exit_code == 10
    assert verdict.should_quarantine
    assert verdict.quarantine_tag == "malicious"
    assert any("9/70" in reason for reason in verdict.reasons)


def test_fuse_suspicious() -> None:
    verdict = fuse([EngineResult(engine="vt", status=SUSPICIOUS, signature="1/70 engines")])
    assert verdict.level == LEVEL_SUSPICIOUS
    assert verdict.exit_code == 11
    assert verdict.quarantine_tag == "suspicious"


def test_fuse_primary_skipped_is_unknown() -> None:
    verdict = fuse(
        [
            EngineResult(engine="clamav", status=SKIPPED, detail="not installed", primary=True),
            EngineResult(engine="yara", status=CLEAN),
        ]
    )
    assert verdict.level == LEVEL_UNKNOWN
    assert verdict.exit_code == 12
    assert any("clamav: skipped" in item for item in verdict.degraded)


def test_fuse_secondary_skipped_stays_clean_but_degraded() -> None:
    verdict = fuse(
        [
            EngineResult(engine="clamav", status=CLEAN, primary=True),
            EngineResult(engine="yara", status=SKIPPED, detail="no-rules"),
        ]
    )
    assert verdict.level == LEVEL_CLEAN
    assert any("yara: skipped" in item for item in verdict.degraded)


def test_fuse_error_never_clean() -> None:
    verdict = fuse(
        [
            EngineResult(engine="clamav", status=CLEAN, primary=True),
            EngineResult(engine="yara", status=ERROR, detail="timeout"),
        ]
    )
    assert verdict.level == LEVEL_UNKNOWN
    assert any("timeout" in item for item in verdict.degraded)


def test_fuse_nothing_ran_is_unknown() -> None:
    verdict = fuse([])
    assert verdict.level == LEVEL_UNKNOWN
    assert "no engine produced evidence" in verdict.reasons


def test_fuse_stale_signatures_are_degraded() -> None:
    verdict = fuse(
        [EngineResult(engine="clamav", status=CLEAN, primary=True)], stale_signatures=True
    )
    assert any("older than 48h" in item for item in verdict.degraded)


def test_verdict_as_dict_and_exit_table() -> None:
    verdict = Verdict(level=LEVEL_MALICIOUS, reasons=["x"])
    payload = verdict.as_dict()
    assert payload["level"] == LEVEL_MALICIOUS
    assert payload["exit_code"] == 10
    assert EXIT_CODES == {"CLEAN": 0, "UNKNOWN": 12, "SUSPICIOUS": 11, "MALICIOUS": 10}
