from __future__ import annotations

import pytest

from myav.state import BootEntry, QuarantineRecord, State
from myav.util import now_iso


def _record(sha: str = "a" * 64, qid: str = "id1") -> QuarantineRecord:
    return QuarantineRecord(
        id=qid,
        original_path="/home/u/Downloads/bad.exe",
        sha256=sha,
        size=123,
        mode=0o600,
        mtime=1.0,
        tag="malicious",
        reason="clamav: Eicar",
        payload=f"{qid}.bin",
        evidence=[{"engine": "clamav", "status": "malicious"}],
    )


def test_schema_version(state: State) -> None:
    assert state.get_meta("schema_version") == "1"
    state.set_meta("last_run", now_iso())
    assert state.get_meta("last_run") is not None
    assert state.get_meta("missing", "fallback") == "fallback"


def test_record_scan_and_stats(state: State) -> None:
    state.record_scan(
        path="/tmp/a", size=1, sha256="a" * 64, verdict="CLEAN", engines=[], kind="manual"
    )
    state.record_scan(
        path="/tmp/b", size=2, sha256="b" * 64, verdict="MALICIOUS", engines=[], kind="watch"
    )
    stats = state.scan_stats()
    assert stats == {"CLEAN": 1, "SUSPICIOUS": 0, "MALICIOUS": 1, "UNKNOWN": 0, "total": 2}
    assert state.last_scan_ts() is not None
    assert state.last_scan_ts("watch") is not None
    assert state.last_scan_ts("nope") is None
    assert state.scan_stats(since_ts="2999-01-01")["total"] == 0


def test_scans_for_sha(state: State) -> None:
    state.record_scan(
        path="/tmp/a", size=1, sha256="c" * 64, verdict="CLEAN", engines=[], kind="manual"
    )
    rows = state.scans_for_sha("c" * 64)
    assert len(rows) == 1
    assert rows[0]["path"] == "/tmp/a"
    assert state.scans_for_sha("d" * 64) == []


def test_quarantine_crud(state: State) -> None:
    record = _record()
    state.add_quarantine(record)
    loaded = state.get_quarantine("id1")
    assert loaded is not None
    assert loaded.evidence[0]["engine"] == "clamav"

    assert [r.id for r in state.list_quarantines()] == ["id1"]
    state.set_quarantine_state("id1", "restored")
    assert state.list_quarantines() == []
    assert len(state.list_quarantines(include_restored=True)) == 1
    assert state.find_quarantine_by_sha("a" * 64) is None
    state.delete_quarantine("id1")
    assert state.get_quarantine("id1") is None


def test_find_quarantine_by_sha_ignores_restored(state: State) -> None:
    state.add_quarantine(_record())
    assert state.find_quarantine_by_sha("a" * 64) is not None
    state.set_quarantine_state("id1", "restored")
    assert state.find_quarantine_by_sha("a" * 64) is None


def test_allowlist(state: State) -> None:
    assert not state.is_allowed("f" * 64)
    state.allow("f" * 64, path="/tmp/a", reason="known good")
    assert state.is_allowed("f" * 64)
    rows = state.list_allowlist()
    assert rows[0]["reason"] == "known good"
    state.allow("f" * 64, path="/tmp/b", reason="updated")
    assert state.list_allowlist()[0]["reason"] == "updated"


def test_boot_apply_first_run_then_diff(state: State) -> None:
    first = BootEntry(key="k1", name="One", command="one.exe", location="registry")
    new, removed = state.boot_apply([first])
    assert [entry.key for entry in new] == ["k1"]
    assert removed == []
    assert state.boot_run_count() == 1
    assert [row["key"] for row in state.boot_snapshot()] == ["k1"]

    second = BootEntry(key="k2", name="Two", command="two.exe", location="startup")
    new, removed = state.boot_apply([second])
    assert [entry.key for entry in new] == ["k2"]
    assert [entry.key for entry in removed] == ["k1"]
    assert state.boot_run_count() == 2
    assert [row["key"] for row in state.boot_snapshot()] == ["k2"]


def test_vt_cache_ttl(state: State, monkeypatch) -> None:
    state.vt_put("e" * 64, "known", 5, 70)
    assert state.vt_get("e" * 64, 3600, 60)["positives"] == 5
    assert state.vt_get("f" * 64, 3600, 60) is None

    monkeypatch.setattr("myav.state.now_ts", lambda: 2_000_000_000)
    assert state.vt_get("e" * 64, 3600, 60) is None


def test_vt_request_accounting(state: State, monkeypatch) -> None:
    monkeypatch.setattr("myav.state.now_ts", lambda: 1_000_000)
    assert state.vt_requests_since(0) == 0
    state.vt_record_request()
    state.vt_record_request()
    assert state.vt_requests_since(0) == 2
    assert state.vt_requests_since(1_000_001) == 0


def test_state_creates_private_parent(tmp_path) -> None:
    db = tmp_path / "deep" / "nested" / "state.db"
    State(db)
    assert db.parent.stat().st_mode & 0o777 == 0o700


def test_quarantine_record_defaults() -> None:
    record = QuarantineRecord(
        id="x",
        original_path="/a",
        sha256="b" * 64,
        size=1,
        mode=0o600,
        mtime=1.0,
        tag="suspicious",
        reason="r",
        payload="x.bin",
    )
    assert record.state == "staged"
    assert record.evidence == []
    assert record.ts


@pytest.mark.parametrize("tag", ["malicious", "suspicious"])
def test_quarantine_tags_roundtrip(state: State, tag: str) -> None:
    record = _record(qid=f"id-{tag}")
    record.tag = tag
    state.add_quarantine(record)
    assert state.get_quarantine(record.id).tag == tag
