"""Honesty dashboard tests (research track).

These tests verify the measurement tooling only — no detection feature ships
as part of MYAV Core from this ticket.
"""

from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

from myav.research.honesty_dashboard import (
    generate_sbom,
    run_honesty_dashboard,
    sign_release,
)


def test_generate_sbom(tmp_path: Path) -> None:
    """SBOM generation produces valid CycloneDX with components."""
    sbom_path = tmp_path / "sbom" / "myav.cdx.json"
    sbom = generate_sbom(sbom_path, version="0.1.0")

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.4"
    assert sbom["metadata"]["component"]["name"] == "myav"
    assert len(sbom["components"]) >= 1  # at least Python + myav
    assert sbom_path.exists()


def test_sign_release_missing_file(tmp_path: Path) -> None:
    """Signing a non-existent file returns signed=False with error."""
    result = sign_release(tmp_path / "nonexistent", method="gpg")
    assert result["signed"] is False
    assert "error" in result


def test_sign_release_no_gpg(tmp_path: Path, monkeypatch) -> None:
    """When gpg is not installed, signing returns signed=False with error."""
    orig_run = subprocess.run

    def fake_run(cmd, **kwargs):
        if cmd[0] == "gpg":
            raise FileNotFoundError("gpg not found")
        return orig_run(cmd, **kwargs)

    monkeypatch.setattr("subprocess.run", fake_run)

    tmp_file = tmp_path / "release.tar.gz"
    tmp_file.write_bytes(b"fake release data")
    result = sign_release(tmp_file, method="gpg")
    assert result["signed"] is False
    assert "gpg not installed" in result["error"]


def test_compute_honesty_metrics_empty_db(tmp_path: Path) -> None:
    """Empty DB returns 'none' confidence."""
    db_path = tmp_path / "state.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, ts TEXT, path TEXT, "
        "size INTEGER, sha256 TEXT, verdict TEXT, quarantine_id TEXT, "
        "engines TEXT, degraded TEXT, kind TEXT)"
    )
    conn.execute(
        "CREATE TABLE quarantines (id TEXT PRIMARY KEY, ts TEXT, "
        "original_path TEXT, sha256 TEXT, size INTEGER, mode INTEGER, "
        "mtime REAL, tag TEXT, reason TEXT, evidence TEXT, state TEXT, "
        "payload TEXT)"
    )
    conn.commit()
    conn.close()

    from myav.research.honesty_dashboard import compute_honesty_metrics

    metrics = compute_honesty_metrics(db_path)
    assert metrics.files_scanned == 0
    assert metrics.files_flagged == 0
    assert metrics.confidence_level == "none"
    assert "no scans" in metrics.confidence_reason.lower()


def test_compute_honesty_metrics_with_scans(tmp_path: Path) -> None:
    """With scan data, metrics are computed correctly."""
    db_path = tmp_path / "state.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, ts TEXT, path TEXT, "
        "size INTEGER, sha256 TEXT, verdict TEXT, quarantine_id TEXT, "
        "engines TEXT, degraded TEXT, kind TEXT)"
    )
    conn.execute(
        "CREATE TABLE quarantines (id TEXT PRIMARY KEY, ts TEXT, "
        "original_path TEXT, sha256 TEXT, size INTEGER, mode INTEGER, "
        "mtime REAL, tag TEXT, reason TEXT, evidence TEXT, state TEXT, "
        "payload TEXT)"
    )
    # Insert 5 clean, 2 malicious, 1 suspicious
    for i in range(5):
        conn.execute(
            "INSERT INTO scans (ts, path, size, sha256, verdict, "
            "quarantine_id, engines, degraded, kind) VALUES (?,?,?,?,?,?,?,?,?)",
            ("2026-11-01T10:00:00+00:00", f"/tmp/clean_{i}.bin", 100,
             "a" * 64, "CLEAN", None, "[]", "[]", "manual"),
        )
    for i in range(2):
        conn.execute(
            "INSERT INTO scans (ts, path, size, sha256, verdict, "
            "quarantine_id, engines, degraded, kind) VALUES (?,?,?,?,?,?,?,?,?)",
            ("2026-11-01T10:00:00+00:00", f"/tmp/mal_{i}.bin", 100,
             "b" * 64, "MALICIOUS", f"qid_{i}", "[]", "[]", "manual"),
        )
    for i in range(1):
        conn.execute(
            "INSERT INTO scans (ts, path, size, sha256, verdict, "
            "quarantine_id, engines, degraded, kind) VALUES (?,?,?,?,?,?,?,?,?)",
            ("2026-11-01T10:00:00+00:00", f"/tmp/sus_{i}.bin", 100,
             "c" * 64, "SUSPICIOUS", f"qid_sus_{i}", "[]", "[]", "manual"),
        )
    # Insert 1 restored quarantine (counts as confirmed FP)
    conn.execute(
        "INSERT INTO quarantines (id, ts, original_path, sha256, size, mode, "
        "mtime, tag, reason, evidence, state, payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("qid_0", "2026-11-01T10:00:00+00:00", "/tmp/mal_0.bin", "b" * 64,
         100, 0o600, 0.0, "malicious", "test", "[]", "restored", "/tmp/q_0.bin"),
    )
    conn.commit()
    conn.close()

    from myav.research.honesty_dashboard import compute_honesty_metrics

    metrics = compute_honesty_metrics(db_path)
    assert metrics.files_scanned == 8
    assert metrics.files_flagged == 3
    assert metrics.files_restored == 1
    assert metrics.confirmed_false_positives == 1
    assert metrics.false_positive_rate == 37.5  # 3/8 * 100
    assert metrics.scans_performed == 8
    assert metrics.confidence_level in ("low", "medium", "high", "none")


def test_run_honesty_dashboard_no_db(tmp_path: Path) -> None:
    """Running dashboard with no DB returns sensible defaults."""
    result = run_honesty_dashboard(tmp_path / "nonexistent.db", json_output=True)
    assert result["command"] == "research-honesty-dashboard"
    assert result["metrics"]["files_scanned"] == 0
    assert result["confidence"]["level"] == "none"


def test_run_honesty_dashboard_json(tmp_path: Path) -> None:
    """JSON output contains all expected keys."""
    db_path = tmp_path / "state.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE scans (id INTEGER PRIMARY KEY, ts TEXT, path TEXT, "
        "size INTEGER, sha256 TEXT, verdict TEXT, quarantine_id TEXT, "
        "engines TEXT, degraded TEXT, kind TEXT)"
    )
    conn.execute(
        "CREATE TABLE quarantines (id TEXT PRIMARY KEY, ts TEXT, "
        "original_path TEXT, sha256 TEXT, size INTEGER, mode INTEGER, "
        "mtime REAL, tag TEXT, reason TEXT, evidence TEXT, state TEXT, "
        "payload TEXT)"
    )
    conn.execute(
        "INSERT INTO scans (ts, path, size, sha256, verdict, "
        "quarantine_id, engines, degraded, kind) VALUES (?,?,?,?,?,?,?,?,?)",
        ("2026-11-01T10:00:00+00:00", "/tmp/test.bin", 100, "a" * 64,
         "CLEAN", None, "[]", "[]", "manual"),
    )
    conn.commit()
    conn.close()

    result = run_honesty_dashboard(db_path, json_output=True)
    assert result["command"] == "research-honesty-dashboard"
    assert "metrics" in result
    assert "confidence" in result
    assert "sbom" in result
    assert "signing" in result
    assert result["metrics"]["files_scanned"] == 1
