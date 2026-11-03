"""Purpose-specific behavioural detection tests (research track).

These tests verify the measurement tooling only — no detection feature ships
as part of MYAV Core from this ticket.
"""

from __future__ import annotations

from pathlib import Path

from myav.research.behaviour_detectors import (
    BehaviourDetectionResult,
    BehaviourMatch,
    detect_all,
    detect_document_macro,
    detect_fileless_obfuscated_script,
    detect_ransomware_bulk_rename,
    detect_ransomware_canary,
    shannon_entropy,
)


def test_shannon_entropy() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00\x00\x00") == 0.0
    assert shannon_entropy(b"\x00\x01\x02\x03") > 1.0
    assert shannon_entropy(b"AAAA") < shannon_entropy(b"AB\x01\xff")


def test_detect_ransomware_canary() -> None:
    tmp = Path("/tmp/canary.txt")
    tmp.write_text("canary content")
    matches = detect_ransomware_canary(tmp)
    assert len(matches) == 1
    assert matches[0].detector == "ransomware-canary"
    assert matches[0].severity == "high"
    assert "canary" in matches[0].description.lower()

    tmp.unlink()

    # Non-canary file should not match
    non_canary = Path("/tmp/normal.txt")
    non_canary.write_text("normal")
    matches = detect_ransomware_canary(non_canary)
    assert matches == []
    non_canary.unlink()


def test_detect_ransomware_bulk_rename() -> None:
    files = [
        Path(f"/tmp/file{i}.locked") for i in range(12)
    ]
    matches = detect_ransomware_bulk_rename(files, window_files=10, suspicious_ratio=0.6)
    assert len(matches) == 1
    assert matches[0].detector == "ransomware-bulk-rename"
    assert matches[0].severity == "high"

    # Clean files should not match
    clean_files = [Path(f"/tmp/clean{i}.txt") for i in range(12)]
    matches = detect_ransomware_bulk_rename(clean_files, window_files=10, suspicious_ratio=0.6)
    assert matches == []

    # Below threshold should not match
    few_files = [Path(f"/tmp/file{i}.locked") for i in range(3)]
    matches = detect_ransomware_bulk_rename(few_files, window_files=10, suspicious_ratio=0.6)
    assert matches == []


def test_detect_fileless_obfuscated_script() -> None:
    tmp = Path("/tmp/script.ps1")
    tmp.write_text('powershell -enc SGVsbG8gV29ybGQh')
    matches = detect_fileless_obfuscated_script(tmp)
    assert len(matches) == 1
    assert matches[0].detector == "fileless-obfuscated-script"
    assert matches[0].severity in ("high", "medium")

    # Clean script should not match
    clean = Path("/tmp/clean.ps1")
    clean.write_text('Write-Host "hello"')
    matches = detect_fileless_obfuscated_script(clean)
    assert matches == []

    tmp.unlink()
    clean.unlink()


def test_detect_document_macro() -> None:
    tmp = Path("/tmp/macro.docm")
    tmp.write_text("VBA AutoOpen Shell CreateObject")
    matches = detect_document_macro(tmp)
    assert len(matches) == 1
    assert matches[0].detector == "document-macro"
    assert matches[0].severity == "medium"

    # Clean document (no macro markers) should not match
    clean = Path("/tmp/clean.docm")
    clean.write_text("just some plain document content here")
    matches = detect_document_macro(clean)
    assert matches == []

    # Non-docm extension should not match
    non_doc = Path("/tmp/clean.txt")
    non_doc.write_text("VBA macro shell")
    matches = detect_document_macro(non_doc)
    assert matches == []

    tmp.unlink()
    clean.unlink()
    non_doc.unlink()


def test_detect_all_ransomware_canary(tmp_path: Path) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("canary")
    result = detect_all(canary)
    assert result.total_files_scanned == 1
    assert result.match_count == 1
    assert result.matches[0].detector == "ransomware-canary"


def test_detect_all_bulk_rename(tmp_path: Path) -> None:
    for i in range(12):
        (tmp_path / f"file{i}.locked").write_text("x")
    result = detect_all(tmp_path)
    assert result.total_files_scanned == 12
    assert any(m.detector == "ransomware-bulk-rename" for m in result.matches)


def test_detect_all_clean_file_not_flagged(tmp_path: Path) -> None:
    clean = tmp_path / "clean.txt"
    clean.write_text("hello world")
    result = detect_all(clean)
    assert result.total_files_scanned == 1
    assert result.match_count == 0


def test_behaviour_match_dataclass() -> None:
    m = BehaviourMatch(
        detector="ransomware-canary",
        severity="high",
        description="test",
        path="/tmp/canary.txt",
        detail="detail",
    )
    assert m.detector == "ransomware-canary"
    assert m.severity == "high"
    assert m.description == "test"
    assert m.path == "/tmp/canary.txt"
    assert m.detail == "detail"


def test_behaviour_detection_result() -> None:
    r = BehaviourDetectionResult(path="/tmp", total_files_scanned=5)
    assert r.match_count == 0
    assert not r.has_matches

    r.matches.append(
        BehaviourMatch(
            detector="ransomware-canary",
            severity="high",
            description="x",
            path="/tmp/canary.txt",
        )
    )
    assert r.match_count == 1
    assert r.has_matches
