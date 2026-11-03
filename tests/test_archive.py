"""Archive scanning tests: zip/docm/7z extraction and content scanning."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from myav.archive import archive_summary, is_archive, scan_archive
from myav.config import Config
from myav.engine import CLEAN, MALICIOUS
from myav.engines.clamav import SignatureInfo
from myav.paths import Paths, default_paths
from myav.pipeline import Engines, Outcome
from myav.platforms import detect_platform
from myav.state import State
from myav.verdict import Verdict


@pytest.fixture
def archive_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    for name in ("Downloads", "Desktop", "Documents"):
        (home / name).mkdir(parents=True)
    return home


@pytest.fixture
def archive_platform(archive_home: Path):
    return detect_platform(home=archive_home, env={"MYAV_PLATFORM": "linux"})


@pytest.fixture
def archive_paths(archive_home: Path, archive_platform) -> Paths:
    return default_paths(home=archive_home, platform=archive_platform)


@pytest.fixture
def archive_config(archive_paths: Paths, archive_home: Path) -> Config:
    config = Config(paths=archive_paths)
    config.watcher.watch_dirs = [archive_home / "Downloads"]
    return config


@pytest.fixture
def archive_state(archive_paths: Paths) -> State:
    return State(archive_paths.state_db)


@pytest.fixture
def archive_engines(archive_platform):
    clam = type(
        "StubClam",
        (),
        {
            "name": "clamav",
            "available": lambda self: True,
            "signature_info": lambda self: SignatureInfo(
                available=True, version="1.5.4", db_version="27400",
                db_date=None,
            ),
            "scan": lambda self, path: type(
                "R", (), {"engine": "clamav", "status": CLEAN, "signature": None,
                          "fired": False, "as_dict": lambda self: {}}
            )(),
        },
    )()
    return Engines(
        clamav=clam,
        yara=type(
            "StubYara",
            (),
            {
                "name": "yara",
                "available": lambda self: True,
                "status": lambda self: {
                    "binary": "/usr/bin/yara",
                    "rules_dir": "/tmp/rules",
                    "cache": "/tmp/rules.yarc",
                    "source": "rules-dir",
                    "rule_files": 1,
                },
                "scan": lambda self, path: type(
                    "R", (), {"engine": "yara", "status": CLEAN, "signature": None,
                              "fired": False, "as_dict": lambda self: {}}
                )(),
            },
        )(),
        virustotal=type(
            "StubVT",
            (),
            {
                "name": "virustotal",
                "configured": False,
                "lookup": lambda self, sha: type(
                    "R", (), {"engine": "virustotal", "status": CLEAN,
                              "signature": None, "fired": False, "as_dict": lambda self: {}}
                )(),
                "status": lambda self: {
                    "configured": False,
                    "enabled": False,
                    "requests_last_minute": 0,
                    "requests_last_day": 0,
                    "limits": {"per_minute": 4, "per_day": 500},
                },
            },
        )(),
        signature_info=SignatureInfo(
            available=True, version="1.5.4", db_version="27400", db_date=None
        ),
        platform=archive_platform,
    )


def test_is_archive_detects_extensions() -> None:
    assert is_archive(Path("a.zip"))
    assert is_archive(Path("b.docm"))
    assert is_archive(Path("c.7z"))
    assert is_archive(Path("a.ZIP"))  # uppercase extension
    assert not is_archive(Path("a.txt"))
    assert not is_archive(Path("a.pdf"))


def test_scan_zip_scans_contents(
    archive_config, archive_paths, archive_state, archive_engines, tmp_path: Path
) -> None:
    zip_path = tmp_path / "test.zip"
    with zipfile.ZipFile(zip_path, "w") as _zf:
        _zf.writestr("clean.txt", "hello world")
        _zf.writestr("nested/sub/file.txt", "nested content")

    outcomes = scan_archive(zip_path, archive_config, archive_paths, archive_state, archive_engines)
    assert len(outcomes) == 2
    for o in outcomes:
        assert o.path == zip_path  # tagged with archive path
        assert o.level == "CLEAN"


def test_scan_zip_with_malicious_content(
    archive_config, archive_paths, archive_state, archive_engines, tmp_path: Path
) -> None:
    zip_path = tmp_path / "bad.zip"
    with zipfile.ZipFile(zip_path, "w") as _zf:
        _zf.writestr("evil.exe", "EICAR test string")

    # Override clamav to detect EICAR
    clam = archive_engines.clamav
    original_scan = clam.scan
    clam.scan = lambda p: type(
        "R", (), {"engine": "clamav", "status": MALICIOUS, "signature": "Eicar-Test",
                  "fired": True, "as_dict": lambda self: {}}
    )()

    outcomes = scan_archive(zip_path, archive_config, archive_paths, archive_state, archive_engines)
    assert len(outcomes) == 1
    assert outcomes[0].level == "MALICIOUS"

    clam.scan = original_scan


def test_scan_empty_zip(
    archive_config, archive_paths, archive_state, archive_engines, tmp_path: Path
) -> None:
    zip_path = tmp_path / "empty.zip"
    with zipfile.ZipFile(zip_path, "w"):
        pass

    outcomes = scan_archive(zip_path, archive_config, archive_paths, archive_state, archive_engines)
    assert len(outcomes) == 1
    assert outcomes[0].skipped is not None
    assert "empty" in outcomes[0].skipped


def test_scan_7z_without_binary(
    archive_config, archive_paths, archive_state, archive_engines, tmp_path: Path
) -> None:
    seven_z_path = tmp_path / "archive.7z"
    seven_z_path.write_bytes(b"fake 7z data")

    outcomes = scan_archive(
        seven_z_path, archive_config, archive_paths, archive_state, archive_engines
    )
    assert len(outcomes) == 1
    assert outcomes[0].skipped is not None
    assert "7z" in outcomes[0].skipped


def test_archive_summary() -> None:
    worst, findings = archive_summary([])
    assert worst == "CLEAN"
    assert findings == 0

    outcomes = [
        Outcome(path=Path("a.zip"), verdict=Verdict(level="CLEAN"), sha256="a" * 64),
        Outcome(path=Path("a.zip"), verdict=Verdict(level="SUSPICIOUS"), sha256="b" * 64),
        Outcome(path=Path("a.zip"), verdict=Verdict(level="MALICIOUS"), sha256="c" * 64),
        Outcome(path=Path("a.zip"), skipped="empty"),
    ]
    worst, findings = archive_summary(outcomes)
    assert worst == "MALICIOUS"
    assert findings == 3
