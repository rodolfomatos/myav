"""False-positive baseline measurement tests (research track).

These tests verify the measurement tooling only — no detection feature ships
as part of MYAV Core from this ticket.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import StubClam, make_engines

from myav.config import Config
from myav.engine import MALICIOUS, EngineResult
from myav.paths import Paths, default_paths
from myav.platforms import detect_platform
from myav.research.fp_baseline import (
    FPBaselineResult,
    scan_directory_for_false_positives,
)
from myav.state import State


class EicarClam(StubClam):
    """ClamAV stub that flags anything whose path contains 'eicar' as MALICIOUS."""

    def scan(self, path: Path) -> EngineResult:
        if path.name.lower().startswith("eicar"):
            return EngineResult(
                engine=self.name,
                status=MALICIOUS,
                signature="Eicar-Test",
                primary=True,
            )
        return super().scan(path)


@pytest.fixture
def fp_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    for name in ("Downloads", "Desktop", "Documents"):
        (home / name).mkdir(parents=True)
    return home


@pytest.fixture
def fp_platform(fp_home: Path):
    return detect_platform(home=fp_home, env={"MYAV_PLATFORM": "linux"})


@pytest.fixture
def fp_paths(fp_home: Path, fp_platform) -> Paths:
    return default_paths(home=fp_home, platform=fp_platform)


@pytest.fixture
def fp_config(fp_paths: Paths, fp_home: Path) -> Config:
    config = Config(paths=fp_paths)
    config.watcher.watch_dirs = [fp_home / "Downloads"]
    return config


@pytest.fixture
def fp_state(fp_paths: Paths) -> State:
    return State(fp_paths.state_db)


@pytest.fixture
def fp_engines(fp_platform):
    clam = StubClam()
    return make_engines(fp_platform, clam=clam)


def test_fp_baseline_clean_corpus_zero_fp(
    fp_config, fp_paths, fp_state, fp_engines, tmp_path: Path
) -> None:
    corpus = tmp_path / "clean-corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello world")
    (corpus / "b.txt").write_text("another clean file")
    (corpus / "sub").mkdir()
    (corpus / "sub" / "c.py").write_text("print('clean')")

    result = scan_directory_for_false_positives(
        corpus, fp_config, fp_paths, fp_engines
    )

    assert isinstance(result, FPBaselineResult)
    assert result.total_scanned == 3
    assert result.false_positives == 0
    assert result.false_positive_rate == 0.0
    assert result.is_clean
    assert result.flagged == []


def test_fp_baseline_with_eicar_one_fp(
    fp_config, fp_paths, fp_state, fp_platform, tmp_path: Path
) -> None:
    corpus = tmp_path / "mixed-corpus"
    corpus.mkdir()
    (corpus / "clean.txt").write_text("hello world")
    eicar = corpus / "eicar.com"
    eicar.write_text(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )

    engines = make_engines(fp_platform, clam=EicarClam())

    result = scan_directory_for_false_positives(
        corpus, fp_config, fp_paths, engines
    )

    assert result.total_scanned == 2
    assert result.false_positives == 1
    assert result.false_positive_rate == 50.0
    assert not result.is_clean
    assert len(result.flagged) == 1
    assert result.flagged[0]["level"] == "MALICIOUS"
    assert "Eicar" in result.flagged[0]["evidence"]


def test_fp_baseline_empty_directory(
    fp_config, fp_paths, fp_state, fp_engines, tmp_path: Path
) -> None:
    corpus = tmp_path / "empty"
    corpus.mkdir()

    result = scan_directory_for_false_positives(
        corpus, fp_config, fp_paths, fp_engines
    )

    assert result.total_scanned == 0
    assert result.false_positives == 0
    assert result.false_positive_rate == 0.0
    assert result.is_clean


def test_fp_baseline_report_structure(
    fp_config, fp_paths, fp_state, fp_engines, tmp_path: Path
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("clean")

    result = scan_directory_for_false_positives(
        corpus, fp_config, fp_paths, fp_engines
    )

    assert result.directory == str(corpus.resolve())
    assert result.total_scanned == 1
    assert isinstance(result.false_positive_rate, float)
