"""False-positive / false-negative measurement tests (research track).

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
    ConfusionMatrix,
    MeasurementResult,
    ScanOutcome,
    measure_fp_fn,
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


def test_measure_fp_fn_clean_corpus_zero_fp(
    fp_config, fp_paths, fp_state, fp_engines, tmp_path: Path
) -> None:
    corpus = tmp_path / "clean-corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello world")
    (corpus / "b.txt").write_text("another clean file")
    (corpus / "sub").mkdir()
    (corpus / "sub" / "c.py").write_text("print('clean')")

    result = measure_fp_fn(corpus, fp_config, fp_paths, fp_engines)

    assert isinstance(result, MeasurementResult)
    c = result.confusion
    assert c.total_clean == 3
    assert c.false_positive == 0
    assert c.true_negative == 3
    assert c.false_positive_rate == 0.0
    assert c.recall == 0.0  # no malicious files, so recall is undefined/zero


def test_measure_fp_fn_with_eicar_one_fp(
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

    result = measure_fp_fn(corpus, fp_config, fp_paths, engines)

    assert result.confusion.total == 2
    assert result.confusion.false_positive == 1
    assert result.confusion.true_negative == 1
    assert result.false_positive_rate == 50.0
    assert len(result.clean_details) == 1
    assert result.clean_details[0]["level"] == "MALICIOUS"
    assert "Eicar" in result.clean_details[0]["evidence"]


def test_measure_fp_fn_empty_directory(
    fp_config, fp_paths, fp_state, fp_engines, tmp_path: Path
) -> None:
    corpus = tmp_path / "empty"
    corpus.mkdir()

    result = measure_fp_fn(corpus, fp_config, fp_paths, fp_engines)

    assert result.confusion.total_clean == 0
    assert result.confusion.false_positive == 0
    assert result.false_positive_rate == 0.0


def test_measure_fp_fn_with_malicious_dir_calculates_fnr(
    fp_config, fp_paths, fp_state, fp_platform, tmp_path: Path
) -> None:
    clean_dir = tmp_path / "clean-corpus"
    clean_dir.mkdir()
    (clean_dir / "a.txt").write_text("hello world")

    malicious_dir = tmp_path / "malicious-corpus"
    malicious_dir.mkdir()
    # One eicar that WILL be detected (true positive)
    detected = malicious_dir / "eicar.com"
    detected.write_text(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    # One clean-looking file that will NOT be detected (false negative)
    missed = malicious_dir / "stealth.bin"
    missed.write_text("this looks clean but is actually malware")

    engines = make_engines(fp_platform, clam=EicarClam())

    result = measure_fp_fn(
        clean_dir, fp_config, fp_paths, engines, malicious_dir=malicious_dir
    )

    c = result.confusion
    assert c.total_clean == 1
    assert c.false_positive == 0
    assert c.total_malicious == 2
    assert c.true_positive == 1  # eicar detected
    assert c.false_negative == 1  # stealth.bin missed
    assert c.false_positive_rate == 0.0
    assert c.false_negative_rate == 50.0
    assert c.precision == 100.0
    assert c.recall == 50.0


def test_measure_fp_fn_all_malicious_detected(
    fp_config, fp_paths, fp_state, fp_platform, tmp_path: Path
) -> None:
    clean_dir = tmp_path / "clean-corpus"
    clean_dir.mkdir()
    (clean_dir / "a.txt").write_text("hello world")

    malicious_dir = tmp_path / "malicious-corpus"
    malicious_dir.mkdir()
    (malicious_dir / "eicar1.com").write_text(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    (malicious_dir / "eicar2.com").write_text(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )

    engines = make_engines(fp_platform, clam=EicarClam())

    result = measure_fp_fn(
        clean_dir, fp_config, fp_paths, engines, malicious_dir=malicious_dir
    )

    c = result.confusion
    assert c.total_malicious == 2
    assert c.true_positive == 2
    assert c.false_negative == 0
    assert c.false_negative_rate == 0.0
    assert c.recall == 100.0


def test_scan_outcome_dataclass() -> None:
    outcome = ScanOutcome(
        directory="/tmp/test",
        total_scanned=5,
        flagged=2,
        skipped=1,
        flagged_files=[
            {
                "path": "/tmp/test/a.txt",
                "level": "MALICIOUS",
                "evidence": "clamav:Eicar",
                "sha256": "abc",
            }
        ],
    )
    assert outcome.total_scanned == 5
    assert outcome.flagged == 2
    assert outcome.skipped == 1
    assert len(outcome.flagged_files) == 1


def test_confusion_matrix_properties() -> None:
    cm = ConfusionMatrix(
        true_negative=90, false_positive=10,
        false_negative=5, true_positive=95,
    )
    assert cm.total_clean == 100
    assert cm.total_malicious == 100
    assert cm.total == 200
    assert cm.false_positive_rate == 10.0
    assert cm.false_negative_rate == 5.0
    assert round(cm.precision, 1) == 90.5  # 95 / (95+10)
    assert cm.recall == 95.0  # 95 / 100


def test_confusion_matrix_empty() -> None:
    cm = ConfusionMatrix(
        true_negative=0, false_positive=0,
        false_negative=0, true_positive=0,
    )
    assert cm.false_positive_rate == 0.0
    assert cm.false_negative_rate == 0.0
    assert cm.precision == 0.0
    assert cm.recall == 0.0
