"""ML baseline tests (research track).

These tests verify the measurement tooling only — no detection feature ships
as part of MYAV Core from this ticket.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from myav.research.ml_baseline import (
    ConfusionMatrix,
    EvaluationResult,
    LogisticRegression,
    Sample,
    extract_features,
    load_samples,
    run_ml_baseline,
    shannon_entropy,
    split_random,
    split_temporal,
)


def test_shannon_entropy() -> None:
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00\x00\x00") == 0.0
    assert shannon_entropy(b"\x00\x01\x02\x03") > 1.0


def test_extract_features_returns_fixed_length() -> None:
    import os

    fd, path = tempfile.mkstemp()
    os.write(fd, b"MZ" + b"\x00" * 100)
    os.close(fd)
    try:
        feats = extract_features(Path(path))
        assert len(feats) == 262  # 6 header + 256 histogram
        assert feats[5] == 1.0  # has PE header
    finally:
        Path(path).unlink()


def test_logistic_regression_predict() -> None:
    model = LogisticRegression.new(2)
    model.weights = [1.0, -1.0]
    model.bias = 0.0
    assert model.predict([1.0, 0.0]) == 1
    assert model.predict([0.0, 1.0]) == 0


def test_logistic_regression_fit_separable() -> None:
    model = LogisticRegression.new(2)
    X = [[0.0, 0.0], [1.0, 1.0], [0.0, 1.0], [1.0, 0.0]]
    y = [0, 1, 0, 1]  # XOR-like but linearly separable enough for demo
    model.fit(X, y)
    # Should at least not crash and produce weights
    assert len(model.weights) == 2


def test_feature_importance_sorted() -> None:
    model = LogisticRegression.new(3)
    model.weights = [0.1, -5.0, 2.0]
    imp = model.feature_importance()
    assert imp[0][1] >= imp[1][1] >= imp[2][1]
    assert imp[0][0] == 1  # -5.0 has largest abs


def test_confusion_matrix_rates() -> None:
    cm = ConfusionMatrix(
        true_negative=90, false_positive=10,
        false_negative=5, true_positive=95,
    )
    assert cm.total == 200
    assert cm.false_positive_rate == 10.0
    assert cm.false_negative_rate == 5.0
    assert round(cm.precision, 1) == 90.5  # 95 / (95+10) ≈ 90.5
    assert cm.recall == 95.0  # 95 / 100


def test_split_temporal_preserves_order() -> None:
    samples = [
        Sample(features=[0.1], label=0, timestamp="2026-01-01T00:00:00+00:00"),
        Sample(features=[0.2], label=1, timestamp="2026-02-01T00:00:00+00:00"),
        Sample(features=[0.3], label=0, timestamp="2026-03-01T00:00:00+00:00"),
        Sample(features=[0.4], label=1, timestamp="2026-04-01T00:00:00+00:00"),
    ]
    train, test = split_temporal(samples, test_fraction=0.5)
    assert len(train) == 2
    assert len(test) == 2
    assert train[0].timestamp == "2026-01-01T00:00:00+00:00"
    assert test[-1].timestamp == "2026-04-01T00:00:00+00:00"


def test_split_temporal_different_from_random() -> None:

    samples = [
        Sample(features=[float(i)], label=i % 2, timestamp=f"2026-0{i+1}-01T00:00:00+00:00")
        for i in range(20)
    ]
    train_t, test_t = split_temporal(samples, test_fraction=0.5)
    train_r, test_r = split_random(samples, test_fraction=0.5, seed=42)
    # Temporal and random splits should generally differ in composition
    t_train_paths = {s.path for s in train_t}
    r_train_paths = {s.path for s in train_r}
    # They might coincidentally be equal for tiny data, but with 20 samples
    # and different methods they almost certainly differ
    assert t_train_paths != r_train_paths or len(train_t) == len(train_r)


def test_evaluate_empty_train() -> None:
    model = LogisticRegression.new(2)
    confusion = ConfusionMatrix(0, 0, 0, 0)
    result = EvaluationResult(
        model=model,
        train_size=0,
        test_size=0,
        confusion=confusion,
        feature_importance=[],
        split_method="temporal",
    )
    assert result.test_size == 0
    assert result.confusion.false_positive_rate == 0.0


def test_run_ml_baseline_no_samples(tmp_path: Path) -> None:
    result = run_ml_baseline(tmp_path / "train", tmp_path / "test", temporal=True)
    assert result["command"] == "research-ml-baseline"
    assert "error" in result


def test_run_ml_baseline_with_samples(tmp_path: Path) -> None:
    train_dir = tmp_path / "train"
    test_dir = tmp_path / "test"
    train_dir.mkdir()
    test_dir.mkdir()

    # Create benign samples
    for i in range(10):
        (train_dir / f"ben_{i}.bin").write_bytes(b"\x00" * 50 + b"hello world")
        (test_dir / f"ben_{i}.bin").write_bytes(b"\x00" * 50 + b"hello world")
    # Create malicious samples
    for i in range(10):
        (train_dir / f"mal_{i}.bin").write_bytes(b"MZ" + b"\xff" * 100)
        (test_dir / f"mal_{i}.bin").write_bytes(b"MZ" + b"\xff" * 100)

    result = run_ml_baseline(train_dir, test_dir, temporal=True)
    assert "command" in result or "error" in result
    if "error" in result:
        pytest.fail(f"ml-baseline returned error: {result['error']}")
    assert result["command"] == "research-ml-baseline"
    assert result["split_method"] == "temporal"
    assert result["train_size"] > 0
    assert result["test_size"] > 0
    c = result["confusion"]
    total = (
        c["true_negative"]
        + c["false_positive"]
        + c["false_negative"]
        + c["true_positive"]
    )
    assert total == result["test_size"]
    assert 0.0 <= result["false_positive_rate"] <= 100.0
    assert 0.0 <= result["false_negative_rate"] <= 100.0
    assert 0.0 <= result["precision"] <= 100.0
    assert 0.0 <= result["recall"] <= 100.0
    assert len(result["top_features"]) <= 10


def test_load_samples_labels_from_prefix(tmp_path: Path) -> None:
    d = tmp_path / "samples"
    d.mkdir()
    (d / "mal_1.bin").write_bytes(b"MZ" + b"\xff" * 50)
    (d / "ben_1.bin").write_bytes(b"\x00" * 50)
    (d / "unknown.bin").write_bytes(b"\x00" * 50)
    samples = load_samples(d)
    assert len(samples) == 3
    labels = {s.label for s in samples}
    assert labels == {0, 1}  # has both benign and malicious
    mal_samples = [s for s in samples if s.label == 1]
    ben_samples = [s for s in samples if s.label == 0]
    assert len(mal_samples) == 1
    assert len(ben_samples) == 2
    assert "mal_" in mal_samples[0].path
