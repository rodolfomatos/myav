"""ML baseline with scientific rigour (research track).

Trains/evaluates a simple classifier on EMBER-style features with **temporal
evaluation**: train on one time period, test on a later period. Reports FPR,
FNR, precision, recall and confusion matrix — never bare accuracy.

This is a **measurement**, not a detector. It does not ship as MYAV Core
protection and never will be, unless it graduates per
docs/RESEARCH_TRACK.md (deterministic, explainable, measurable, offline).

Sommer & Paxson (2010): ML fails under real base rates.
Pendlebury et al. (2019): random train/test splits overstate performance;
temporal evaluation is required.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from pathlib import Path

# --------------------------------------------------------------------------- features


@dataclass
class Sample:
    """One feature vector with label and timestamp."""

    features: list[float]
    label: int  # 1 = malicious, 0 = benign
    timestamp: str  # ISO-8601
    path: str = ""


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_features(path: Path) -> list[float]:
    """Extract EMBER-style features from a file.

    Returns a fixed-length vector:
    [0] file size (log-scaled)
    [1] Shannon entropy
    [2] byte histogram mean
    [3] byte histogram std
    [4] printable string ratio
    [5] has PE-like header ('MZ')
    [6..] histogram of first 256 byte values (normalized)
    """
    try:
        data = path.read_bytes()
    except OSError:
        return [0.0] * 262

    size = len(data)
    size_log = math.log1p(size) / 10.0  # crude normalisation
    entropy = shannon_entropy(data) / 8.0  # normalise to [0,1]

    # Byte histogram
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = max(size, 1)
    hist = [c / total for c in counts]
    hist_mean = sum(hist) / 256.0
    hist_std = math.sqrt(sum((c - hist_mean) ** 2 for c in hist) / 256.0)

    # Printable string ratio
    printable = sum(1 for b in data if 32 <= b <= 126)
    printable_ratio = printable / total

    # PE header
    has_pe = 1.0 if data[:2] == b"MZ" else 0.0

    return [size_log, entropy, hist_mean, hist_std, printable_ratio, has_pe] + hist


# --------------------------------------------------------------------------- model


@dataclass
class LogisticRegression:
    """Minimal logistic regression with gradient descent.

    Pure stdlib implementation — no scikit-learn dependency. Feature importance
    is derived from the absolute value of the learned weights.
    """

    weights: list[float]
    bias: float
    learning_rate: float = 0.1
    n_iter: int = 1000

    @classmethod
    def new(cls, n_features: int) -> LogisticRegression:
        return cls(weights=[0.0] * n_features, bias=0.0)

    def _sigmoid(self, z: float) -> float:
        if z >= 0:
            return 1.0 / (1.0 + math.exp(-z))
        return math.exp(z) / (1.0 + math.exp(z))

    def predict_proba(self, features: list[float]) -> float:
        z = self.bias + sum(w * x for w, x in zip(self.weights, features, strict=False))
        return self._sigmoid(z)

    def predict(self, features: list[float]) -> int:
        return 1 if self.predict_proba(features) >= 0.5 else 0

    def fit(self, X: list[list[float]], y: list[int]) -> None:
        n = len(X)
        n_features = len(X[0]) if X else 0
        for _ in range(self.n_iter):
            dw = [0.0] * n_features
            db = 0.0
            for xi, yi in zip(X, y, strict=False):
                p = self.predict_proba(xi)
                error = p - yi
                db += error
                for j in range(n_features):
                    dw[j] += error * xi[j]
            for j in range(n_features):
                self.weights[j] -= (self.learning_rate / n) * dw[j]
            self.bias -= (self.learning_rate / n) * db

    def feature_importance(self) -> list[tuple[int, float]]:
        """Return (feature_index, abs_weight) sorted by importance desc."""
        imp = [(i, abs(w)) for i, w in enumerate(self.weights)]
        imp.sort(key=lambda x: x[1], reverse=True)
        return imp


# --------------------------------------------------------------------------- data loading


def load_samples(directory: Path) -> list[Sample]:
    """Load samples from a directory.

    Each file becomes one sample with label derived from filename prefix:
    'mal_' -> malicious (1), 'ben_' -> benign (0), else benign (0).
    Timestamp is the file mtime.
    """
    samples: list[Sample] = []
    if not directory.exists():
        return samples
    for p in sorted(directory.iterdir()):
        if not p.is_file():
            continue
        features = extract_features(p)
        name = p.name.lower()
        label = 1 if name.startswith("mal_") else 0
        mtime = p.stat().st_mtime
        timestamp = _iso_from_mtime(mtime)
        samples.append(
            Sample(features=features, label=label, timestamp=timestamp, path=str(p))
        )
    return samples


def _iso_from_mtime(mtime: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()


# --------------------------------------------------------------------------- split


def split_temporal(
    samples: list[Sample], test_fraction: float = 0.3
) -> tuple[list[Sample], list[Sample]]:
    """Split samples by timestamp: train on older, test on newer.

    Never shuffles — preserves temporal order so the evaluation is honest.
    """
    ordered = sorted(samples, key=lambda s: s.timestamp)
    n = len(ordered)
    if n == 0:
        return [], []
    split_idx = max(1, int(n * (1.0 - test_fraction)))
    return ordered[:split_idx], ordered[split_idx:]


def split_random(
    samples: list[Sample], test_fraction: float = 0.3, seed: int = 42
) -> tuple[list[Sample], list[Sample]]:
    """Split samples randomly (naive, overstates performance).

    Included only for comparison to show why temporal evaluation matters.
    """
    shuffled = list(samples)
    rng = random.Random(seed)
    rng.shuffle(shuffled)
    n = len(shuffled)
    if n == 0:
        return [], []
    split_idx = max(1, int(n * (1.0 - test_fraction)))
    return shuffled[:split_idx], shuffled[split_idx:]


# --------------------------------------------------------------------------- evaluation


@dataclass
class ConfusionMatrix:
    true_negative: int
    false_positive: int
    false_negative: int
    true_positive: int

    @property
    def total(self) -> int:
        return self.true_negative + self.false_positive + self.false_negative + self.true_positive

    @property
    def false_positive_rate(self) -> float:
        denom = self.true_negative + self.false_positive
        return self.false_positive / denom * 100.0 if denom else 0.0

    @property
    def false_negative_rate(self) -> float:
        denom = self.false_negative + self.true_positive
        return self.false_negative / denom * 100.0 if denom else 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom * 100.0 if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom * 100.0 if denom else 0.0


@dataclass
class EvaluationResult:
    model: LogisticRegression
    train_size: int
    test_size: int
    confusion: ConfusionMatrix
    feature_importance: list[tuple[int, float]]
    split_method: str  # "temporal" | "random"

    def to_dict(self) -> dict:
        return {
            "command": "research-ml-baseline",
            "split_method": self.split_method,
            "train_size": self.train_size,
            "test_size": self.test_size,
            "confusion": {
                "true_negative": self.confusion.true_negative,
                "false_positive": self.confusion.false_positive,
                "false_negative": self.confusion.false_negative,
                "true_positive": self.confusion.true_positive,
            },
            "false_positive_rate": round(self.confusion.false_positive_rate, 4),
            "false_negative_rate": round(self.confusion.false_negative_rate, 4),
            "precision": round(self.confusion.precision, 4),
            "recall": round(self.confusion.recall, 4),
            "top_features": [
                {"feature_index": i, "importance": round(w, 4)}
                for i, w in self.feature_importance[:10]
            ],
        }


def evaluate(
    train_samples: list[Sample],
    test_samples: list[Sample],
    split_method: str,
) -> EvaluationResult:
    """Train on train_samples, evaluate on test_samples."""
    if not train_samples:
        # Degenerate case: no training data
        model = LogisticRegression.new(0)
        confusion = ConfusionMatrix(0, 0, 0, 0)
        return EvaluationResult(
            model=model,
            train_size=0,
            test_size=len(test_samples),
            confusion=confusion,
            feature_importance=[],
            split_method=split_method,
        )

    n_features = len(train_samples[0].features)
    model = LogisticRegression.new(n_features)
    X_train = [s.features for s in train_samples]
    y_train = [s.label for s in train_samples]
    model.fit(X_train, y_train)

    tn = fp = fn = tp = 0
    for s in test_samples:
        pred = model.predict(s.features)
        if s.label == 1 and pred == 1:
            tp += 1
        elif s.label == 1 and pred == 0:
            fn += 1
        elif s.label == 0 and pred == 1:
            fp += 1
        else:
            tn += 1

    confusion = ConfusionMatrix(tn, fp, fn, tp)
    return EvaluationResult(
        model=model,
        train_size=len(train_samples),
        test_size=len(test_samples),
        confusion=confusion,
        feature_importance=model.feature_importance(),
        split_method=split_method,
    )


def run_ml_baseline(
    train_dir: Path | None,
    test_dir: Path | None,
    temporal: bool = True,
) -> dict:
    """Run the full ML baseline measurement.

    Loads samples from train_dir and test_dir, trains a logistic regression,
    evaluates with confusion matrix metrics. Returns a JSON-serialisable dict.
    """
    train_samples = load_samples(train_dir) if train_dir else []
    test_samples = load_samples(test_dir) if test_dir else []

    if not train_samples and not test_samples:
        return {
            "command": "research-ml-baseline",
            "error": "no samples found in train or test directory",
            "train_size": 0,
            "test_size": 0,
        }

    if temporal and train_samples and test_samples:
        # Combined temporal split: sort all by time, train=older, test=newer
        all_samples = train_samples + test_samples
        train_split, test_split = split_temporal(all_samples)
        method = "temporal"
    else:
        train_split = train_samples
        test_split = test_samples
        method = "random"

    result = evaluate(train_split, test_split, method)
    return result.to_dict()
