"""YARA adapter.

Rules are never vendored: ``myav rules fetch`` downloads a pinned public pack, verifies its
archive hash, and records provenance. This module only consumes the result.

Severity comes from rule metadata (``severity``, ``level`` or ``score``). Rules without any
of those default to *suspicious*, never malicious — an unknown rule is evidence, not proof.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..config import YaraConfig
from ..engine import CLEAN, ERROR, MALICIOUS, SKIPPED, SUSPICIOUS, EngineResult

_META_PAIR_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"|(\w+)\s*=\s*([^,\s]+)')
_LEVELS = {
    "critical": 9,
    "high": 8,
    "medium": 5,
    "moderate": 5,
    "low": 3,
    "info": 1,
    "informational": 1,
}
DEFAULT_SEVERITY = 5


@dataclass
class YaraMatch:
    rule: str
    severity: int
    meta: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {"rule": self.rule, "severity": self.severity, "meta": self.meta}


def parse_meta_block(block: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for match in _META_PAIR_RE.finditer(block):
        key = match.group(1) or match.group(3)
        value = match.group(2) if match.group(1) else match.group(4)
        if key:
            meta[key] = value
    return meta


def severity_of(meta: dict[str, str]) -> int:
    for key in ("severity", "level", "score", "threat_level"):
        raw = meta.get(key)
        if raw is None:
            continue
        text = str(raw).strip().lower()
        if text in _LEVELS:
            return _LEVELS[text]
        try:
            value = int(float(text))
        except ValueError:
            continue
        # Accept both 0-10 and 0-100 scales.
        if value > 10:
            value = (value + 5) // 10
        return max(1, min(10, value))
    return DEFAULT_SEVERITY


def parse_yara_output(stdout: str, target: str = "") -> list[YaraMatch]:
    """Parse ``yara --print-meta`` output for a single target file.

    Formats observed across 4.x:
        rule_name [author="x", severity="high"] /path/to/file
        rule_name /path/to/file
    """
    matches: list[YaraMatch] = []
    suffix = target
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        if suffix and line.endswith(suffix):
            line = line[: -len(suffix)].rstrip()
        meta: dict[str, str] = {}
        if line.endswith("]") and " [" in line:
            rule, _, meta_block = line.partition(" [")
            meta = parse_meta_block(meta_block[:-1])
        else:
            rule = line.split()[0] if line.split() else ""
        rule = rule.strip()
        if not rule:
            continue
        matches.append(YaraMatch(rule=rule, severity=severity_of(meta), meta=meta))
    return matches


class YaraEngine:
    name = "yara"

    def __init__(
        self,
        config: YaraConfig | None = None,
        rules_dir: Path | None = None,
        cache_path: Path | None = None,
        which=shutil.which,
    ):
        self.config = config or YaraConfig()
        self.rules_dir = rules_dir
        self.cache_path = cache_path
        self._which = which

    def available(self) -> bool:
        return self._which("yara") is not None

    def _rule_source(self) -> tuple[list[str], str] | None:
        if self.cache_path and self.cache_path.exists():
            return (["-C", str(self.cache_path)], "compiled-cache")
        if self.rules_dir and self.rules_dir.is_dir() and any(self.rules_dir.rglob("*.yar*")):
            return (["-r", str(self.rules_dir)], "rules-dir")
        return None

    def status(self) -> dict:
        source = self._rule_source()
        return {
            "binary": self._which("yara"),
            "rules_dir": str(self.rules_dir) if self.rules_dir else None,
            "cache": str(self.cache_path) if self.cache_path else None,
            "source": source[1] if source else "missing",
            "rule_files": len(list(self.rules_dir.rglob("*.yar*")))
            if self.rules_dir and self.rules_dir.is_dir()
            else 0,
        }

    def scan(self, path: Path) -> EngineResult:
        if not self.available():
            return EngineResult(engine=self.name, status=SKIPPED, detail="yara not installed")
        source = self._rule_source()
        if source is None:
            return EngineResult(engine=self.name, status=SKIPPED, detail="no-rules")
        try:
            size = Path(path).stat().st_size
        except OSError as exc:
            return EngineResult(engine=self.name, status=ERROR, detail=str(exc))
        if size > self.config.max_scan_bytes:
            return EngineResult(
                engine=self.name,
                status=SKIPPED,
                detail=f"file larger than {self.config.max_scan_bytes} bytes",
                meta={"size": size},
            )
        args = ["yara", "-w", "--print-meta", *source[0], str(Path(path).absolute())]
        try:
            completed = subprocess.run(
                args, capture_output=True, text=True, timeout=self.config.timeout
            )
        except subprocess.TimeoutExpired:
            return EngineResult(engine=self.name, status=ERROR, detail="timeout")
        except OSError as exc:
            return EngineResult(engine=self.name, status=ERROR, detail=str(exc))

        if completed.returncode not in (0, 1):
            return EngineResult(
                engine=self.name,
                status=ERROR,
                detail=(completed.stderr or f"exit {completed.returncode}").strip()[:300],
            )

        matches = parse_yara_output(completed.stdout, str(Path(path).absolute()))
        if not matches:
            return EngineResult(engine=self.name, status=CLEAN, meta={"source": source[1]})
        top = max(matches, key=lambda match: match.severity)
        status = MALICIOUS if top.severity >= self.config.malicious_severity else SUSPICIOUS
        return EngineResult(
            engine=self.name,
            status=status,
            signature=", ".join(match.rule for match in matches),
            meta={"matches": [match.as_dict() for match in matches], "source": source[1]},
        )
