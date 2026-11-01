"""ClamAV adapter.

Per-file ``clamscan`` reloads ~250 MiB of signatures (1–3 s per file), which makes it
unusable for a watcher. ``clamdscan`` against a warm daemon answers in milliseconds, so
the daemon is tried first and the CLI is the documented fallback.

Parsing is separated into pure functions so the tests never need a real ClamAV.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from ..config import ClamAVConfig
from ..engine import CLEAN, ERROR, MALICIOUS, SKIPPED, EngineResult

_FOUND_RE = re.compile(r"^(?P<path>.+?): (?P<sig>.+) FOUND$")
_OK_RE = re.compile(r"^(?P<path>.+?): OK$")
_VERSION_RE = re.compile(r"ClamAV (?P<version>[\d.]+)/(?P<db>\d+)/(?P<date>.+)$")
_DAEMON_DOWN_MARKERS = (
    "could not connect",
    "connection refused",
    "no such file or directory",
    "can't connect",
    "failed to connect",
    "unable to connect",
)

STALE_AFTER = timedelta(hours=48)


@dataclass
class SignatureInfo:
    version: str = ""
    db_version: str = ""
    db_date: datetime | None = None
    available: bool = False
    detail: str = ""

    @property
    def age(self) -> timedelta | None:
        if self.db_date is None:
            return None
        return datetime.now(timezone.utc) - self.db_date

    @property
    def stale(self) -> bool:
        age = self.age
        return age is None or age > STALE_AFTER

    def as_dict(self) -> dict:
        age = self.age
        return {
            "available": self.available,
            "version": self.version,
            "db_version": self.db_version,
            "db_date": self.db_date.isoformat() if self.db_date else None,
            "age_hours": round(age.total_seconds() / 3600, 1) if age else None,
            "stale": self.stale,
            "detail": self.detail,
        }


def parse_version_output(text: str) -> SignatureInfo:
    for line in text.splitlines():
        match = _VERSION_RE.search(line.strip())
        if not match:
            continue
        info = SignatureInfo(
            available=True, version=match.group("version"), db_version=match.group("db")
        )
        try:
            parsed = parsedate_to_datetime(match.group("date").strip())
            info.db_date = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            info.detail = "could not parse signature database date"
        return info
    return SignatureInfo(available=bool(text.strip()), detail="unrecognised version output")


def parse_scan_output(stdout: str, returncode: int, engine: str) -> EngineResult:
    """Turn clamdscan/clamscan output into exactly one result."""
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    for line in lines:
        match = _FOUND_RE.match(line)
        if match:
            return EngineResult(
                engine=engine,
                status=MALICIOUS,
                signature=match.group("sig").strip(),
                primary=True,
            )
    for line in lines:
        if _OK_RE.match(line):
            return EngineResult(engine=engine, status=CLEAN, primary=True)
    if returncode == 0:
        return EngineResult(engine=engine, status=CLEAN, detail="no findings", primary=True)
    if returncode == 1:
        # Virus found but the line was unparseable; do not guess which signature.
        return EngineResult(engine=engine, status=MALICIOUS, signature="unparsed", primary=True)
    return EngineResult(
        engine=engine,
        status=ERROR,
        detail=(lines[-1] if lines else f"exit {returncode}"),
        primary=True,
    )


class ClamAVEngine:
    name = "clamav"

    def __init__(self, config: ClamAVConfig | None = None, which=shutil.which):
        self.config = config or ClamAVConfig()
        self._which = which

    # ------------------------------------------------------------------ probes

    def _binary(self, name: str) -> str | None:
        return self._which(name)

    def available(self) -> bool:
        return self._binary("clamdscan") is not None or self._binary("clamscan") is not None

    def signature_info(self) -> SignatureInfo:
        binary = self._binary("clamscan") or self._binary("clamdscan")
        if binary is None:
            return SignatureInfo(available=False, detail="clamscan/clamdscan not found")
        try:
            completed = subprocess.run(
                [binary, "--version"], capture_output=True, text=True, timeout=20
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return SignatureInfo(available=False, detail=str(exc))
        if completed.returncode != 0:
            return SignatureInfo(available=False, detail=completed.stderr.strip()[:200])
        return parse_version_output(completed.stdout)

    # -------------------------------------------------------------------- scan

    def scan(self, path: Path) -> EngineResult:
        absolute = str(Path(path).absolute())
        if self._binary("clamdscan"):
            result, stderr = self._run("clamdscan", absolute)
            if result.status == ERROR and _looks_like_daemon_down(stderr):
                fallback, _ = self._run("clamscan", absolute)
                fallback.meta["fallback"] = "clamscan"
                fallback.meta["daemon_error"] = result.detail
                return fallback
            return result
        if self._binary("clamscan"):
            result, _ = self._run("clamscan", absolute)
            result.meta["fallback"] = "clamscan"
            return result
        return EngineResult(
            engine=self.name,
            status=SKIPPED,
            detail="clamav not installed",
            primary=True,
        )

    def _run(self, binary: str, absolute: str) -> tuple[EngineResult, str]:
        try:
            completed = subprocess.run(
                [binary, "--no-summary", "--stdout", absolute],
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )
        except subprocess.TimeoutExpired:
            return (
                EngineResult(engine=binary, status=ERROR, detail="timeout", primary=True),
                "",
            )
        except OSError as exc:
            return EngineResult(engine=binary, status=ERROR, detail=str(exc), primary=True), ""
        return (
            parse_scan_output(completed.stdout, completed.returncode, binary),
            completed.stderr or "",
        )


def _looks_like_daemon_down(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(marker in lowered for marker in _DAEMON_DOWN_MARKERS)
