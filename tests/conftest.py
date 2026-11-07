"""Shared fixtures.

Every test runs against a temporary home directory: no test may touch the real
``~/.config/myav``, the real quarantine, or the real SQLite database. That is not
politeness — a test suite that quarantines your files is a virus.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from myav.config import Config
from myav.engine import CLEAN, EngineResult
from myav.engines.clamav import SignatureInfo
from myav.paths import default_paths
from myav.pipeline import Engines
from myav.platforms import detect_platform
from myav.state import State


@pytest.fixture
def home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    for name in ("Downloads", "Desktop", "Documents"):
        (home / name).mkdir(parents=True)
    return home


@pytest.fixture
def platform(home: Path):
    return detect_platform(home=home, env={"MYAV_PLATFORM": "linux"})


@pytest.fixture
def paths(home: Path, platform):
    return default_paths(home=home, platform=platform)


@pytest.fixture
def config(paths, home: Path) -> Config:
    config = Config(paths=paths)
    config.watcher.watch_dirs = [home / "Downloads", home / "Desktop", home / "Documents"]
    return config


@pytest.fixture
def state(paths) -> State:
    return State(paths.state_db)


class StubClam:
    name = "clamav"

    def __init__(
        self,
        status: str = CLEAN,
        signature: str | None = None,
        detail: str | None = None,
        available: bool = True,
        signature_info: SignatureInfo | None = None,
    ):
        self.status = status
        self.signature = signature
        self.detail = detail
        self._available = available
        self.info = signature_info or SignatureInfo(
            available=True,
            version="1.5.4",
            db_version="27400",
            db_date=datetime.now(timezone.utc),
        )

    def available(self) -> bool:
        return self._available

    def signature_info(self) -> SignatureInfo:
        return self.info

    def scan(self, path: Path) -> EngineResult:
        return EngineResult(
            engine=self.name,
            status=self.status,
            signature=self.signature,
            detail=self.detail,
            primary=True,
        )


class StubYara:
    name = "yara"

    def __init__(self, status: str = CLEAN, signature: str | None = None, files: int = 1):
        self.status_value = status
        self.signature = signature
        self.files = files

    def available(self) -> bool:
        return True

    def status(self) -> dict:
        return {
            "binary": "/usr/bin/yara",
            "rules_dir": "/tmp/rules",
            "cache": "/tmp/rules.yarc",
            "source": "rules-dir" if self.files else "missing",
            "rule_files": self.files,
        }

    def scan(self, path: Path) -> EngineResult:
        return EngineResult(engine=self.name, status=self.status_value, signature=self.signature)


class StubVirusTotal:
    name = "virustotal"

    def __init__(self, status: str = CLEAN, signature: str | None = None, configured: bool = False):
        self.status_value = status
        self.signature = signature
        self._configured = configured

    @property
    def configured(self) -> bool:
        return self._configured

    def lookup(self, sha256: str) -> EngineResult:
        return EngineResult(engine=self.name, status=self.status_value, signature=self.signature)

    def status(self) -> dict:
        return {
            "configured": self._configured,
            "enabled": self._configured,
            "requests_last_minute": 0,
            "requests_last_day": 0,
            "limits": {"per_minute": 4, "per_day": 500},
        }


def make_engines(
    platform,
    clam: StubClam | None = None,
    yara: StubYara | None = None,
    vt: StubVirusTotal | None = None,
    intel=None,
) -> Engines:
    clam = clam or StubClam()
    return Engines(
        clamav=clam,
        yara=yara or StubYara(),
        virustotal=vt or StubVirusTotal(),
        signature_info=clam.signature_info(),
        platform=platform,
        intel=intel,
    )


@pytest.fixture
def engines(platform):
    return make_engines(platform)
