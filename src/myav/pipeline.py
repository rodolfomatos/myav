"""The scan pipeline: hash → ClamAV → YARA → VirusTotal (hash only) → verdict → quarantine.

Order matters. ClamAV is primary and its failure makes the verdict UNKNOWN. YARA and
VirusTotal add evidence but never subtract it. Quarantine happens only after the verdict is
fused, and only for MALICIOUS/SUSPICIOUS.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .archive import is_archive, scan_archive
from .config import Config
from .engine import EngineResult
from .engines.clamav import ClamAVEngine, SignatureInfo
from .engines.intel_engine import IntelEngine
from .engines.virustotal import VirusTotalEngine
from .engines.yara import YaraEngine
from .hashutil import digests
from .paths import Paths, classify_mount, is_within
from .platforms import Platform, detect_platform
from .quarantine import Quarantine, QuarantineError
from .state import QuarantineRecord, State
from .util import display_path
from .verdict import LEVEL_CLEAN, Verdict, fuse


@dataclass
class Engines:
    clamav: ClamAVEngine
    yara: YaraEngine
    virustotal: VirusTotalEngine
    signature_info: SignatureInfo = field(default_factory=SignatureInfo)
    platform: Platform = field(default_factory=detect_platform)
    intel: IntelEngine | None = None


def build_engines(
    config: Config, paths: Paths, state: State, platform: Platform | None = None
) -> Engines:
    plat = platform or detect_platform()
    clam = ClamAVEngine(config.clamav)
    return Engines(
        clamav=clam,
        yara=YaraEngine(config.yara, rules_dir=paths.rules_dir, cache_path=paths.yara_cache),
        virustotal=VirusTotalEngine(config.virustotal, state),
        signature_info=clam.signature_info(),
        platform=plat,
        intel=IntelEngine(config.intel, state),
    )


@dataclass
class Outcome:
    path: Path
    verdict: Verdict | None = None
    sha256: str = ""
    size: int = 0
    quarantined: QuarantineRecord | None = None
    skipped: str | None = None
    error: str | None = None
    duration: float = 0.0

    @property
    def level(self) -> str:
        return self.verdict.level if self.verdict else "UNKNOWN"

    def as_dict(self) -> dict:
        return {
            "path": display_path(self.path),
            "level": self.level,
            "sha256": self.sha256,
            "size": self.size,
            "quarantined": self.quarantined.id if self.quarantined else None,
            "skipped": self.skipped,
            "error": self.error,
            "duration": round(self.duration, 3),
            "verdict": self.verdict.as_dict() if self.verdict else None,
        }


def scan_file(
    path: Path,
    config: Config,
    paths: Paths,
    state: State,
    engines: Engines,
    *,
    kind: str = "manual",
    dry_run: bool = False,
) -> Outcome:
    started = time.monotonic()
    target = Path(path)
    outcome = Outcome(path=target)

    try:
        stat = target.lstat()
    except FileNotFoundError:
        outcome.skipped = "vanished"
        outcome.duration = time.monotonic() - started
        return outcome

    if not os.path.isfile(target):
        outcome.skipped = "not-a-regular-file"
        outcome.duration = time.monotonic() - started
        return outcome
    if os.path.islink(target) and not config.scan.follow_symlinks:
        outcome.skipped = "symlink"
        outcome.duration = time.monotonic() - started
        return outcome
    if config.scan.skip_hidden and target.name.startswith("."):
        outcome.skipped = "hidden"
        outcome.duration = time.monotonic() - started
        return outcome

    outcome.size = stat.st_size
    try:
        hashes = digests(target)
    except OSError as exc:
        outcome.error = f"unreadable: {exc}"
        outcome.verdict = Verdict(level="UNKNOWN", reasons=[outcome.error])
        outcome.duration = time.monotonic() - started
        return outcome
    outcome.sha256 = hashes["sha256"]

    if state.is_allowed(outcome.sha256):
        outcome.verdict = Verdict(level=LEVEL_CLEAN, reasons=["allowlisted by sha256"], results=[])
        _record(state, outcome, kind, quarantined=None)
        outcome.duration = time.monotonic() - started
        return outcome

    results: list[EngineResult] = []
    results.append(_safe_engine(engines.clamav.name, lambda: engines.clamav.scan(target)))
    results.append(_safe_engine(engines.yara.name, lambda: engines.yara.scan(target)))
    if engines.virustotal.configured:
        results.append(
            _safe_engine(engines.virustotal.name, lambda: engines.virustotal.lookup(outcome.sha256))
        )
    if engines.intel is not None and engines.intel.configured:
        results.append(
            _safe_engine(engines.intel.name, lambda: engines.intel.lookup(outcome.sha256))
        )

    outcome.verdict = fuse(results, stale_signatures=engines.signature_info.stale)

    quarantined = None
    if outcome.verdict.should_quarantine and not dry_run:
        quarantine = Quarantine(paths, state, config)
        try:
            quarantined = quarantine.quarantine(
                target, outcome.verdict, reason="; ".join(outcome.verdict.reasons)
            )
        except QuarantineError as exc:
            # The file is still on disk. Report that plainly; never claim it was moved.
            outcome.verdict.degraded.append(f"quarantine: {exc}")
    outcome.quarantined = quarantined

    _record(state, outcome, kind, quarantined=quarantined)
    outcome.duration = time.monotonic() - started
    return outcome


def _record(
    state: State, outcome: Outcome, kind: str, quarantined: QuarantineRecord | None
) -> None:
    verdict = outcome.verdict
    state.record_scan(
        path=str(outcome.path.absolute()),
        size=outcome.size,
        sha256=outcome.sha256,
        verdict=verdict.level if verdict else "UNKNOWN",
        engines=[result.as_dict() for result in (verdict.results if verdict else [])],
        degraded=verdict.degraded if verdict else [],
        quarantine_id=quarantined.id if quarantined else None,
        kind=kind,
    )


def _safe_engine(name: str, call) -> EngineResult:
    try:
        return call()
    except Exception as exc:  # noqa: BLE001 - an engine crash must not abort the scan
        return EngineResult(engine=name, status="error", detail=f"crashed: {exc}")


def scan_targets(
    targets: Iterable[Path],
    config: Config,
    paths: Paths,
    state: State,
    engines: Engines,
    *,
    kind: str = "manual",
    dry_run: bool = False,
) -> Iterator[Outcome]:
    for target in targets:
        if target.is_dir():
            for file_path in walk_directory(target, config):
                yield from _scan_one(
                    file_path, config, paths, state, engines, kind=kind, dry_run=dry_run
                )
        else:
            yield from _scan_one(
                target, config, paths, state, engines, kind=kind, dry_run=dry_run
            )


def _scan_one(
    file_path: Path,
    config: Config,
    paths: Paths,
    state: State,
    engines: Engines,
    *,
    kind: str = "manual",
    dry_run: bool = False,
) -> Iterator[Outcome]:
    """Scan a single path. If it is an archive, scan its contents instead."""
    if is_archive(file_path):
        yield from scan_archive(file_path, config, paths, state, engines, kind=kind)
    else:
        yield scan_file(file_path, config, paths, state, engines, kind=kind, dry_run=dry_run)


def walk_directory(root: Path, config: Config) -> Iterator[Path]:
    """Deterministic directory walk honouring symlink and hidden-file policy."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=config.scan.follow_symlinks):
        dirnames.sort()
        if config.scan.skip_hidden:
            dirnames[:] = [name for name in dirnames if not name.startswith(".")]
        for name in sorted(filenames):
            if config.scan.skip_hidden and name.startswith("."):
                continue
            candidate = Path(dirpath) / name
            if candidate.is_symlink() and not config.scan.follow_symlinks:
                continue
            if not os.path.isfile(candidate):
                continue
            yield candidate


def default_scope(config: Config, platform: Platform, include_usb: bool = True) -> list[Path]:
    """The default scan scope: user folders, plus removable mounts when asked."""
    from .paths import discover_removable_mounts

    targets = [
        Path(directory) for directory in config.watcher.watch_dirs if Path(directory).is_dir()
    ]
    if include_usb and platform.is_desktop:
        targets.extend(discover_removable_mounts())
    seen: set[Path] = set()
    unique: list[Path] = []
    for target in targets:
        if target in seen:
            continue
        seen.add(target)
        unique.append(target)
    return unique


def scope_allows(path: Path, platform: Platform) -> bool:
    """Refuse /mnt/c and WSL internals; allow everything else."""
    if not platform.is_wsl:
        return True
    kind = classify_mount(str(path))
    return kind != "windows" and not is_within(path, Path("/mnt/wsl"))
