"""Archive handling: extract and scan contents of zip/7z/docm files.

A ``.zip`` (or ``.docm``, which is a zip) is extracted to a temporary directory and every
contained file is scanned individually. A ``.7z`` is handled the same way when the ``7z``
binary is available; otherwise it is skipped and reported as degraded.

Bomb protection: at most ``MAX_EXTRACT_FILES`` files and ``MAX_EXTRACT_TOTAL_BYTES`` bytes
are extracted, preventing zip-bomb style denial of service.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

from .config import Config
from .paths import Paths
from .state import State

if TYPE_CHECKING:
    from .pipeline import Engines, Outcome


ARCHIVE_EXTENSIONS = {".zip", ".docm", ".7z"}
MAX_EXTRACT_FILES = 1000
MAX_EXTRACT_TOTAL_BYTES = 100 * 1024 * 1024  # 100 MiB


def is_archive(path: Path) -> bool:
    return path.suffix.lower() in ARCHIVE_EXTENSIONS


def scan_archive(
    path: Path,
    config: Config,
    paths: Paths,
    state: State,
    engines: Engines,
    kind: str = "manual",
) -> list[Outcome]:
    """Extract an archive and scan every contained file.

    Returns one :class:`Outcome` per extracted file, each tagged with the archive's path
    so reports show which archive contained the finding. The archive itself is not
    quarantined here — individual malicious files inside it are.
    """
    from .pipeline import Outcome, scan_file  # lazy import to avoid circular import

    outcomes: list[Outcome] = []
    tmpdir = Path(tempfile.mkdtemp(prefix="myav-archive-"))
    try:
        suffix = path.suffix.lower()
        if suffix == ".7z":
            seven_z = shutil.which("7z")
            if not seven_z:
                outcomes.append(
                    Outcome(  # type: ignore[call-arg]
                        path=path,
                        skipped="7z not installed — .7z contents not scanned",
                    )
                )
                return outcomes
            completed = subprocess.run(
                [seven_z, "x", str(path), f"-o{tmpdir}", "-y"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if completed.returncode != 0:
                outcomes.append(
                    Outcome(  # type: ignore[call-arg]
                        path=path,
                        skipped=f"7z extraction failed: {completed.stderr.strip()[:120]}",
                    )
                )
                return outcomes
        else:
            # .zip and .docm are both zip-format
            extracted = 0
            total_bytes = 0
            with zipfile.ZipFile(path) as zf:
                for member in zf.infolist():
                    if member.is_dir():
                        continue
                    if extracted >= MAX_EXTRACT_FILES:
                        break
                    total_bytes += member.file_size
                    if total_bytes > MAX_EXTRACT_TOTAL_BYTES:
                        break
                    zf.extract(member, tmpdir)
                    extracted += 1

            if extracted == 0:
                outcomes.append(
                    Outcome(  # type: ignore[call-arg]
                        path=path,
                        skipped="archive is empty or only contains directories",
                    )
                )
                return outcomes

        for file_path in sorted(tmpdir.rglob("*")):
            if file_path.is_file() and not file_path.is_symlink():
                outcome = scan_file(
                    file_path, config, paths, state, engines, kind=kind
                )
                # Tag the outcome with the archive path so the report shows the container.
                outcome.path = path
                outcomes.append(outcome)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return outcomes


def archive_summary(outcomes: list[Outcome]) -> tuple[str, int]:
    """Return (worst_level, count_of_findings) from archive scan outcomes."""
    worst = "CLEAN"
    findings = 0
    rank = {"CLEAN": 0, "UNKNOWN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}
    for o in outcomes:
        if o.skipped:
            continue
        level = o.level
        findings += 1
        if rank.get(level, 0) > rank.get(worst, 0):
            worst = level
    return worst, findings
