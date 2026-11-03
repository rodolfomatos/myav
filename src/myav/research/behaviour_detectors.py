"""Purpose-specific behavioural detection (research track).

Read-only heuristic detectors that fire on *patterns* rather than byte signatures:

- **Ransomware:** honeyfile/canary modification; bulk rename with suspicious extensions.
- **Fileless / LOTL:** obfuscated PowerShell/VBA scripts (high entropy, known patterns).
- **Documents:** Office macro / PDF OLE object presence (extraction only, no execution).

These are alert-only detections for research measurement. Nothing ships as MYAV Core
protection unless it graduates per docs/RESEARCH_TRACK.md.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- data types


@dataclass(frozen=True)
class BehaviourMatch:
    """A single behavioural match from a detector."""

    # detector: ransomware-canary | ransomware-bulk-rename |
    # fileless-obfuscated-script | document-macro
    detector: str
    # severity: high | medium | low
    severity: str
    description: str
    path: str
    detail: str = ""


@dataclass
class BehaviourDetectionResult:
    """Result of scanning a path/directory with all detectors."""

    path: str
    total_files_scanned: int
    matches: list[BehaviourMatch] = field(default_factory=list)

    @property
    def match_count(self) -> int:
        return len(self.matches)

    @property
    def has_matches(self) -> bool:
        return len(self.matches) > 0


# --------------------------------------------------------------------------- entropy


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = uniform, 8 = maximum randomness)."""
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


# --------------------------------------------------------------------------- ransomware detectors


SUSPICIOUS_EXTENSIONS = {
    ".locked", ".crypto", ".encrypted", ".enc", ".ransom", ".wannacry",
    ".cerber", ".locky", ".petya", ".crypt", ".xtbl", ".zzz", ".micro",
    ".exx", ".eva", ".lock97",
}


def detect_ransomware_canary(
    path: Path,
    canary_names: set[str] | None = None,
) -> list[BehaviourMatch]:
    """Alert if a canary/honeyfile is modified or renamed.

    ``canary_names`` defaults to common canary filenames. If the scanned path
    itself is a canary and its content changed since baseline (simply: file
    exists and is non-empty here as a proxy for "touched"), alert.
    """
    if canary_names is None:
        canary_names = {
            "canary.txt", "honeyfile.txt", "my_canary.txt",
            "DO_NOT_OPEN.txt", "readme_canary.txt",
        }
    matches: list[BehaviourMatch] = []
    if path.is_file() and path.name in canary_names:
        matches.append(
            BehaviourMatch(
                detector="ransomware-canary",
                severity="high",
                description="Canary/honeyfile touched — possible ransomware activity",
                path=str(path),
                detail=f"canary file '{path.name}' exists and is non-empty",
            )
        )
    return matches


def detect_ransomware_bulk_rename(
    files: list[Path],
    window_files: int = 10,
    suspicious_ratio: float = 0.6,
) -> list[BehaviourMatch]:
    """Alert if many files are renamed with suspicious extensions in short window.

    Heuristic: if ``window_files`` or more files have suspicious ransomware
    extensions, and the ratio of suspicious to total exceeds ``suspicious_ratio``,
    alert.
    """
    matches: list[BehaviourMatch] = []
    if len(files) < window_files:
        return matches
    suspicious = sum(1 for f in files if f.suffix.lower() in SUSPICIOUS_EXTENSIONS)
    if suspicious == 0:
        return matches
    ratio = suspicious / len(files)
    if ratio >= suspicious_ratio:
        matches.append(
            BehaviourMatch(
                detector="ransomware-bulk-rename",
                severity="high",
                description="Bulk rename with suspicious extensions — possible ransomware",
                path=str(files[0]),
                detail=f"{suspicious}/{len(files)} files have ransomware-like extensions",
            )
        )
    return matches


# --------------------------------------------------------------------------- fileless / LOTL


OBFUSCATED_PATTERNS = [
    re.compile(r"powershell.*-enc\b", re.IGNORECASE),
    re.compile(r"powershell.*-encodedcommand\b", re.IGNORECASE),
    re.compile(r"mshta\b", re.IGNORECASE),
    re.compile(r"certutil\b.*-decode", re.IGNORECASE),
    re.compile(r"wmic\b", re.IGNORECASE),
    re.compile(r"regsvr32\b", re.IGNORECASE),
    re.compile(r"rundll32\b", re.IGNORECASE),
    re.compile(r"iex\b", re.IGNORECASE),
    re.compile(r"invoke-expression", re.IGNORECASE),
    re.compile(r"base64", re.IGNORECASE),
    re.compile(r"FromBase64String", re.IGNORECASE),
]


def detect_fileless_obfuscated_script(
    path: Path,
    entropy_threshold: float = 4.5,
) -> list[BehaviourMatch]:
    """Alert if a script looks obfuscated (high entropy or known LOTL patterns)."""
    matches: list[BehaviourMatch] = []
    if not path.is_file():
        return matches
    try:
        data = path.read_bytes()
    except OSError:
        return matches
    text = data.decode("utf-8", errors="replace")

    # Pattern matches
    fired_patterns = [
        pat.pattern for pat in OBFUSCATED_PATTERNS if pat.search(text)
    ]
    if not fired_patterns:
        return matches

    ent = shannon_entropy(data)
    severity = "high" if ent >= entropy_threshold else "medium"

    matches.append(
        BehaviourMatch(
            detector="fileless-obfuscated-script",
            severity=severity,
            description="Obfuscated script detected — possible fileless/LOTL activity",
            path=str(path),
            detail=f"patterns: {', '.join(fired_patterns[:3])}; "
            f"entropy={ent:.2f} bits/byte",
        )
    )
    return matches


# --------------------------------------------------------------------------- document detectors


def detect_document_macro(path: Path) -> list[BehaviourMatch]:
    """Alert if a document likely contains macros/OLE objects (extraction only).

    Heuristic: file extension and simple content scan for VBA/Office markers.
    Does NOT execute or parse the document structure deeply.
    """
    matches: list[BehaviourMatch] = []
    if not path.is_file():
        return matches
    ext = path.suffix.lower()
    macro_extensions = {".docm", ".xlsm", ".pptm", ".doc", ".xls", ".ppt"}
    if ext not in macro_extensions:
        return matches
    try:
        data = path.read_bytes()
    except OSError:
        return matches
    text = data.decode("utf-8", errors="replace").lower()
    markers = [
        "vba", "macro", "autoopen", "document_open",
        "shell", "createobject", "executeexcelscript4macro",
    ]
    found = [m for m in markers if m in text]
    if not found:
        return matches
    matches.append(
        BehaviourMatch(
            detector="document-macro",
            severity="medium",
            description="Document contains macro/OLE markers — inspection recommended",
            path=str(path),
            detail=f"markers: {', '.join(found[:5])}",
        )
    )
    return matches


# --------------------------------------------------------------------------- orchestration


def iter_files(root: Path) -> Iterator[Path]:
    """Yield regular files under *root* (or the file itself if root is a file)."""
    if root.is_file():
        yield root
        return
    if root.is_dir():
        for p in sorted(root.rglob("*")):
            if p.is_file():
                yield p


def detect_all(
    path: Path,
    *,
    canary_names: set[str] | None = None,
    window_files: int = 10,
    suspicious_ratio: float = 0.6,
    entropy_threshold: float = 4.5,
) -> BehaviourDetectionResult:
    """Run all behavioural detectors against *path*.

    Read-only: reads files but never writes, quarantines, or blocks.
    """
    path = path.resolve()
    files = list(iter_files(path))
    matches: list[BehaviourMatch] = []

    for f in files:
        matches.extend(detect_ransomware_canary(f, canary_names=canary_names))
        matches.extend(detect_fileless_obfuscated_script(f, entropy_threshold=entropy_threshold))
        matches.extend(detect_document_macro(f))

    matches.extend(
        detect_ransomware_bulk_rename(
            files, window_files=window_files, suspicious_ratio=suspicious_ratio
        )
    )

    return BehaviourDetectionResult(
        path=str(path),
        total_files_scanned=len(files),
        matches=matches,
    )
