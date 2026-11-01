"""Streaming file digests. Never loads a file into memory."""

from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK = 1024 * 1024


def digests(path: Path, algorithms: tuple[str, ...] = ("sha256", "md5")) -> dict[str, str]:
    """Return ``{algo: hexdigest}`` computed in a single read pass."""
    hashers = {name: hashlib.new(name) for name in algorithms}
    with open(path, "rb") as handle:
        while True:
            block = handle.read(CHUNK)
            if not block:
                break
            for hasher in hashers.values():
                hasher.update(block)
    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def sha256_file(path: Path) -> str:
    return digests(path, ("sha256",))["sha256"]
