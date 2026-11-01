"""Small shared helpers: time, sizes, redaction, path display."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

SECRET_KEYS = ("api_key", "apikey", "x-apikey", "token", "password")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def now_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def format_bytes(size: int | float) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"  # pragma: no cover - unreachable


def short_hash(digest: str, length: int = 12) -> str:
    return digest[:length]


def redact(text: str, secrets: list[str] | None = None) -> str:
    """Remove API keys from any string headed for a log, report, or exception message."""
    if not text:
        return text
    for secret in secrets or []:
        if secret and len(secret) >= 8:
            text = text.replace(secret, "***REDACTED***")
    # Defence in depth: VT keys are 64 hex chars.
    return re.sub(r"\b[0-9a-f]{64}\b", "***REDACTED***", text)


def redact_mapping_keys(data: dict) -> dict:
    """Blank out values whose key looks secret, recursively."""
    out: dict = {}
    for key, value in data.items():
        if any(marker in key.lower() for marker in SECRET_KEYS):
            out[key] = "***REDACTED***" if value else value
        elif isinstance(value, dict):
            out[key] = redact_mapping_keys(value)
        else:
            out[key] = value
    return out


def display_path(path: Path) -> str:
    home = str(Path.home())
    text = str(path)
    return "~" + text[len(home) :] if text.startswith(home) else text


def human_age(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.0f}m"
    if seconds < 172800:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"
