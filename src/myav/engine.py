"""Engine result type shared by ClamAV, YARA and VirusTotal."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CLEAN = "clean"
MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"
ERROR = "error"
SKIPPED = "skipped"

STATUSES = {CLEAN, MALICIOUS, SUSPICIOUS, ERROR, SKIPPED}


@dataclass
class EngineResult:
    """The only thing an engine adapter is allowed to return.

    ``primary`` marks the engine whose failure makes a verdict UNKNOWN instead of merely
    degraded: ClamAV is the primary engine, YARA and VirusTotal add evidence.
    """

    engine: str
    status: str
    signature: str | None = None
    detail: str | None = None
    primary: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"invalid engine status: {self.status}")

    @property
    def fired(self) -> bool:
        return self.status in {MALICIOUS, SUSPICIOUS}

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "status": self.status,
            "signature": self.signature,
            "detail": self.detail,
            "primary": self.primary,
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EngineResult:
        return cls(
            engine=data["engine"],
            status=data["status"],
            signature=data.get("signature"),
            detail=data.get("detail"),
            primary=bool(data.get("primary", False)),
            meta=data.get("meta", {}),
        )
