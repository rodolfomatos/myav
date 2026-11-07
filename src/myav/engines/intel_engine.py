"""Exact-match threat-intel engine backed by the local IOC cache.

This engine never performs network I/O. It only answers one question: *has this
exact SHA-256 been published by a named feed already imported into the state
database?* A hit is explainable — the source and confidence travel with it —
and reproducible offline.

URLs, domains and IPs are deliberately **not** consulted here. Matching them
against file contents would be a heuristic with an unmeasured false-positive
rate; they remain available through ``myav intel check`` as advisory data.
"""

from __future__ import annotations

from typing import Any

from ..config import IntelConfig
from ..engine import CLEAN, MALICIOUS, EngineResult
from ..state import State


class IntelEngine:
    name = "intel"

    def __init__(self, config: IntelConfig, state: State):
        self.config = config
        self.state = state

    @property
    def configured(self) -> bool:
        """Only join the pipeline when enabled *and* the cache has indicators."""
        if not self.config.enabled:
            return False
        return int(self.state.intel_summary()["total"]) > 0

    def lookup(self, sha256: str) -> EngineResult:
        hits = self.state.lookup_intel("sha256", sha256.lower())
        if not hits:
            return EngineResult(
                engine=self.name,
                status=CLEAN,
                detail="no exact hash match in the local intel cache",
            )
        best = hits[0]
        sources = ", ".join(
            f"{hit['source']} (confidence {hit['confidence']})" for hit in hits
        )
        return EngineResult(
            engine=self.name,
            status=MALICIOUS,
            signature=f"intel:{best['source']}",
            detail=f"exact SHA-256 match published by {sources}",
            meta={
                "sources": [
                    {
                        "source": hit["source"],
                        "confidence": hit["confidence"],
                        "tags": hit["tags"],
                    }
                    for hit in hits
                ]
            },
        )

    def status(self) -> dict[str, Any]:
        summary = self.state.intel_summary()
        return {
            "configured": self.configured,
            "enabled": self.config.enabled,
            "max_age_hours": self.config.max_age_hours,
            "timeout": self.config.timeout,
            "ioc_count": summary["total"],
            "by_type": summary["by_type"],
            "sources": summary["sources"],
            "feeds": summary["feeds"],
            "last_update": summary["last_update"],
        }
