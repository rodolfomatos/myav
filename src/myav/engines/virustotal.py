"""VirusTotal reputation by hash. **No file contents ever leave this machine.**

The only request this module can issue is ``GET /api/v3/files/{hash}``. That is enforced by
a test that greps this file: no POST, no PUT, no request body, no filename.

Hash lookup is still a privacy event — it tells VirusTotal that this machine possesses a
file with that hash. The engine is therefore opt-in, and silence is the default.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable

from ..config import VirusTotalConfig
from ..engine import CLEAN, ERROR, MALICIOUS, SKIPPED, SUSPICIOUS, EngineResult
from ..state import State
from ..util import now_ts

BASE_URL = "https://www.virustotal.com/api/v3/files/"
MALICIOUS_POSITIVES = 3

HttpGet = Callable[[str, dict[str, str], int], tuple[int, str]]


def http_get(url: str, headers: dict[str, str], timeout: int) -> tuple[int, str]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, str(exc)


class VirusTotalEngine:
    name = "virustotal"

    def __init__(
        self,
        config: VirusTotalConfig,
        state: State,
        get: HttpGet = http_get,
    ):
        self.config = config
        self.state = state
        self._get = get

    @property
    def configured(self) -> bool:
        return bool(self.config.enabled and self.config.api_key)

    def status(self) -> dict:
        return {
            "configured": self.configured,
            "enabled": self.config.enabled,
            "requests_last_minute": self.state.vt_requests_since(now_ts() - 60),
            "requests_last_day": self.state.vt_requests_since(now_ts() - 86400),
            "limits": {
                "per_minute": self.config.requests_per_minute,
                "per_day": self.config.requests_per_day,
            },
        }

    def lookup(self, sha256: str) -> EngineResult:
        if not self.configured:
            return EngineResult(engine=self.name, status=SKIPPED, detail="not-configured")

        cached = self.state.vt_get(
            sha256, self.config.ttl_positive_seconds, self.config.ttl_negative_seconds
        )
        if cached is not None:
            return self._result_from_cache(cached)

        if self.state.vt_requests_since(now_ts() - 60) >= self.config.requests_per_minute:
            return EngineResult(engine=self.name, status=SKIPPED, detail="rate-limited")
        if self.state.vt_requests_since(now_ts() - 86400) >= self.config.requests_per_day:
            return EngineResult(engine=self.name, status=SKIPPED, detail="daily-quota")

        headers = {"x-apikey": self.config.api_key, "accept": "application/json"}
        self.state.vt_record_request()
        status, body = self._get(BASE_URL + sha256, headers, self.config.timeout)

        if status == 404:
            self.state.vt_put(sha256, "unknown", 0, 0)
            return EngineResult(engine=self.name, status=SKIPPED, detail="unknown-hash")
        if status == 429:
            return EngineResult(engine=self.name, status=SKIPPED, detail="rate-limited")
        if status in (401, 403):
            return EngineResult(engine=self.name, status=ERROR, detail="auth-rejected")
        if status != 200:
            return EngineResult(
                engine=self.name, status=ERROR, detail=f"http-{status or 'unreachable'}"
            )

        try:
            payload = json.loads(body)
            stats = payload["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(int(value) for value in stats.values())
        except (ValueError, KeyError, TypeError):
            return EngineResult(engine=self.name, status=ERROR, detail="bad-response")

        self.state.vt_put(sha256, "known", malicious, total)
        return self._verdict(sha256, malicious, suspicious, total, cached=False)

    def _result_from_cache(self, cached: dict) -> EngineResult:
        if cached["status"] == "unknown":
            return EngineResult(engine=self.name, status=SKIPPED, detail="unknown-hash")
        return self._verdict(
            cached["sha256"],
            int(cached["positives"]),
            0,
            int(cached["total"]),
            cached=True,
        )

    def _verdict(
        self, sha256: str, malicious: int, suspicious: int, total: int, cached: bool
    ) -> EngineResult:
        signature = f"{malicious}/{total} engines"
        meta = {"positives": malicious, "suspicious": suspicious, "total": total, "cached": cached}
        if malicious >= MALICIOUS_POSITIVES:
            return EngineResult(engine=self.name, status=MALICIOUS, signature=signature, meta=meta)
        if malicious >= 1:
            return EngineResult(engine=self.name, status=SUSPICIOUS, signature=signature, meta=meta)
        return EngineResult(engine=self.name, status=CLEAN, signature=signature, meta=meta)
