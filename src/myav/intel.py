"""Offline threat-intel feeds: Abuse.ch (URLhaus/MalwareBazaar/ThreatFox) and MISP.

The cache lives in the state database. ``update``/``import`` are the only paths
that touch a feed; scanning never performs network I/O. Matching is exact:
only a SHA-256 hit changes a file verdict. URLs, domains and IPs are advisory
and available through ``myav intel check``.

Nothing here is a heuristic. A hit means "this exact indicator was published by
this named source", which is explainable and reproducible offline.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

IOC_SHA256 = "sha256"
IOC_URL = "url"
IOC_DOMAIN = "domain"
IOC_IP = "ip"

SUPPORTED_FORMATS = {
    "auto",
    "text",
    "urlhaus-csv",
    "malwarebazaar-json",
    "threatfox-json",
    "misp-json",
}

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}$")

HttpGet = Callable[[str, int], str]


class IntelError(RuntimeError):
    """A feed could not be fetched or parsed."""


# --------------------------------------------------------------------------- model


@dataclass
class IntelIOC:
    """One indicator of compromise with provenance."""

    ioc_type: str
    value: str
    source: str
    confidence: int = 50
    tags: list[str] = field(default_factory=list)

    def key(self) -> tuple[str, str, str]:
        return (self.ioc_type, self.value, self.source)

    def to_dict(self) -> dict:
        return {
            "type": self.ioc_type,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "tags": list(self.tags),
        }


@dataclass
class FeedUpdate:
    """Outcome of importing one feed."""

    name: str
    source: str
    format: str
    ioc_count: int

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "source": self.source,
            "format": self.format,
            "ioc_count": self.ioc_count,
        }


# --------------------------------------------------------------------------- normalisation


def normalise_indicator(text: str) -> tuple[str, str]:
    """Return ``(ioc_type, normalised_value)`` or raise ``ValueError``."""
    value = text.strip()
    if not value:
        raise ValueError("empty indicator")
    if _HEX64.match(value):
        return IOC_SHA256, value.lower()
    if value.lower().startswith(("http://", "https://")):
        return IOC_URL, value
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return IOC_IP, value
    candidate = value.rstrip(".").lower()
    if _DOMAIN.match(candidate):
        return IOC_DOMAIN, candidate
    raise ValueError(f"unsupported indicator: {text!r}")


def _ioc(ioc_type: str, value: str, source: str, confidence: int, tags: Iterable[str]) -> IntelIOC:
    return IntelIOC(
        ioc_type=ioc_type,
        value=value,
        source=source,
        confidence=max(0, min(100, int(confidence))),
        tags=sorted({tag for tag in tags if tag}),
    )


def _expand_value(value: str) -> list[tuple[str, str]]:
    """Normalise *value*, expanding a URL into URL + hostname."""
    try:
        ioc_type, normalised = normalise_indicator(value)
    except ValueError:
        return []
    if ioc_type == IOC_URL:
        expansions = [(IOC_URL, normalised)]
        host = urlsplit(normalised).hostname
        if host and _DOMAIN.match(host):
            expansions.append((IOC_DOMAIN, host.lower()))
        return expansions
    return [(ioc_type, normalised)]


def _dedupe(iocs: Iterable[IntelIOC]) -> list[IntelIOC]:
    merged: dict[tuple[str, str, str], IntelIOC] = {}
    for ioc in iocs:
        merged.setdefault(ioc.key(), ioc)
    return list(merged.values())


# --------------------------------------------------------------------------- parsers


def parse_generic_text(text: str, source: str, confidence: int = 50) -> list[IntelIOC]:
    """One indicator per line; ``#`` comments and blanks are ignored."""
    found: list[IntelIOC] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for ioc_type, value in _expand_value(stripped):
            found.append(_ioc(ioc_type, value, source, confidence, ()))
    return _dedupe(found)


def parse_urlhaus_csv(text: str, source: str, confidence: int = 80) -> list[IntelIOC]:
    """URLhaus CSV export (``id,dateadded,url,url_status,...,tags,...``)."""
    found: list[IntelIOC] = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        url = (row.get("url") or "").strip()
        if not url:
            continue
        tags = (row.get("tags") or "").split(",")
        for ioc_type, value in _expand_value(url):
            found.append(_ioc(ioc_type, value, source, confidence, tags))
    return _dedupe(found)


def parse_malwarebazaar_json(
    text: str, source: str, confidence: int = 90
) -> list[IntelIOC]:
    """MalwareBazaar ``get_recent``/``get_info`` JSON (sha256 hashes)."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IntelError(f"invalid malwarebazaar JSON: {exc}") from exc
    data = payload.get("data") or [] if isinstance(payload, dict) else []
    found: list[IntelIOC] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        digest = item.get("sha256_hash") or item.get("sha256")
        if not digest:
            continue
        tags = [item.get("signature") or "", *(item.get("tags") or [])]
        try:
            ioc_type, value = normalise_indicator(str(digest))
        except ValueError:
            continue
        if ioc_type == IOC_SHA256:
            found.append(_ioc(ioc_type, value, source, confidence, tags))
    return _dedupe(found)


def _threatfox_type(raw_type: str | None, value: str) -> str | None:
    kind = (raw_type or "").lower()
    if kind in ("sha256_hash", "sha256"):
        return IOC_SHA256
    if kind in ("ip:port", "ip"):
        return IOC_IP
    if kind == "url":
        return IOC_URL
    if kind in ("domain", "hostname"):
        return IOC_DOMAIN
    try:
        return normalise_indicator(value)[0]
    except ValueError:
        return None


def parse_threatfox_json(text: str, source: str, confidence: int = 85) -> list[IntelIOC]:
    """ThreatFox ``get_iocs`` JSON (mixed hash/url/domain/ip indicators)."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IntelError(f"invalid threatfox JSON: {exc}") from exc
    data = payload.get("data") or [] if isinstance(payload, dict) else []
    found: list[IntelIOC] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        raw = str(item.get("ioc") or "").strip()
        if not raw:
            continue
        kind = _threatfox_type(item.get("ioc_type"), raw)
        if kind == IOC_IP and ":" in raw:
            raw = raw.rsplit(":", 1)[0]
        if kind is None:
            continue
        tags = [item.get("malware") or "", *(item.get("tags") or [])]
        if kind in (IOC_DOMAIN, IOC_IP):
            try:
                ioc_type, value = normalise_indicator(raw)
            except ValueError:
                continue
            found.append(_ioc(ioc_type, value, source, confidence, tags))
        else:
            for ioc_type, value in _expand_value(raw):
                found.append(_ioc(ioc_type, value, source, confidence, tags))
    return _dedupe(found)


_MISP_TYPES = {
    "sha256": IOC_SHA256,
    "url": IOC_URL,
    "domain": IOC_DOMAIN,
    "hostname": IOC_DOMAIN,
    "ip-dst": IOC_IP,
    "ip-src": IOC_IP,
}


def _misp_attributes(payload: object) -> list[dict]:
    if isinstance(payload, dict):
        if isinstance(payload.get("response"), dict):
            attributes = payload["response"].get("Attribute")
            if isinstance(attributes, list):
                return [item for item in attributes if isinstance(item, dict)]
        attributes = payload.get("Attribute")
        if isinstance(attributes, list):
            return [item for item in attributes if isinstance(item, dict)]
        events = payload.get("Event")
        if isinstance(events, list):
            collected: list[dict] = []
            for event in events:
                if isinstance(event, dict) and isinstance(event.get("Attribute"), list):
                    collected.extend(
                        item for item in event["Attribute"] if isinstance(item, dict)
                    )
            return collected
    if isinstance(payload, list):
        collected = []
        for event in payload:
            if isinstance(event, dict) and isinstance(event.get("Attribute"), list):
                collected.extend(item for item in event["Attribute"] if isinstance(item, dict))
        return collected
    return []


def parse_misp_json(text: str, source: str, confidence: int = 90) -> list[IntelIOC]:
    """MISP attribute export. Only attributes flagged ``to_ids`` are used."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IntelError(f"invalid MISP JSON: {exc}") from exc
    found: list[IntelIOC] = []
    for attribute in _misp_attributes(payload):
        if attribute.get("to_ids") is False:
            continue
        ioc_type = _MISP_TYPES.get(str(attribute.get("type") or "").lower())
        raw = str(attribute.get("value") or "").strip()
        if ioc_type is None or not raw:
            continue
        tags: list[str] = []
        for tag in attribute.get("Tag") or []:
            if isinstance(tag, dict) and tag.get("name"):
                tags.append(str(tag["name"]))
            elif isinstance(tag, str):
                tags.append(tag)
        try:
            actual_type, value = normalise_indicator(raw)
        except ValueError:
            continue
        if ioc_type == IOC_DOMAIN and actual_type == IOC_IP:
            actual_type = IOC_IP
        found.append(_ioc(actual_type, value, source, confidence, tags))
    return _dedupe(found)


# --------------------------------------------------------------------------- format dispatch


def detect_format(text: str) -> str:
    """Best-effort format detection for ``--format auto``."""
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            return "text"
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, list) and data and isinstance(data[0], dict):
                if "ioc" in data[0] or "ioc_type" in data[0]:
                    return "threatfox-json"
                if "sha256_hash" in data[0]:
                    return "malwarebazaar-json"
            if "response" in payload or "Attribute" in payload or "Event" in payload:
                return "misp-json"
        if isinstance(payload, list):
            return "misp-json"
        return "text"
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        lowered = candidate.lower()
        if "," in candidate and ("url" in lowered or "sha256" in lowered):
            return "urlhaus-csv"
        break
    return "text"


def read_feed(text: str, fmt: str, source: str, confidence: int = 50) -> list[IntelIOC]:
    """Parse *text* using *fmt* (``auto`` detects the format first)."""
    if fmt not in SUPPORTED_FORMATS:
        raise IntelError(f"unsupported feed format: {fmt}")
    chosen = detect_format(text) if fmt == "auto" else fmt
    parsers = {
        "text": parse_generic_text,
        "urlhaus-csv": parse_urlhaus_csv,
        "malwarebazaar-json": parse_malwarebazaar_json,
        "threatfox-json": parse_threatfox_json,
        "misp-json": parse_misp_json,
    }
    parser = parsers.get(chosen)
    if parser is None:
        raise IntelError(f"unsupported feed format: {chosen}")
    return parser(text, source, confidence=confidence)


# --------------------------------------------------------------------------- fetching


def http_get(url: str, timeout: int) -> str:
    """GET a feed over HTTPS and return its body as text."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "myav/0.1 threat-intel"}, method="GET"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise IntelError(f"could not fetch {url}: {exc}") from exc


def load_source(source: str, timeout: int = 20, get: HttpGet = http_get) -> str:
    """Read a feed from an HTTP(S) URL or a local file."""
    if source.lower().startswith(("http://", "https://")):
        return get(source, timeout)
    path = Path(source).expanduser()
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise IntelError(f"could not read {path}: {exc}") from exc


def update_from_source(
    state,
    *,
    name: str,
    source: str,
    fmt: str = "auto",
    confidence: int = 50,
    timeout: int = 20,
    get: HttpGet = http_get,
) -> FeedUpdate:
    """Fetch/parse *source*, store its IOCs, and record the feed in the DB."""
    text = load_source(source, timeout=timeout, get=get)
    chosen = detect_format(text) if fmt == "auto" else fmt
    iocs = read_feed(text, fmt, source=name, confidence=confidence)
    if not iocs:
        raise IntelError(f"no supported indicators found in {source}")
    state.upsert_intel(iocs)
    state.record_intel_feed(name=name, source=source, fmt=chosen, ioc_count=len(iocs))
    return FeedUpdate(name=name, source=source, format=chosen, ioc_count=len(iocs))
