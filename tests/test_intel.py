"""Threat-intel parser, cache and engine tests (T037).

Everything is synthetic and offline: no test performs network I/O, and the
fetch hook is injected exactly like the VirusTotal adapter does it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import make_engines

from myav.config import Config
from myav.engine import CLEAN, MALICIOUS
from myav.engines.intel_engine import IntelEngine
from myav.hashutil import sha256_file
from myav.intel import (
    IOC_DOMAIN,
    IOC_IP,
    IOC_SHA256,
    IOC_URL,
    IntelError,
    IntelIOC,
    detect_format,
    load_source,
    normalise_indicator,
    parse_generic_text,
    parse_malwarebazaar_json,
    parse_misp_json,
    parse_threatfox_json,
    parse_urlhaus_csv,
    read_feed,
    update_from_source,
)
from myav.state import State

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


# --------------------------------------------------------------------- normalisation


def test_normalise_sha256_is_lowercased() -> None:
    assert normalise_indicator(SHA_A.upper()) == (IOC_SHA256, SHA_A)


def test_normalise_url_and_domain_and_ip() -> None:
    assert normalise_indicator("https://evil.example/x") == (IOC_URL, "https://evil.example/x")
    assert normalise_indicator("Evil.Example.") == (IOC_DOMAIN, "evil.example")
    assert normalise_indicator("1.2.3.4") == (IOC_IP, "1.2.3.4")
    assert normalise_indicator("2001:db8::1") == (IOC_IP, "2001:db8::1")


@pytest.mark.parametrize("value", ["", "   ", "not an indicator", "ftp://x"])
def test_normalise_rejects_garbage(value: str) -> None:
    with pytest.raises(ValueError):
        normalise_indicator(value)


# --------------------------------------------------------------------------- parsers


def test_parse_generic_text_skips_comments_and_expands_urls() -> None:
    text = f"# comment\n\n{SHA_A}\nhttps://evil.example/payload\n1.2.3.4\n"
    iocs = parse_generic_text(text, source="manual")
    assert {(ioc.ioc_type, ioc.value) for ioc in iocs} == {
        (IOC_SHA256, SHA_A),
        (IOC_URL, "https://evil.example/payload"),
        (IOC_DOMAIN, "evil.example"),
        (IOC_IP, "1.2.3.4"),
    }


def test_parse_urlhaus_csv() -> None:
    text = (
        "id,dateadded,url,url_status,tags\n"
        "1,2026-01-01,https://bad.example/a,online,emotet\n"
        "2,2026-01-01,not-a-url,online,skip\n"
    )
    iocs = parse_urlhaus_csv(text, source="urlhaus")
    values = {(ioc.ioc_type, ioc.value) for ioc in iocs}
    assert (IOC_URL, "https://bad.example/a") in values
    assert (IOC_DOMAIN, "bad.example") in values
    assert all(ioc.confidence == 80 for ioc in iocs)
    assert any("emotet" in ioc.tags for ioc in iocs)


def test_parse_malwarebazaar_json() -> None:
    text = (
        '{"query_status":"ok","data":['
        f'{{"sha256_hash":"{SHA_A.upper()}","signature":"AgentTesla","tags":["exe"]}},'
        '{"sha256_hash":"nope"}]}'
    )
    iocs = parse_malwarebazaar_json(text, source="bazaar")
    assert len(iocs) == 1
    assert iocs[0].ioc_type == IOC_SHA256
    assert iocs[0].value == SHA_A
    assert "AgentTesla" in iocs[0].tags


def test_parse_malwarebazaar_invalid_json() -> None:
    with pytest.raises(IntelError):
        parse_malwarebazaar_json("{", source="bazaar")


def test_parse_threatfox_json_mixed_types() -> None:
    text = (
        '{"data":['
        '{"ioc":"1.2.3.4:443","ioc_type":"ip:port","malware":"Cobalt"},'
        '{"ioc":"evil.example","ioc_type":"domain","malware":"Loader"},'
        '{"ioc":"https://evil.example/x","ioc_type":"url"},'
        f'{{"ioc":"{SHA_B}","ioc_type":"sha256_hash"}},'
        '{"ioc":"???","ioc_type":"unknown"}]}'
    )
    iocs = parse_threatfox_json(text, source="threatfox")
    values = {(ioc.ioc_type, ioc.value) for ioc in iocs}
    assert (IOC_IP, "1.2.3.4") in values
    assert (IOC_DOMAIN, "evil.example") in values
    assert (IOC_URL, "https://evil.example/x") in values
    assert (IOC_SHA256, SHA_B) in values


def test_parse_misp_json_uses_only_to_ids() -> None:
    text = (
        '{"response":{"Attribute":['
        f'{{"type":"sha256","value":"{SHA_C}","to_ids":true,'
        '"Tag":[{"name":"tlp:white"},"malware"]},'
        '{"type":"ip-dst","value":"5.6.7.8","to_ids":false},'
        '{"type":"domain","value":"evil.example","to_ids":true}]}}'
    )
    iocs = parse_misp_json(text, source="misp")
    values = {(ioc.ioc_type, ioc.value) for ioc in iocs}
    assert values == {(IOC_SHA256, SHA_C), (IOC_DOMAIN, "evil.example")}
    sha = next(ioc for ioc in iocs if ioc.ioc_type == IOC_SHA256)
    assert sha.tags == ["malware", "tlp:white"]


def test_parse_misp_json_invalid() -> None:
    with pytest.raises(IntelError):
        parse_misp_json("[]broken", source="misp")


# ---------------------------------------------------------------------- format dispatch


def test_detect_format_variants() -> None:
    assert detect_format(f'{{"data":[{{"sha256_hash":"{SHA_A}"}}]}}') == "malwarebazaar-json"
    assert detect_format('{"data":[{"ioc":"1.2.3.4","ioc_type":"ip"}]}') == "threatfox-json"
    assert detect_format('{"Attribute":[]}') == "misp-json"
    assert detect_format("id,dateadded,url,url_status\n1,x,https://a.example,online") == (
        "urlhaus-csv"
    )
    assert detect_format(SHA_A) == "text"


def test_read_feed_rejects_unknown_format() -> None:
    with pytest.raises(IntelError):
        read_feed("x", "bogus", source="s")


def test_read_feed_auto_uses_detected_format() -> None:
    iocs = read_feed(
        '{"data":[{"ioc":"1.2.3.4","ioc_type":"ip:port"}]}', "auto", source="s"
    )
    assert iocs[0].value == "1.2.3.4"


# ------------------------------------------------------------------------- fetching


def test_load_source_reads_local_file(tmp_path: Path) -> None:
    feed = tmp_path / "feed.txt"
    feed.write_text(SHA_A)
    assert load_source(str(feed)) == SHA_A


def test_load_source_missing_file() -> None:
    with pytest.raises(IntelError):
        load_source("/nonexistent/feed.txt")


def test_update_from_source_uses_injected_get(state: State) -> None:
    calls: list[tuple[str, int]] = []

    def fake_get(url: str, timeout: int) -> str:
        calls.append((url, timeout))
        return SHA_A

    result = update_from_source(
        state,
        name="manual",
        source="https://feeds.example/list.txt",
        fmt="auto",
        timeout=7,
        get=fake_get,
    )
    assert calls == [("https://feeds.example/list.txt", 7)]
    assert result.ioc_count == 1
    assert result.format == "text"
    assert state.lookup_intel(IOC_SHA256, SHA_A)[0]["source"] == "manual"
    feeds = state.intel_feeds()
    assert feeds[0]["name"] == "manual"
    assert feeds[0]["ioc_count"] == 1


def test_update_from_source_empty_feed_is_an_error(state: State) -> None:
    with pytest.raises(IntelError):
        update_from_source(state, name="empty", source="# nothing\n", fmt="text")


# ------------------------------------------------------------------------- state cache


def test_upsert_lookup_and_summary(state: State) -> None:
    assert state.upsert_intel(
        [
            IntelIOC(IOC_SHA256, SHA_A, "feed-a", confidence=80, tags=["emotet"]),
            IntelIOC(IOC_DOMAIN, "evil.example", "feed-a"),
            IntelIOC(IOC_IP, "1.2.3.4", "feed-b", confidence=90),
        ]
    ) == 3
    state.record_intel_feed(
        name="feed-a", source="https://a", fmt="text", ioc_count=2
    )

    summary = state.intel_summary()
    assert summary["total"] == 3
    assert summary["by_type"] == {IOC_DOMAIN: 1, IOC_IP: 1, IOC_SHA256: 1}
    assert summary["sources"] == 2
    assert summary["feeds"] == 1
    assert summary["last_update"] is not None

    hits = state.lookup_intel(IOC_SHA256, SHA_A.upper())
    assert len(hits) == 1
    assert hits[0]["source"] == "feed-a"
    assert hits[0]["confidence"] == 80
    assert hits[0]["tags"] == ["emotet"]


def test_upsert_merges_same_key_and_preserves_first_seen(state: State) -> None:
    state.upsert_intel([IntelIOC(IOC_SHA256, SHA_A, "feed", confidence=10)])
    first = state.lookup_intel(IOC_SHA256, SHA_A)[0]["first_seen"]
    state.upsert_intel([IntelIOC(IOC_SHA256, SHA_A, "feed", confidence=99, tags=["new"])])
    hits = state.lookup_intel(IOC_SHA256, SHA_A)
    assert len(hits) == 1
    assert hits[0]["confidence"] == 99
    assert hits[0]["tags"] == ["new"]
    assert hits[0]["first_seen"] == first


def test_upsert_accepts_mappings_and_skips_invalid(state: State) -> None:
    assert state.upsert_intel(
        [
            {"type": IOC_IP, "value": "9.9.9.9", "source": "dict"},
            {"type": IOC_IP, "value": "", "source": "dict"},
        ]
    ) == 1
    assert state.lookup_intel(IOC_IP, "9.9.9.9")[0]["source"] == "dict"


def test_record_intel_feed_updates_provenance(state: State) -> None:
    state.record_intel_feed(name="f", source="old", fmt="text", ioc_count=1)
    state.record_intel_feed(name="f", source="new", fmt="misp-json", ioc_count=7)
    feeds = state.intel_feeds()
    assert len(feeds) == 1
    assert feeds[0]["source"] == "new"
    assert feeds[0]["format"] == "misp-json"
    assert feeds[0]["ioc_count"] == 7


def test_clear_intel_removes_iocs_and_feeds(state: State) -> None:
    state.upsert_intel([IntelIOC(IOC_SHA256, SHA_A, "feed")])
    state.record_intel_feed(name="feed", source="s", fmt="text", ioc_count=1)
    assert state.clear_intel() == 1
    assert state.intel_summary()["total"] == 0
    assert state.intel_feeds() == []


# ------------------------------------------------------------------------- engine


def test_engine_disabled_even_with_cache(state: State, config: Config) -> None:
    state.upsert_intel([IntelIOC(IOC_SHA256, SHA_A, "feed")])
    engine = IntelEngine(config.intel, state)  # enabled is False by default
    assert engine.configured is False
    assert engine.lookup(SHA_A).status == MALICIOUS  # lookup itself is unconditional


def test_engine_enabled_without_cache_is_not_configured(state: State, config: Config) -> None:
    config.intel.enabled = True
    assert IntelEngine(config.intel, state).configured is False


def test_engine_hit_and_miss(state: State, config: Config) -> None:
    config.intel.enabled = True
    state.upsert_intel(
        [
            IntelIOC(IOC_SHA256, SHA_A, "feed-a", confidence=80, tags=["emotet"]),
            IntelIOC(IOC_SHA256, SHA_A, "feed-b", confidence=90),
        ]
    )
    engine = IntelEngine(config.intel, state)
    assert engine.configured is True

    hit = engine.lookup(SHA_A.upper())
    assert hit.status == MALICIOUS
    assert hit.signature == "intel:feed-b"  # highest confidence first
    assert "feed-a" in (hit.detail or "")
    assert {item["source"] for item in hit.meta["sources"]} == {"feed-a", "feed-b"}

    miss = engine.lookup(SHA_B)
    assert miss.status == CLEAN
    assert miss.fired is False


def test_engine_status(state: State, config: Config) -> None:
    config.intel.enabled = True
    state.upsert_intel([IntelIOC(IOC_SHA256, SHA_A, "feed")])
    state.record_intel_feed(name="feed", source="s", fmt="text", ioc_count=1)
    payload = IntelEngine(config.intel, state).status()
    assert payload["configured"] is True
    assert payload["ioc_count"] == 1
    assert payload["feeds"] == 1
    assert payload["by_type"] == {IOC_SHA256: 1}


# ------------------------------------------------------------------------- pipeline


def test_pipeline_intel_hit_is_malicious(
    config, paths, state, platform, tmp_path: Path
) -> None:
    from myav.paths import ensure_dirs
    from myav.pipeline import scan_file

    ensure_dirs(paths)
    target = tmp_path / "payload.bin"
    target.write_bytes(b"payload")
    digest = sha256_file(target)

    state.upsert_intel([IntelIOC(IOC_SHA256, digest, "feed", confidence=95)])
    config.intel.enabled = True

    engines = make_engines(platform, intel=IntelEngine(config.intel, state))
    outcome = scan_file(target, config, paths, state, engines)
    assert outcome.level == "MALICIOUS"
    assert any(result.engine == "intel" and result.fired for result in outcome.verdict.results)


def test_pipeline_intel_miss_does_not_change_verdict(
    config, paths, state, platform, tmp_path: Path
) -> None:
    from myav.paths import ensure_dirs
    from myav.pipeline import scan_file

    ensure_dirs(paths)
    target = tmp_path / "clean.bin"
    target.write_bytes(b"benign")
    state.upsert_intel([IntelIOC(IOC_SHA256, SHA_A, "feed")])
    config.intel.enabled = True

    engines = make_engines(platform, intel=IntelEngine(config.intel, state))
    outcome = scan_file(target, config, paths, state, engines)
    assert outcome.level == "CLEAN"
