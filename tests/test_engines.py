from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from myav.config import VirusTotalConfig, YaraConfig
from myav.engine import CLEAN, ERROR, MALICIOUS, SKIPPED, SUSPICIOUS
from myav.engines import clamav as clamav_module
from myav.engines import virustotal as vt_module
from myav.engines import yara as yara_module
from myav.engines.clamav import (
    ClamAVEngine,
    SignatureInfo,
    _looks_like_daemon_down,
    parse_scan_output,
    parse_version_output,
)
from myav.engines.virustotal import VirusTotalEngine, http_get
from myav.engines.yara import (
    YaraEngine,
    parse_meta_block,
    parse_yara_output,
    severity_of,
)
from myav.state import State


def completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["x"], returncode=returncode, stdout=stdout, stderr=stderr
    )


# ----------------------------------------------------------------------------- ClamAV


def test_parse_version_output() -> None:
    info = parse_version_output("ClamAV 1.5.4/27400/Wed Oct 30 08:12:34 2026\n")
    assert info.available
    assert info.version == "1.5.4"
    assert info.db_version == "27400"
    assert info.db_date is not None


def test_parse_version_output_bad_date() -> None:
    info = parse_version_output("ClamAV 1.5.4/27400/not-a-date")
    assert info.available
    assert "could not parse" in info.detail


def test_parse_version_output_unrecognised() -> None:
    assert parse_version_output("garbage").available is True
    assert parse_version_output("garbage").detail == "unrecognised version output"
    assert parse_version_output("").available is False


def test_signature_info_stale_without_date() -> None:
    assert SignatureInfo().stale is True
    assert SignatureInfo().age is None
    assert SignatureInfo().as_dict()["age_hours"] is None


def test_parse_scan_output_variants() -> None:
    found = parse_scan_output("/tmp/eicar.txt: Eicar-Test-Signature FOUND", 1, "clamdscan")
    assert found.status == MALICIOUS
    assert found.signature == "Eicar-Test-Signature"
    assert found.primary

    ok = parse_scan_output("/tmp/a.txt: OK", 0, "clamdscan")
    assert ok.status == CLEAN

    zero = parse_scan_output("", 0, "clamdscan")
    assert zero.status == CLEAN
    assert zero.detail == "no findings"

    unparsed = parse_scan_output("something weird", 1, "clamdscan")
    assert unparsed.status == MALICIOUS
    assert unparsed.signature == "unparsed"

    error = parse_scan_output("", 2, "clamdscan")
    assert error.status == ERROR
    assert "exit 2" in error.detail


def test_looks_like_daemon_down() -> None:
    assert _looks_like_daemon_down("ERROR: Could not connect to clamd")
    assert _looks_like_daemon_down("Connection refused")
    assert not _looks_like_daemon_down("virus found")


def test_clamav_unavailable_when_no_binary() -> None:
    engine = ClamAVEngine(which=lambda name: None)
    assert engine.available() is False
    assert engine.signature_info().available is False
    assert engine.scan(Path("/tmp/x")).status == SKIPPED


def test_clamav_signature_info_paths(monkeypatch) -> None:
    engine = ClamAVEngine(which=lambda name: "/usr/bin/clamscan")
    monkeypatch.setattr(
        clamav_module.subprocess, "run", lambda *a, **k: completed(0, "ClamAV 1.0/1/x\n")
    )
    assert engine.signature_info().available

    monkeypatch.setattr(clamav_module.subprocess, "run", lambda *a, **k: completed(2, "", "boom"))
    info = engine.signature_info()
    assert not info.available
    assert "boom" in info.detail

    def explode(*a, **k):
        raise OSError("nope")

    monkeypatch.setattr(clamav_module.subprocess, "run", explode)
    assert engine.signature_info().available is False


def test_clamav_scan_uses_daemon(monkeypatch, tmp_path: Path) -> None:
    engine = ClamAVEngine(which=lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(
        clamav_module.subprocess,
        "run",
        lambda *a, **k: completed(1, f"{tmp_path / 'x'}: Eicar FOUND\n"),
    )
    result = engine.scan(tmp_path / "x")
    assert result.status == MALICIOUS
    assert result.engine == "clamdscan"


def test_clamav_scan_falls_back_when_daemon_down(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []

    def fake_run(argv, **kwargs):
        calls.append(argv[0])
        if argv[0].endswith("clamdscan"):
            return completed(2, "", "ERROR: Could not connect to clamd")
        return completed(0, f"{tmp_path / 'x'}: OK\n")

    engine = ClamAVEngine(which=lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(clamav_module.subprocess, "run", fake_run)
    result = engine.scan(tmp_path / "x")
    assert result.status == CLEAN
    assert result.engine == "clamscan"
    assert result.meta["fallback"] == "clamscan"
    assert "clamdscan" in calls and "clamscan" in calls


def test_clamav_scan_without_daemon(monkeypatch, tmp_path: Path) -> None:
    engine = ClamAVEngine(which=lambda name: "/usr/bin/clamscan" if name == "clamscan" else None)
    monkeypatch.setattr(clamav_module.subprocess, "run", lambda *a, **k: completed(0, "OK\n"))
    result = engine.scan(tmp_path / "x")
    assert result.status == CLEAN
    assert result.meta["fallback"] == "clamscan"


def test_clamav_scan_timeout_and_oserror(monkeypatch, tmp_path: Path) -> None:
    engine = ClamAVEngine(which=lambda name: "/usr/bin/clamscan")

    def timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="clamscan", timeout=1)

    monkeypatch.setattr(clamav_module.subprocess, "run", timeout)
    assert engine.scan(tmp_path / "x").status == ERROR

    def oserror(*a, **k):
        raise OSError("boom")

    monkeypatch.setattr(clamav_module.subprocess, "run", oserror)
    assert engine.scan(tmp_path / "x").status == ERROR


# ------------------------------------------------------------------------------- YARA


def test_parse_meta_block() -> None:
    meta = parse_meta_block('author="me", severity="high", score=9, bare=yes')
    assert meta["author"] == "me"
    assert meta["severity"] == "high"
    assert meta["score"] == "9"
    assert meta["bare"] == "yes"


def test_severity_of() -> None:
    assert severity_of({"severity": "critical"}) == 9
    assert severity_of({"level": "low"}) == 3
    assert severity_of({"score": "7"}) == 7
    assert severity_of({"score": "85"}) == 9  # 0-100 scale normalised
    assert severity_of({"score": "0"}) == 1
    assert severity_of({}) == 5
    assert severity_of({"severity": "nonsense"}) == 5


def test_parse_yara_output_with_and_without_meta() -> None:
    target = "/tmp/sample.bin"
    output = (
        'evil_rule [author="me", severity="high"] /tmp/sample.bin\nplain_rule /tmp/sample.bin\n'
    )
    matches = parse_yara_output(output, target)
    assert [match.rule for match in matches] == ["evil_rule", "plain_rule"]
    assert matches[0].severity == 8
    assert matches[1].severity == 5


def test_yara_status_and_missing_rules(tmp_path: Path) -> None:
    engine = YaraEngine(which=lambda name: "/usr/bin/yara", rules_dir=tmp_path / "none")
    assert engine.available()
    assert engine.status()["source"] == "missing"
    result = engine.scan(tmp_path / "x")
    assert result.status == SKIPPED
    assert result.detail == "no-rules"

    engine = YaraEngine(which=lambda name: None)
    assert engine.scan(tmp_path / "x").detail == "yara not installed"


def test_yara_scan_too_large(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yar").write_text("rule a { condition: true }")
    target = tmp_path / "big.bin"
    target.write_bytes(b"x" * 10)
    engine = YaraEngine(
        config=YaraConfig(max_scan_bytes=5), rules_dir=rules, which=lambda name: "/usr/bin/yara"
    )
    result = engine.scan(target)
    assert result.status == SKIPPED
    assert result.meta["size"] == 10


def test_yara_scan_matches(monkeypatch, tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yar").write_text("rule a { condition: true }")
    target = tmp_path / "sample.bin"
    target.write_bytes(b"data")

    def fake_run(argv, **kwargs):
        return completed(0, 'evil [severity="high"] /tmp/sample.bin\n')

    engine = YaraEngine(
        config=YaraConfig(malicious_severity=7),
        rules_dir=rules,
        which=lambda name: "/usr/bin/yara",
    )
    monkeypatch.setattr(yara_module.subprocess, "run", fake_run)
    monkeypatch.setattr(yara_module.Path, "absolute", lambda self: Path("/tmp/sample.bin"))
    result = engine.scan(target)
    assert result.status == MALICIOUS
    assert "evil" in result.signature

    monkeypatch.setattr(
        yara_module.subprocess,
        "run",
        lambda *a, **k: completed(0, 'meh [severity="low"] /tmp/sample.bin\n'),
    )
    assert engine.scan(target).status == SUSPICIOUS

    monkeypatch.setattr(yara_module.subprocess, "run", lambda *a, **k: completed(0, ""))
    assert engine.scan(target).status == CLEAN


def test_yara_scan_errors(monkeypatch, tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yar").write_text("rule a { condition: true }")
    target = tmp_path / "x"
    target.write_bytes(b"x")
    engine = YaraEngine(rules_dir=rules, which=lambda name: "/usr/bin/yara")

    monkeypatch.setattr(
        yara_module.subprocess, "run", lambda *a, **k: completed(2, "", "syntax error")
    )
    assert engine.scan(target).status == ERROR

    def timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="yara", timeout=1)

    monkeypatch.setattr(yara_module.subprocess, "run", timeout)
    assert engine.scan(target).status == ERROR

    def oserror(*a, **k):
        raise OSError("nope")

    monkeypatch.setattr(yara_module.subprocess, "run", oserror)
    assert engine.scan(target).status == ERROR


def test_yara_compiled_cache_is_preferred(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yar").write_text("rule a { condition: true }")
    cache = tmp_path / "rules.yarc"
    cache.write_bytes(b"compiled")
    engine = YaraEngine(rules_dir=rules, cache_path=cache, which=lambda name: "/usr/bin/yara")
    assert engine.status()["source"] == "compiled-cache"


# ------------------------------------------------------------------------ VirusTotal


def _vt(
    state: State,
    configured: bool = True,
    get=None,
    per_minute: int = 100,
    per_day: int = 500,
) -> VirusTotalEngine:
    config = VirusTotalConfig(
        enabled=configured,
        api_key="a" * 64 if configured else "",
        requests_per_minute=per_minute,
        requests_per_day=per_day,
    )
    return VirusTotalEngine(config, state, get=get or (lambda url, headers, timeout: (200, "{}")))


def test_vt_unconfigured(state: State) -> None:
    engine = _vt(state, configured=False)
    assert engine.configured is False
    result = engine.lookup("b" * 64)
    assert result.status == SKIPPED
    assert result.detail == "not-configured"
    status = engine.status()
    assert status["configured"] is False


def test_vt_known_hash_verdicts(state: State) -> None:
    payload = (
        '{"data": {"attributes": {"last_analysis_stats": '
        '{"malicious": 5, "suspicious": 1, "undetected": 60, "harmless": 4, "timeout": 0}}}}'
    )
    engine = _vt(state, get=lambda url, headers, timeout: (200, payload))
    result = engine.lookup("b" * 64)
    assert result.status == MALICIOUS
    assert result.signature == "5/70 engines"
    assert result.meta["total"] == 70

    # Second lookup is served from the SQLite cache, with no HTTP call.
    def explode(*args, **kwargs):
        raise AssertionError("should not hit the network")

    engine._get = explode
    cached = engine.lookup("b" * 64)
    assert cached.status == MALICIOUS
    assert cached.meta["cached"] is True


def test_vt_suspicious_and_clean(state: State) -> None:
    suspicious = (
        '{"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "undetected": 9}}}}'
    )
    engine = _vt(state, get=lambda *a: (200, suspicious))
    assert engine.lookup("b" * 64).status == SUSPICIOUS

    clean = '{"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "undetected": 10}}}}'
    engine = _vt(state, get=lambda *a: (200, clean))
    assert engine.lookup("c" * 64).status == CLEAN


def test_vt_http_error_paths(state: State) -> None:
    engine = _vt(state, get=lambda *a: (404, ""))
    result = engine.lookup("b" * 64)
    assert result.status == SKIPPED
    assert result.detail == "unknown-hash"
    # The negative answer is cached; the next call is served locally.
    engine._get = lambda *a: (_ for _ in ()).throw(AssertionError("network"))
    assert engine.lookup("b" * 64).detail == "unknown-hash"

    engine = _vt(state, get=lambda *a: (429, ""))
    assert engine.lookup("d" * 64).detail == "rate-limited"

    engine = _vt(state, get=lambda *a: (401, ""))
    assert engine.lookup("e" * 64).status == ERROR

    engine = _vt(state, get=lambda *a: (503, ""))
    assert engine.lookup("f" * 64).detail == "http-503"

    engine = _vt(state, get=lambda *a: (200, "not json"))
    assert engine.lookup("1" * 64).detail == "bad-response"

    engine = _vt(state, get=lambda *a: (200, '{"data": {}}'))
    assert engine.lookup("2" * 64).detail == "bad-response"


def test_vt_rate_limits(state: State) -> None:
    engine = _vt(state, get=lambda *a: (404, ""), per_minute=2)
    state.vt_put("3" * 64, "known", 0, 10)
    state.vt_put("4" * 64, "known", 0, 10)
    state.vt_record_request()
    state.vt_record_request()
    result = engine.lookup("5" * 64)
    assert result.detail == "rate-limited"

    engine = _vt(state, get=lambda *a: (404, ""), per_day=0)
    assert engine.lookup("6" * 64).detail == "daily-quota"


def test_vt_cache_result_unknown(state: State) -> None:
    engine = _vt(state)
    state.vt_put("7" * 64, "unknown", 0, 0)
    assert engine.lookup("7" * 64).detail == "unknown-hash"


def test_http_get_handles_errors(monkeypatch) -> None:
    import urllib.error

    class FakeResponse:
        status = 200

        def read(self):
            return b"body"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(vt_module.urllib.request, "urlopen", lambda *a, **k: FakeResponse())
    assert http_get("https://example", {}, 1) == (200, "body")

    def http_error(*a, **k):
        raise urllib.error.HTTPError("url", 404, "missing", {}, None)

    monkeypatch.setattr(vt_module.urllib.request, "urlopen", http_error)
    assert http_get("https://example", {}, 1)[0] == 404

    def url_error(*a, **k):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(vt_module.urllib.request, "urlopen", url_error)
    assert http_get("https://example", {}, 1)[0] == 0


@pytest.mark.parametrize("positives,expected", [(3, MALICIOUS), (2, SUSPICIOUS), (0, CLEAN)])
def test_vt_thresholds(state: State, positives: int, expected: str) -> None:
    payload = json.dumps(
        {
            "data": {
                "attributes": {"last_analysis_stats": {"malicious": positives, "undetected": 10}}
            }
        }
    )
    engine = _vt(state, get=lambda *a: (200, payload))
    assert engine.lookup(f"{positives:064x}").status == expected
