from __future__ import annotations

from pathlib import Path

import pytest
from conftest import StubClam, StubVirusTotal, StubYara, make_engines

from myav import pipeline as pipeline_module
from myav.engine import ERROR, MALICIOUS, SUSPICIOUS
from myav.hashutil import sha256_file
from myav.pipeline import (
    build_engines,
    default_scope,
    scan_file,
    scan_targets,
    scope_allows,
    walk_directory,
)
from myav.quarantine import QuarantineError
from myav.verdict import LEVEL_CLEAN, LEVEL_MALICIOUS, LEVEL_SUSPICIOUS, LEVEL_UNKNOWN


@pytest.fixture
def target(tmp_path: Path) -> Path:
    path = tmp_path / "sample.bin"
    path.write_bytes(b"sample payload")
    return path


def test_missing_file_is_skipped(config, paths, state, engines, tmp_path: Path) -> None:
    outcome = scan_file(tmp_path / "ghost", config, paths, state, engines)
    assert outcome.skipped == "vanished"
    assert outcome.level == "UNKNOWN"


def test_directory_is_skipped(config, paths, state, engines, tmp_path: Path) -> None:
    outcome = scan_file(tmp_path, config, paths, state, engines)
    assert outcome.skipped == "not-a-regular-file"


def test_symlink_policy(config, paths, state, engines, target: Path, tmp_path: Path) -> None:
    link = tmp_path / "link.bin"
    link.symlink_to(target)
    assert scan_file(link, config, paths, state, engines).skipped == "symlink"

    config.scan.follow_symlinks = True
    outcome = scan_file(link, config, paths, state, engines)
    assert outcome.skipped is None
    assert outcome.sha256 == sha256_file(target)


def test_hidden_policy(config, paths, state, engines, tmp_path: Path) -> None:
    hidden = tmp_path / ".secret"
    hidden.write_bytes(b"x")
    assert scan_file(hidden, config, paths, state, engines).skipped is None
    config.scan.skip_hidden = True
    assert scan_file(hidden, config, paths, state, engines).skipped == "hidden"


def test_unreadable_file_is_unknown(config, paths, state, engines, target: Path) -> None:
    target.chmod(0o000)
    try:
        outcome = scan_file(target, config, paths, state, engines)
    finally:
        target.chmod(0o600)
    assert outcome.level == LEVEL_UNKNOWN
    assert outcome.error is not None


def test_allowlisted_hash_is_clean(config, paths, state, engines, target: Path) -> None:
    state.allow(sha256_file(target), reason="known good")
    outcome = scan_file(target, config, paths, state, engines)
    assert outcome.level == LEVEL_CLEAN
    assert "allowlisted" in outcome.verdict.reasons[0]
    assert outcome.verdict.results == []


def test_clean_scan_is_recorded(config, paths, state, engines, target: Path) -> None:
    outcome = scan_file(target, config, paths, state, engines, kind="unit")
    assert outcome.level == LEVEL_CLEAN
    assert outcome.sha256 == sha256_file(target)
    assert outcome.size == 14
    assert state.last_scan_ts("unit") is not None


def test_malicious_file_is_quarantined(config, paths, state, target: Path, platform) -> None:
    engines = make_engines(
        platform, clam=StubClam(status=MALICIOUS, signature="Eicar-Test-Signature")
    )
    outcome = scan_file(target, config, paths, state, engines)
    assert outcome.level == LEVEL_MALICIOUS
    assert outcome.quarantined is not None
    assert not target.exists()
    assert state.list_quarantines()[0].id == outcome.quarantined.id


def test_suspicious_file_is_quarantined_tagged(
    config, paths, state, target: Path, platform
) -> None:
    engines = make_engines(platform, yara=StubYara(status=SUSPICIOUS, signature="Packer"))
    outcome = scan_file(target, config, paths, state, engines)
    assert outcome.level == LEVEL_SUSPICIOUS
    assert outcome.quarantined.tag == "suspicious"


def test_dry_run_never_quarantines(config, paths, state, target: Path, platform) -> None:
    engines = make_engines(platform, clam=StubClam(status=MALICIOUS, signature="Eicar"))
    outcome = scan_file(target, config, paths, state, engines, dry_run=True)
    assert outcome.level == LEVEL_MALICIOUS
    assert outcome.quarantined is None
    assert target.exists()
    assert state.list_quarantines() == []


def test_quarantine_failure_is_reported_not_hidden(
    config, paths, state, target: Path, platform, monkeypatch
) -> None:
    class Failing:
        def __init__(self, *args, **kwargs):
            pass

        def quarantine(self, *args, **kwargs):
            raise QuarantineError("disk full", code=3)

    monkeypatch.setattr(pipeline_module, "Quarantine", Failing)
    engines = make_engines(platform, clam=StubClam(status=MALICIOUS, signature="Eicar"))
    outcome = scan_file(target, config, paths, state, engines)
    assert outcome.level == LEVEL_MALICIOUS
    assert outcome.quarantined is None
    assert target.exists()
    assert any("disk full" in item for item in outcome.verdict.degraded)


def test_engine_crash_never_aborts_the_scan(config, paths, state, target: Path, platform) -> None:
    class Exploding(StubClam):
        def scan(self, path):
            raise RuntimeError("engine bug")

    engines = make_engines(platform, clam=Exploding())
    outcome = scan_file(target, config, paths, state, engines)
    assert outcome.level == LEVEL_UNKNOWN
    assert target.exists()


def test_virustotal_runs_only_when_configured(config, paths, state, target: Path, platform) -> None:
    engines = make_engines(
        platform, vt=StubVirusTotal(status=MALICIOUS, signature="9/70", configured=True)
    )
    outcome = scan_file(target, config, paths, state, engines)
    assert outcome.level == LEVEL_MALICIOUS


def test_walk_directory_order_and_policies(tmp_path: Path, config) -> None:
    root = tmp_path / "tree"
    (root / "sub").mkdir(parents=True)
    (root / "b.txt").write_bytes(b"b")
    (root / "a.txt").write_bytes(b"a")
    (root / ".hidden").write_bytes(b"h")
    (root / "sub" / "c.txt").write_bytes(b"c")
    (root / "link.txt").symlink_to(root / "a.txt")

    names = [path.name for path in walk_directory(root, config)]
    assert names == [".hidden", "a.txt", "b.txt", "c.txt"]

    config.scan.skip_hidden = True
    names = [path.name for path in walk_directory(root, config)]
    assert ".hidden" not in names


def test_scan_targets_walks_directories(config, paths, state, engines, tmp_path: Path) -> None:
    root = tmp_path / "dir"
    root.mkdir()
    (root / "one.txt").write_bytes(b"1")
    (root / "two.txt").write_bytes(b"2")
    outcomes = list(scan_targets([root], config, paths, state, engines))
    assert len(outcomes) == 2


def test_default_scope_dedupes_and_includes_usb(
    config, platform, tmp_path: Path, monkeypatch
) -> None:
    usb = tmp_path / "usb"
    usb.mkdir()
    monkeypatch.setattr("myav.paths.discover_removable_mounts", lambda: [usb])
    scope = default_scope(config, platform)
    assert scope == config.watcher.watch_dirs + [usb]

    duplicated = config.watcher.watch_dirs + [config.watcher.watch_dirs[0]]
    config.watcher.watch_dirs = duplicated
    assert len(default_scope(config, platform)) == 4
    assert default_scope(config, platform, include_usb=False) == config.watcher.watch_dirs[:3]


def test_scope_allows_wsl_rules(platform) -> None:
    assert scope_allows(Path("/home/x"), platform) is True
    assert scope_allows(Path("/mnt/c/Users/x"), platform) is True  # not WSL: no restriction

    from myav.platforms import detect_platform

    wsl = detect_platform(home=Path("/home/x"), env={"MYAV_PLATFORM": "wsl"})
    assert scope_allows(Path("/mnt/c/Users/x"), wsl) is False
    assert scope_allows(Path("/mnt/wsl/docker"), wsl) is False
    assert scope_allows(Path("/mnt/d/usb"), wsl) is True


def test_build_engines_returns_all_three(config, paths, state, platform) -> None:
    engines = build_engines(config, paths, state, platform)
    assert engines.platform is platform
    assert engines.clamav.name == "clamav"
    assert engines.yara.name == "yara"
    assert engines.virustotal.configured is False


def test_outcome_as_dict(config, paths, state, engines, target: Path) -> None:
    outcome = scan_file(target, config, paths, state, engines)
    payload = outcome.as_dict()
    assert payload["path"].endswith("sample.bin")
    assert payload["level"] == "CLEAN"
    assert payload["verdict"]["exit_code"] == 0


def test_error_engine_result_is_unknown(config, paths, state, target: Path, platform) -> None:
    engines = make_engines(platform, yara=StubYara(status=ERROR))
    outcome = scan_file(target, config, paths, state, engines)
    assert outcome.level == LEVEL_UNKNOWN


def test_vanished_between_stat_and_hash(
    config, paths, state, target: Path, engines, monkeypatch
) -> None:
    original = pipeline_module.digests

    def gone(path):
        raise FileNotFoundError("gone")

    monkeypatch.setattr(pipeline_module, "digests", gone)
    outcome = scan_file(target, config, paths, state, engines)
    assert outcome.level == LEVEL_UNKNOWN
    assert "unreadable" in (outcome.error or "")
    assert original is not None


def test_quarantine_only_after_verdict(config, paths, state, target: Path, platform) -> None:
    engines = make_engines(
        platform,
        clam=StubClam(status=ERROR, detail="timeout"),
    )
    outcome = scan_file(target, config, paths, state, engines)
    assert outcome.level == LEVEL_UNKNOWN
    assert outcome.quarantined is None
    assert target.exists()


def test_engine_result_names_are_preserved(config, paths, state, target: Path, platform) -> None:
    engines = make_engines(platform, vt=StubVirusTotal(configured=False))
    outcome = scan_file(target, config, paths, state, engines)
    assert [result.engine for result in outcome.verdict.results] == ["clamav", "yara"]
