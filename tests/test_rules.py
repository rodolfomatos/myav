"""YARA pack fetching: provenance, safe extraction and per-file compile reporting."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from myav import rules
from myav.rules import RulesError


def make_archive(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, payload in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def test_status_empty(paths) -> None:
    assert rules.status(paths)["rule_files"] == 0
    assert rules.status(paths)["pinned"] is False


def test_status_reads_provenance(paths) -> None:
    paths.rules_dir.mkdir(parents=True, exist_ok=True)
    (paths.rules_dir / "a.yar").write_text("rule a { condition: true }")
    (paths.rules_dir / "PROVENANCE.json").write_text(json.dumps({"commit": "abc"}))
    result = rules.status(paths)
    assert result["rule_files"] == 1
    assert result["pinned"] is True
    assert result["commit"] == "abc"


def test_status_bad_json_is_reported(paths) -> None:
    paths.rules_dir.mkdir(parents=True, exist_ok=True)
    (paths.rules_dir / "PROVENANCE.json").write_text("{not json")
    assert "error" in rules.status(paths)


def test_resolve_commit() -> None:
    payload = b'[{"sha": "deadbeef"}]'
    assert rules.resolve_commit(lambda url, timeout: payload) == "deadbeef"


def test_resolve_commit_failure() -> None:
    with pytest.raises(RulesError):
        rules.resolve_commit(lambda url, timeout: b"{}")


def test_safe_extract_skips_non_rules_and_traversal(tmp_path: Path) -> None:
    archive = make_archive(
        {
            "pack-1/rules/good.yar": b"rule good { condition: true }",
            "pack-1/rules/also.yara": b"rule also { condition: true }",
            "pack-1/README.md": b"ignore me",
            "pack-1/rules/../../evil.yar": b"rule evil { condition: true }",
        }
    )
    count = rules._safe_extract(archive, tmp_path)
    assert count == 2
    assert (tmp_path / "rules" / "good.yar").exists()
    assert (tmp_path / "rules" / "also.yara").exists()
    assert not (tmp_path.parent / "evil.yar").exists()


def test_compile_pack_without_yarac(tmp_path: Path) -> None:
    result = rules.compile_pack(tmp_path, tmp_path / "cache.yarc", yarac="")
    assert result["compiled"] is False
    assert result["reason"] == "yarac not installed"


def test_compile_pack_no_rules(tmp_path: Path) -> None:
    result = rules.compile_pack(tmp_path, tmp_path / "cache.yarc", yarac="/bin/true")
    assert result["compiled"] is False
    assert result["reason"] == "no rule files"


def test_compile_pack_reports_skips(tmp_path: Path, monkeypatch) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "good.yar").write_text("rule good { condition: true }")
    (rules_dir / "bad.yar").write_text("this is not yara")

    calls: list[list[str]] = []

    class Completed:
        def __init__(self, returncode: int, stderr: str = "") -> None:
            self.returncode = returncode
            self.stderr = stderr
            self.stdout = ""

    def fake_run(argv, capture_output, text, timeout):
        calls.append(argv)
        if "bad.yar" in argv[0] or (len(argv) > 1 and "bad.yar" in " ".join(argv)):
            return Completed(1, "syntax error")
        return Completed(0)

    monkeypatch.setattr(rules.subprocess, "run", fake_run)
    result = rules.compile_pack(rules_dir, tmp_path / "cache.yarc", yarac="/usr/bin/yarac")
    assert result["compiled"] is True
    assert result["rules"] == 1
    assert result["skipped"][0]["file"] == "bad.yar"
    assert calls


def test_compile_pack_all_bad(tmp_path: Path, monkeypatch) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "bad.yar").write_text("nope")

    class Completed:
        returncode = 1
        stderr = "syntax error"
        stdout = ""

    monkeypatch.setattr(rules.subprocess, "run", lambda *a, **k: Completed())
    result = rules.compile_pack(rules_dir, tmp_path / "cache.yarc", yarac="/usr/bin/yarac")
    assert result["compiled"] is False
    assert result["reason"] == "no rule file compiled"


def test_compile_final_link_failure(tmp_path: Path, monkeypatch) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "good.yar").write_text("rule good { condition: true }")

    class Completed:
        def __init__(self, returncode: int) -> None:
            self.returncode = returncode
            self.stderr = "link failed"
            self.stdout = ""

    calls = {"n": 0}

    def fake_run(argv, capture_output, text, timeout):
        calls["n"] += 1
        return Completed(0 if calls["n"] == 1 else 1)

    monkeypatch.setattr(rules.subprocess, "run", fake_run)
    result = rules.compile_pack(rules_dir, tmp_path / "cache.yarc", yarac="/usr/bin/yarac")
    assert result["compiled"] is False
    assert "link failed" in result["reason"]


def test_fetch_requires_license(paths) -> None:
    with pytest.raises(RulesError):
        rules.fetch(paths, accept_license=False)


def test_fetch_writes_provenance(paths, monkeypatch) -> None:
    archive = make_archive({"pack-1/rules/good.yar": b"rule good { condition: true }"})

    def fake_fetch(url: str, timeout: int) -> bytes:
        if "api.github.com" in url:
            return b'[{"sha": "abc123"}]'
        return archive

    monkeypatch.setattr(
        rules, "compile_pack", lambda *a, **k: {"compiled": False, "reason": "no yarac"}
    )
    result = rules.fetch(paths, accept_license=True, fetch=fake_fetch)
    assert result["changed"] is True
    assert result["commit"] == "abc123"
    assert result["rule_files"] == 1
    assert (paths.rules_dir / "PROVENANCE.json").exists()

    again = rules.fetch(paths, accept_license=True, fetch=fake_fetch)
    assert again["changed"] is False

    updated = rules.fetch(paths, accept_license=True, update=True, fetch=fake_fetch)
    assert updated["changed"] is True


def test_fetch_clears_stale_directories(paths, monkeypatch) -> None:
    paths.rules_dir.mkdir(parents=True, exist_ok=True)
    (paths.rules_dir / "old").mkdir()
    (paths.rules_dir / "old" / "stale.yar").write_text("rule stale { condition: true }")
    archive = make_archive({"pack-1/rules/new.yar": b"rule new { condition: true }"})

    monkeypatch.setattr(rules, "compile_pack", lambda *a, **k: {"compiled": False})
    rules.fetch(
        paths,
        accept_license=True,
        update=True,
        fetch=lambda url, timeout: b'[{"sha": "abc"}]' if "api" in url else archive,
    )
    assert not (paths.rules_dir / "old").exists()
    assert (paths.rules_dir / "rules" / "new.yar").exists()
