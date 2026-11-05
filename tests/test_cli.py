"""CLI behaviour and the exit-code contract.

Every command is exercised through its function with a fake context rooted in a temp home,
so no test touches the real ``~/.config/myav``, the real quarantine or the real database.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

import pytest
from conftest import StubClam, make_engines

from myav import cli
from myav.config import ConfigError
from myav.engine import CLEAN, MALICIOUS, EngineResult
from myav.paths import ensure_dirs
from myav.pipeline import Outcome
from myav.quarantine import Quarantine, QuarantineError
from myav.scheduler import Artifact
from myav.state import QuarantineRecord
from myav.verdict import Verdict
from myav.watcher import WatcherStats


class FakeContext:
    def __init__(self, config, paths, state, platform, engines) -> None:
        self.config = config
        self.paths = paths
        self.state = state
        self.platform = platform
        self._engines = engines

    def engines(self):
        return self._engines


@pytest.fixture
def fake(monkeypatch, config, paths, state, platform, engines):
    ensure_dirs(paths)
    context = FakeContext(config, paths, state, platform, engines)
    monkeypatch.setattr(cli, "make_context", lambda create_dirs=True: context)
    return context


def args(**kwargs) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


# ------------------------------------------------------------------- basic commands


def test_version_text_and_json(capsys) -> None:
    assert cli.main(["version"]) == 0
    assert "myav" in capsys.readouterr().out

    assert cli.main(["version", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["name"] == "myav"
    assert payload["version"]


def test_platforms_text_and_json(capsys) -> None:
    assert cli.main(["platforms"]) == 0
    assert "linux" in capsys.readouterr().out.lower()

    assert cli.main(["platforms", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["platforms"]) >= 4


def test_completion_bash(capsys) -> None:
    assert cli.main(["completion"]) == 0
    out = capsys.readouterr().out
    assert "_myav_completion" in out
    assert "complete -o default" in out
    assert "scan" in out
    assert "quarantine" in out


def test_completion_zsh(capsys) -> None:
    assert cli.main(["completion", "zsh"]) == 0
    out = capsys.readouterr().out
    assert "#compdef myav" in out


def test_completion_json(capsys) -> None:
    assert cli.main(["completion", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "completion"
    assert payload["shell"] == "bash"
    assert "_myav_completion" in payload["script"]


def test_doctor_reports_missing_clamav(fake, monkeypatch, capsys) -> None:
    clam = StubClam(available=False)
    clam.info = type("I", (), {"available": False, "detail": "not installed", "stale": False})()
    fake._engines = make_engines(fake.platform, clam=clam)
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    monkeypatch.setattr(cli, "rules_status", lambda paths: {"rule_files": 0, "cache_exists": False})
    monkeypatch.setattr(cli, "schedule_status", lambda *a, **k: {"installed": []})
    monkeypatch.setattr(cli, "_systemd_state", lambda: "offline")

    code = cli.main(["doctor"])
    out = capsys.readouterr().out
    assert code == 1
    assert "FAIL  ClamAV" in out

    assert cli.main(["doctor", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["failed"] >= 1


def test_doctor_healthy_path(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.setattr(cli, "rules_status", lambda paths: {"rule_files": 3, "cache_exists": True})
    monkeypatch.setattr(cli, "schedule_status", lambda *a, **k: {"installed": ["myav-watch"]})
    fake.config.virustotal.enabled = True
    fake.config.virustotal.api_key = "a" * 64
    fake.state.set_baseline_established_at("2026-11-03T16:00:00+00:00")

    code = cli.main(["doctor"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Everything myav depends on" in out


def test_config_path_and_show(fake, capsys) -> None:
    assert cli.main(["config", "path"]) == 0
    assert str(fake.paths.config_file) in capsys.readouterr().out

    fake.config.virustotal.api_key = "abcdef" + "0" * 58
    assert cli.main(["config", "show", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["virustotal"]["api_key"].endswith("00")
    assert (
        "abcdef" not in json.dumps(payload["virustotal"])[:200]
        or "…" in payload["virustotal"]["api_key"]
    )


def test_config_set_vt_key_valid_and_invalid(fake, capsys) -> None:
    good = "0123456789abcdef" * 4
    assert cli.main(["config", "set-vt-key", "--key", good]) == 0
    assert fake.paths.config_file.exists()
    assert (fake.paths.config_file.stat().st_mode & 0o777) == 0o600

    assert cli.main(["config", "set-vt-key", "--key", "nope"]) == 2
    assert "64 hexadecimal" in capsys.readouterr().err


# ----------------------------------------------------------------------------- scan


def test_scan_missing_path_is_usage(fake, capsys) -> None:
    assert cli.main(["scan", "/definitely/not/here"]) == 2
    assert "no such file" in capsys.readouterr().err


def test_scan_clean(fake, tmp_path, capsys) -> None:
    target = tmp_path / "clean.txt"
    target.write_text("hello")
    assert cli.main(["scan", str(target)]) == 0
    out = capsys.readouterr().out
    assert "CLEAN" in out
    assert target.exists()


def test_scan_clean_json(fake, tmp_path, capsys) -> None:
    target = tmp_path / "clean.txt"
    target.write_text("hello")
    assert cli.main(["scan", str(target), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "CLEAN"
    assert payload["files"] == 1


def test_scan_malicious_quarantines(fake, tmp_path, capsys) -> None:
    fake._engines = make_engines(fake.platform, clam=StubClam(MALICIOUS, "Test.Sig"))
    target = tmp_path / "bad.bin"
    target.write_text("malware")
    assert cli.main(["scan", str(target)]) == 10
    assert not target.exists()
    assert fake.state.list_quarantines()


def test_scan_dry_run_keeps_file(fake, tmp_path, capsys) -> None:
    fake._engines = make_engines(fake.platform, clam=StubClam(MALICIOUS, "Test.Sig"))
    target = tmp_path / "bad.bin"
    target.write_text("malware")
    assert cli.main(["scan", str(target), "--dry-run"]) == 10
    assert target.exists()
    assert "dry run" in capsys.readouterr().out


def test_scan_writes_report(fake, tmp_path, capsys) -> None:
    target = tmp_path / "clean.txt"
    target.write_text("hello")
    assert cli.main(["scan", str(target), "--report"]) == 0
    assert list(fake.paths.reports_dir.glob("*.md"))


def test_full_scan_writes_report(fake, tmp_path, capsys) -> None:
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    assert cli.main(["full-scan", str(folder)]) == 0
    out = capsys.readouterr().out
    assert "myav report" in out
    assert list(fake.paths.reports_dir.glob("*.md"))


def test_full_scan_default_scope(fake, tmp_path, monkeypatch, capsys) -> None:
    folder = tmp_path / "secret-scope"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    monkeypatch.setattr(cli, "default_scope", lambda config, platform: [folder])
    assert cli.main(["full-scan"]) == 0
    assert "secret-scope" in capsys.readouterr().out


def test_full_scan_nothing_to_scan(fake, tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "default_scope", lambda config, platform: [tmp_path / "gone"])
    assert cli.main(["full-scan"]) == 1
    assert "Nothing to scan" in capsys.readouterr().err


def test_full_scan_shows_progress_on_stderr(fake, tmp_path, capsys, monkeypatch) -> None:
    import myav.progress as progress_module

    monkeypatch.setattr(progress_module, "_is_tty", lambda stream: True)
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    (folder / "b.txt").write_text("b")
    assert cli.main(["full-scan", str(folder)]) == 0
    err = capsys.readouterr().err
    assert "█" in err or "░" in err
    assert "2/2" in err


def test_full_scan_suppresses_progress_with_json(fake, tmp_path, capsys) -> None:
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    assert cli.main(["full-scan", str(folder), "--json"]) == 0
    err = capsys.readouterr().err
    assert "[progress]" not in err


def test_full_scan_suppresses_progress_with_quiet(fake, tmp_path, capsys) -> None:
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    assert cli.main(["full-scan", str(folder), "--quiet"]) == 0
    err = capsys.readouterr().err
    assert "[progress]" not in err


# ------------------------------------------------------------------- baseline


def test_baseline_writes_report(fake, tmp_path, capsys) -> None:
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    assert cli.main(["baseline", str(folder)]) == 0
    out = capsys.readouterr().out
    assert "myav report — baseline" in out
    assert list(fake.paths.reports_dir.glob("*.md"))


def test_baseline_default_scope(fake, tmp_path, monkeypatch, capsys) -> None:
    folder = tmp_path / "secret-scope"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    monkeypatch.setattr(cli, "default_scope", lambda config, platform: [folder])
    assert cli.main(["baseline"]) == 0
    assert "secret-scope" in capsys.readouterr().out


def test_baseline_nothing_to_scan(fake, tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "default_scope", lambda config, platform: [tmp_path / "gone"])
    assert cli.main(["baseline"]) == 1
    assert "Nothing to baseline" in capsys.readouterr().err


def test_baseline_records_meta(fake, tmp_path) -> None:
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    assert cli.main(["baseline", str(folder)]) == 0
    ts = fake.state.get_baseline_established_at()
    assert ts is not None
    assert "T" in ts  # ISO format


def test_baseline_json(fake, tmp_path, capsys) -> None:
    folder = tmp_path / "docs"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    assert cli.main(["baseline", str(folder), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "baseline"
    assert "baseline_established_at" in payload


# ---------------------------------------------------------------------------- rules


def test_rules_status_text_and_json(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "rules_status",
        lambda paths: {
            "rules_dir": str(paths.rules_dir),
            "rule_files": 2,
            "cache_exists": True,
            "commit": "abc123",
            "archive_sha256": "deadbeef" * 8,
            "license": "DRL",
        },
    )
    assert cli.main(["rules", "status"]) == 0
    assert "pinned commit" in capsys.readouterr().out

    assert cli.main(["rules", "status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["commit"] == "abc123"


def test_rules_status_without_provenance(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "rules_status",
        lambda paths: {"rules_dir": "d", "rule_files": 0, "cache_exists": False},
    )
    assert cli.main(["rules", "status"]) == 0
    assert "provenance" in capsys.readouterr().out


def test_rules_fetch_changed_and_unchanged(fake, monkeypatch, capsys) -> None:
    result = {
        "changed": True,
        "rule_files": 4,
        "repo": "Neo23x0/signature-base",
        "commit": "abcdef123456",
        "archive_sha256": "f" * 64,
        "compile": {"compiled": True, "rules": 4},
        "skipped_rules": [{"file": "x.yar", "error": "syntax"}],
    }
    monkeypatch.setattr(cli, "fetch_rules", lambda *a, **k: result)
    assert cli.main(["rules", "fetch", "--accept-license"]) == 0
    out = capsys.readouterr().out
    assert "Fetched 4 rule files" in out
    assert "failed to compile" in out

    monkeypatch.setattr(cli, "fetch_rules", lambda *a, **k: {**result, "changed": False})
    assert cli.main(["rules", "fetch", "--accept-license"]) == 0
    assert "already pinned" in capsys.readouterr().out

    monkeypatch.setattr(
        cli,
        "fetch_rules",
        lambda *a, **k: {**result, "compile": {"compiled": False, "reason": "no yarac"}},
    )
    assert cli.main(["rules", "fetch", "--accept-license", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["changed"] is True


def test_rules_refresh_no_change(fake, monkeypatch, capsys, tmp_path) -> None:
    # Create a rules dir with some files and PROVENANCE
    rules_dir = fake.paths.rules_dir
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "rule1.yar").write_text("rule a { condition: true }")
    (rules_dir / "rule2.yar").write_text("rule b { condition: true }")
    prov = {
        "repo": "Neo23x0/signature-base",
        "commit": "oldcommit1234",
        "rule_files": 2,
    }
    (rules_dir / "PROVENANCE.json").write_text(
        json.dumps(prov, indent=2), encoding="utf-8"
    )

    monkeypatch.setattr(
        cli,
        "fetch_rules",
        lambda *a, **k: {
            "changed": False,
            "rule_files": 2,
            "repo": "Neo23x0/signature-base",
            "commit": "oldcommit1234",
        },
    )
    assert cli.main(["rules", "refresh"]) == 0
    out = capsys.readouterr().out
    assert "already up to date" in out


def test_rules_refresh_with_changes(fake, monkeypatch, capsys, tmp_path) -> None:
    rules_dir = fake.paths.rules_dir
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "old.yar").write_text("rule old { condition: true }")
    prov = {
        "repo": "Neo23x0/signature-base",
        "commit": "oldcommit1234",
        "rule_files": 1,
    }
    (rules_dir / "PROVENANCE.json").write_text(
        json.dumps(prov, indent=2), encoding="utf-8"
    )

    monkeypatch.setattr(
        cli,
        "fetch_rules",
        lambda *a, **k: {
            "changed": True,
            "rule_files": 2,
            "repo": "Neo23x0/signature-base",
            "commit": "newcommit5678",
            "compile": {"compiled": True, "rules": 2},
        },
    )
    # After fetch, the new rule file should exist
    def fake_fetch(*a, **k):
        (rules_dir / "new.yar").write_text("rule new { condition: true }")
        return {
            "changed": True,
            "rule_files": 2,
            "repo": "Neo23x0/signature-base",
            "commit": "newcommit5678",
            "compile": {"compiled": True, "rules": 2},
        }

    monkeypatch.setattr(cli, "fetch_rules", fake_fetch)
    assert cli.main(["rules", "refresh"]) == 0
    out = capsys.readouterr().out
    assert "YARA pack refreshed" in out
    assert "Added (1)" in out
    assert "+ new.yar" in out


def test_rules_refresh_json(fake, monkeypatch, capsys, tmp_path) -> None:
    rules_dir = fake.paths.rules_dir
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "old.yar").write_text("rule old { condition: true }")
    prov = {
        "repo": "Neo23x0/signature-base",
        "commit": "oldcommit1234",
        "rule_files": 1,
    }
    (rules_dir / "PROVENANCE.json").write_text(
        json.dumps(prov, indent=2), encoding="utf-8"
    )

    monkeypatch.setattr(
        cli,
        "fetch_rules",
        lambda *a, **k: {
            "changed": True,
            "rule_files": 1,
            "repo": "Neo23x0/signature-base",
            "commit": "newcommit5678",
            "compile": {"compiled": True, "rules": 1},
        },
    )
    assert cli.main(["rules", "refresh", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "rules-refresh"
    assert payload["changed"] is True
    assert payload["before_commit"] == "oldcommit1234"
    assert payload["after_commit"] == "newcommit5678"


# ------------------------------------------------------------------ allow --json


def test_allow_list_json(fake, capsys) -> None:
    assert cli.main(["allow", "list", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "allow-list"
    assert payload["records"] == []


def test_allow_add_json(fake, tmp_path, capsys) -> None:
    target = tmp_path / "trusted.bin"
    target.write_text("trusted")
    assert cli.main(["allow", "add", str(target), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "allow-add"
    assert payload["path"] == str(target.absolute())


def test_allow_remove_json(fake, tmp_path, capsys) -> None:
    target = tmp_path / "trusted.bin"
    target.write_text("trusted")
    cli.main(["allow", "add", str(target)])
    capsys.readouterr()  # discard add output
    assert cli.main(["allow", "remove", "--json"]) == 2  # no hash arg, no --path
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "allow-remove"
    assert payload["removed"] is False


def test_report_json(fake, capsys) -> None:
    assert cli.main(["report", "--json"]) == 1  # no reports yet
    # Create a report
    fake.paths.reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = fake.paths.reports_dir / "2026-01-01-0000-full.md"
    report_file.write_text("# test report")
    assert cli.main(["report", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "report"
    assert "# test report" in payload["content"]


# ------------------------------------------------------------------- research


def test_research_fp_baseline_clean(fake, tmp_path, capsys) -> None:
    corpus = tmp_path / "clean-corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello world")
    (corpus / "b.txt").write_text("clean file")

    assert cli.main(["research", "fp-baseline", str(corpus)]) == 0
    out = capsys.readouterr().out
    assert "Honest measurement" in out
    assert "True negative  (clean, not flagged):  2" in out
    assert "False positive rate:  0.00%" in out


def test_research_fp_baseline_with_eicar(fake, tmp_path, capsys, monkeypatch) -> None:
    corpus = tmp_path / "mixed-corpus"
    corpus.mkdir()
    (corpus / "clean.txt").write_text("hello world")
    eicar = corpus / "eicar.com"
    eicar.write_text(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )

    from myav.engine import MALICIOUS, EngineResult

    def eicar_scan(self, path: Path) -> EngineResult:
        if path.name.lower().startswith("eicar"):
            return EngineResult(
                engine="clamav", status=MALICIOUS, signature="Eicar-Test",
                primary=True,
            )
        return EngineResult(engine="clamav", status=CLEAN, primary=True)

    monkeypatch.setattr(fake._engines.clamav, "scan", eicar_scan.__get__(fake._engines.clamav))

    assert cli.main(["research", "fp-baseline", str(corpus)]) == 0
    out = capsys.readouterr().out
    assert "False positive rate:  50.00%" in out
    assert "False negative rate:  0.00%" in out
    assert "eicar.com" in out


def test_research_fp_baseline_with_malicious_dir(fake, tmp_path, capsys, monkeypatch) -> None:
    clean_dir = tmp_path / "clean-corpus"
    clean_dir.mkdir()
    (clean_dir / "a.txt").write_text("hello world")

    malicious_dir = tmp_path / "malicious-corpus"
    malicious_dir.mkdir()
    detected = malicious_dir / "eicar.com"
    detected.write_text(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    missed = malicious_dir / "stealth.bin"
    missed.write_text("this looks clean but is actually malware")

    from myav.engine import MALICIOUS, EngineResult

    def eicar_scan(self, path: Path) -> EngineResult:
        if path.name.lower().startswith("eicar"):
            return EngineResult(
                engine="clamav", status=MALICIOUS, signature="Eicar-Test",
                primary=True,
            )
        return EngineResult(engine="clamav", status=CLEAN, primary=True)

    monkeypatch.setattr(fake._engines.clamav, "scan", eicar_scan.__get__(fake._engines.clamav))

    assert cli.main([
        "research", "fp-baseline", str(clean_dir),
        "--malicious-dir", str(malicious_dir),
    ]) == 0
    out = capsys.readouterr().out
    assert "Malicious corpus:" in out
    assert "False negative rate:  50.00%" in out
    assert "False positive rate:  0.00%" in out
    assert "True positive  (malicious, flagged):  1" in out
    assert "False negative (malicious, missed):   1" in out


def test_research_fp_baseline_json(fake, tmp_path, capsys) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("clean")

    assert cli.main(["research", "fp-baseline", str(corpus), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "research-fp-baseline"
    assert payload["total_scanned"] == 1
    assert payload["false_positive"] == 0
    assert payload["false_positive_rate"] == 0.0
    assert payload["false_negative_rate"] == 0.0


def test_research_fp_baseline_json_with_malicious_dir(fake, tmp_path, capsys, monkeypatch) -> None:
    clean_dir = tmp_path / "clean-corpus"
    clean_dir.mkdir()
    (clean_dir / "a.txt").write_text("hello world")

    malicious_dir = tmp_path / "malicious-corpus"
    malicious_dir.mkdir()
    detected = malicious_dir / "eicar.com"
    detected.write_text(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )

    from myav.engine import MALICIOUS, EngineResult

    def eicar_scan(self, path: Path) -> EngineResult:
        if path.name.lower().startswith("eicar"):
            return EngineResult(
                engine="clamav", status=MALICIOUS, signature="Eicar-Test",
                primary=True,
            )
        return EngineResult(engine="clamav", status=CLEAN, primary=True)

    monkeypatch.setattr(fake._engines.clamav, "scan", eicar_scan.__get__(fake._engines.clamav))

    assert cli.main([
        "research", "fp-baseline", str(clean_dir),
        "--malicious-dir", str(malicious_dir),
        "--json",
    ]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "research-fp-baseline"
    assert payload["false_negative"] == 0
    assert payload["true_positive"] == 1
    assert payload["false_negative_rate"] == 0.0


def test_research_fp_baseline_not_a_directory(fake, capsys) -> None:
    assert cli.main(["research", "fp-baseline", "/nonexistent/path"]) == 2


def test_research_fp_baseline_malicious_dir_not_a_directory(fake, tmp_path, capsys) -> None:
    clean_dir = tmp_path / "clean-corpus"
    clean_dir.mkdir()
    (clean_dir / "a.txt").write_text("hello world")

    assert cli.main([
        "research", "fp-baseline", str(clean_dir),
        "--malicious-dir", "/nonexistent/malicious",
    ]) == 2


# ------------------------------------------------------------------- research behaviour-baseline


def test_research_behaviour_baseline_learn(fake, tmp_path, capsys) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello")
    (corpus / "b.py").write_text("print(1)")

    assert cli.main(["research", "behaviour-baseline", str(corpus), "--learn"]) == 0
    out = capsys.readouterr().out
    assert "Behaviour baseline learned" in out
    assert "Observations:  2" in out
    assert "process-txt" in out
    assert "process-py" in out


def test_research_behaviour_baseline_check_no_deviations(
    fake, tmp_path, capsys
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello")

    cli.main(["research", "behaviour-baseline", str(corpus), "--learn"])
    capsys.readouterr()  # discard learn output

    assert cli.main(["research", "behaviour-baseline", str(corpus), "--check"]) == 0
    out = capsys.readouterr().out
    assert "Behaviour baseline check" in out
    assert "Deviations:    0" in out
    assert "No deviations from baseline." in out


def test_research_behaviour_baseline_check_with_deviations(
    fake, tmp_path, capsys
) -> None:
    corpus1 = tmp_path / "corpus1"
    corpus1.mkdir()
    (corpus1 / "a.txt").write_text("hello")

    corpus2 = tmp_path / "corpus2"
    corpus2.mkdir()
    (corpus2 / "b.py").write_text("print(1)")
    (corpus2 / "c.sh").write_text("#!/bin/bash")

    cli.main(["research", "behaviour-baseline", str(corpus1), "--learn"])
    capsys.readouterr()  # discard learn output

    assert cli.main(["research", "behaviour-baseline", str(corpus2), "--check"]) == 0
    out = capsys.readouterr().out
    assert "Behaviour baseline check" in out
    assert "Deviations:    6" in out
    assert "new_process" in out
    assert "new_directory" in out
    assert "new_modified_file" in out


def test_research_behaviour_baseline_check_without_baseline(
    fake, tmp_path, capsys
) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello")

    assert cli.main(["research", "behaviour-baseline", str(corpus), "--check"]) == 0
    out = capsys.readouterr().out
    assert "Deviations:    0" in out


def test_research_behaviour_baseline_learn_json(fake, tmp_path, capsys) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello")

    assert cli.main(["research", "behaviour-baseline", str(corpus), "--learn", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "research-behaviour-baseline"
    assert payload["learn"] is True
    assert payload["check"] is False
    assert payload["baseline_learned"] is True
    assert payload["total_observations"] == 1
    assert payload["deviation_count"] == 0
    assert "process-txt" in payload["baseline"]["processes"]


def test_research_behaviour_baseline_check_json(fake, tmp_path, capsys) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello")

    cli.main(["research", "behaviour-baseline", str(corpus), "--learn"])
    capsys.readouterr()  # discard learn output

    assert cli.main(["research", "behaviour-baseline", str(corpus), "--check", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "research-behaviour-baseline"
    assert payload["learn"] is False
    assert payload["check"] is True
    assert payload["baseline_learned"] is False
    assert payload["total_observations"] == 1
    assert payload["deviation_count"] == 0
    assert payload["deviation_rate"] == 0.0


def test_research_behaviour_baseline_not_a_directory(fake, capsys) -> None:
    assert cli.main(["research", "behaviour-baseline", "/nonexistent/path", "--learn"]) == 2


def test_research_behaviour_baseline_no_action(fake, tmp_path, capsys) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello")

    assert cli.main(["research", "behaviour-baseline", str(corpus)]) == 2


def test_research_behaviour_baseline_both_actions(fake, tmp_path, capsys) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "a.txt").write_text("hello")

    assert cli.main([
        "research", "behaviour-baseline", str(corpus), "--learn", "--check",
    ]) == 2


# ------------------------------------------------------------------- research behaviour-detect


def test_research_behaviour_detect_clean_not_flagged(fake, tmp_path, capsys) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "clean.txt").write_text("hello world")

    assert cli.main(["research", "behaviour-detect", str(corpus)]) == 0
    out = capsys.readouterr().out
    assert "Behaviour detection" in out
    assert "Files scanned: 1" in out
    assert "No behavioural matches." in out


def test_research_behaviour_detect_canary(fake, tmp_path, capsys) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("canary content")

    assert cli.main(["research", "behaviour-detect", str(canary)]) == 0
    out = capsys.readouterr().out
    assert "ransomware-canary" in out
    assert "high" in out


def test_research_behaviour_detect_json(fake, tmp_path, capsys) -> None:
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    (corpus / "clean.txt").write_text("hello world")

    assert cli.main(["research", "behaviour-detect", str(corpus), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "research-behaviour-detect"
    assert payload["total_files_scanned"] == 1
    assert payload["match_count"] == 0


def test_research_behaviour_detect_not_a_path(fake, capsys) -> None:
    assert cli.main(["research", "behaviour-detect", "/nonexistent/path"]) == 2


# ------------------------------------------------------------------- research ml-baseline


def test_research_ml_baseline_no_samples(fake, tmp_path, capsys) -> None:
    assert cli.main(["research", "ml-baseline"]) == 0
    out = capsys.readouterr().out
    assert "no samples found" in out


def test_research_ml_baseline_with_samples(fake, tmp_path, capsys) -> None:
    train_dir = tmp_path / "train"
    test_dir = tmp_path / "test"
    train_dir.mkdir()
    test_dir.mkdir()

    for i in range(10):
        (train_dir / f"ben_{i}.bin").write_bytes(b"\x00" * 50 + b"hello world")
        (train_dir / f"mal_{i}.bin").write_bytes(b"MZ" + b"\xff" * 100)
        (test_dir / f"ben_{i}.bin").write_bytes(b"\x00" * 50 + b"hello world")
        (test_dir / f"mal_{i}.bin").write_bytes(b"MZ" + b"\xff" * 100)

    assert cli.main(
        ["research", "ml-baseline", "--train-dir", str(train_dir), "--test-dir", str(test_dir)]
    ) == 0
    out = capsys.readouterr().out
    assert "ML baseline" in out
    assert "False positive rate:" in out
    assert "False negative rate:" in out
    assert "Precision:" in out
    assert "Recall:" in out


def test_research_ml_baseline_json(fake, tmp_path, capsys) -> None:
    train_dir = tmp_path / "train"
    test_dir = tmp_path / "test"
    train_dir.mkdir()
    test_dir.mkdir()

    for i in range(10):
        (train_dir / f"ben_{i}.bin").write_bytes(b"\x00" * 50 + b"hello world")
        (train_dir / f"mal_{i}.bin").write_bytes(b"MZ" + b"\xff" * 100)
        (test_dir / f"ben_{i}.bin").write_bytes(b"\x00" * 50 + b"hello world")
        (test_dir / f"mal_{i}.bin").write_bytes(b"MZ" + b"\xff" * 100)

    assert cli.main(
        [
            "research",
            "ml-baseline",
            "--train-dir",
            str(train_dir),
            "--test-dir",
            str(test_dir),
            "--json",
        ]
    ) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "command" in payload or "error" in payload
    if "error" in payload:
        pytest.fail(f"ml-baseline returned error: {payload['error']}")
    assert payload["command"] == "research-ml-baseline"
    assert payload["split_method"] == "temporal"
    assert "confusion" in payload
    assert "false_positive_rate" in payload
    assert "false_negative_rate" in payload
    assert "precision" in payload
    assert "recall" in payload


def test_research_ml_baseline_train_dir_not_found(fake, capsys) -> None:
    assert cli.main(["research", "ml-baseline", "--train-dir", "/nonexistent/train"]) == 2


# ------------------------------------------------------------------- research sandbox


def test_research_sandbox_clean_file(fake, tmp_path, capsys) -> None:
    script = tmp_path / "hello.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    os.chmod(script, stat.S_IRUSR | stat.S_IXUSR)

    assert cli.main(["research", "sandbox", str(script)]) == 0
    out = capsys.readouterr().out
    assert "Sandbox:" in out
    assert "Files scanned:" not in out  # sandbox doesn't scan files, it executes


def test_research_sandbox_json(fake, tmp_path, capsys) -> None:
    script = tmp_path / "hello.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    os.chmod(script, stat.S_IRUSR | stat.S_IXUSR)

    assert cli.main(["research", "sandbox", str(script), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "research-sandbox"
    assert payload["target"] == str(script.resolve())
    assert "event_count" in payload
    assert "evasion_count" in payload


def test_research_sandbox_not_a_file(fake, capsys) -> None:
    assert cli.main(["research", "sandbox", "/nonexistent/path"]) == 2


# ------------------------------------------------------------------- research campaign-graph


def test_research_campaign_graph_default(fake, capsys) -> None:
    assert cli.main(["research", "campaign-graph"]) == 0
    out = capsys.readouterr().out
    assert "Campaign graph:" in out
    assert "nodes" in out
    assert "edges" in out
    assert "Clusters:" in out


def test_research_campaign_graph_json(fake, capsys) -> None:
    assert cli.main(["research", "campaign-graph", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "research-campaign-graph"
    assert "node_count" in payload
    assert "edge_count" in payload
    assert "cluster_count" in payload
    assert "nodes" in payload
    assert "edges" in payload
    assert "clusters" in payload


def test_research_campaign_graph_days(fake, capsys) -> None:
    assert cli.main(["research", "campaign-graph", "--days", "30"]) == 0
    out = capsys.readouterr().out
    assert "Window: 30 days" in out


# ----------------------------------------------------------------------- quarantine


def make_quarantine_record(fake, tmp_path) -> QuarantineRecord:
    source = tmp_path / "bad.bin"
    source.write_text("malware")
    quarantine = Quarantine(fake.paths, fake.state, fake.config)
    verdict = Verdict(level="MALICIOUS")
    return quarantine.quarantine(source, verdict, reason="test")


def test_quarantine_list_empty(fake, capsys) -> None:
    assert cli.main(["quarantine", "list"]) == 0
    assert "empty" in capsys.readouterr().out


def test_quarantine_list_and_restore(fake, tmp_path, capsys) -> None:
    record = make_quarantine_record(fake, tmp_path)
    assert cli.main(["quarantine", "list", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["records"][0]["id"] == record.id

    assert cli.main(["quarantine", "list"]) == 0
    assert record.id[:8] in capsys.readouterr().out

    assert cli.main(["quarantine", "restore", record.id]) == 0
    assert (tmp_path / "bad.bin").exists()
    assert "hash-verified" in capsys.readouterr().out


def test_quarantine_purge_requires_yes(fake, tmp_path, capsys) -> None:
    record = make_quarantine_record(fake, tmp_path)
    payload = fake.paths.quarantine_dir / record.payload

    # Without --yes it only describes what it *would* do; the file stays put.
    assert cli.main(["quarantine", "purge", record.id]) == 0
    assert payload.exists()
    assert "re-run with --yes" in capsys.readouterr().out

    assert cli.main(["quarantine", "purge", record.id, "--yes"]) == 0
    assert not payload.exists()
    assert "cannot be undone" in capsys.readouterr().out


# -------------------------------------------------------------------------- allowlist


def test_allow_list_and_add(fake, tmp_path, capsys) -> None:
    assert cli.main(["allow", "list"]) == 0
    assert "empty" in capsys.readouterr().out

    target = tmp_path / "trusted.bin"
    target.write_text("trusted")
    assert cli.main(["allow", "add", str(target), "--reason", "vendor"]) == 0
    assert "Allowlisted" in capsys.readouterr().out

    assert cli.main(["allow", "list"]) == 0
    assert "trusted.bin" in capsys.readouterr().out

    assert cli.main(["allow", "add", str(tmp_path / "missing")]) == 2


def test_allow_remove_by_hash(fake, tmp_path, capsys) -> None:
    target = tmp_path / "trusted.bin"
    target.write_text("trusted")
    from myav.hashutil import sha256_file

    digest = sha256_file(target)
    assert cli.main(["allow", "add", str(target), "--reason", "vendor"]) == 0
    assert cli.main(["allow", "remove", digest]) == 0
    out = capsys.readouterr().out
    assert "Removed" in out
    assert cli.main(["allow", "list"]) == 0
    assert "trusted.bin" not in capsys.readouterr().out


def test_allow_remove_by_path(fake, tmp_path, capsys) -> None:
    target = tmp_path / "trusted.bin"
    target.write_text("trusted")
    assert cli.main(["allow", "add", str(target), "--reason", "vendor"]) == 0
    assert cli.main(["allow", "remove", "--path", str(target)]) == 0
    out = capsys.readouterr().out
    assert "Removed" in out
    assert cli.main(["allow", "list"]) == 0
    assert "trusted.bin" not in capsys.readouterr().out


def test_allow_remove_missing_hash(fake, capsys) -> None:
    assert cli.main(["allow", "remove", "a" * 64]) == 2
    assert "was not allowlisted" in capsys.readouterr().err


def test_allow_remove_nonexistent_path(fake, tmp_path, capsys) -> None:
    assert cli.main(["allow", "remove", "--path", str(tmp_path / "missing")]) == 2


# ------------------------------------------------------------------- notify


def test_notify_rejects_linux(fake, capsys) -> None:
    assert cli.main(["notify", "title", "message"]) == 3
    assert "not available" in capsys.readouterr().err


def test_notify_json_rejects_linux(fake, capsys) -> None:
    assert cli.main(["notify", "title", "message", "--json"]) == 3
    err = capsys.readouterr().err
    assert "not available" in err


def test_notify_windows(tmp_path, monkeypatch, capsys) -> None:
    from myav.config import Config
    from myav.paths import default_paths
    from myav.platforms import Capability, detect_platform
    from myav.state import State
    from tests.conftest import make_engines

    home = tmp_path / "home"
    for name in ("Downloads", "Desktop", "Documents"):
        (home / name).mkdir(parents=True)

    platform = detect_platform(home=home, env={"MYAV_PLATFORM": "windows"})
    assert platform.supports(Capability.TOAST)
    paths = default_paths(home=home, platform=platform)
    config = Config(paths=paths)
    config.watcher.watch_dirs = [home / "Downloads", home / "Desktop", home / "Documents"]
    state = State(paths.state_db)
    engines = make_engines(platform)

    class WinCtx:
        def __init__(self, config, paths, state, platform, engines):
            self.config = config
            self.paths = paths
            self.state = state
            self.platform = platform
            self._engines = engines

        def engines(self):
            return self._engines

    ctx = WinCtx(config, paths, state, platform, engines)
    monkeypatch.setattr(cli, "make_context", lambda create_dirs=True: ctx)

    assert cli.main(["notify", "myav", "threat found"]) == 0
    out = capsys.readouterr().out
    assert "[toast]" in out
    assert "threat found" in out


def test_notify_windows_json(tmp_path, monkeypatch, capsys) -> None:
    from myav.config import Config
    from myav.paths import default_paths
    from myav.platforms import detect_platform
    from myav.state import State
    from tests.conftest import make_engines

    home = tmp_path / "home"
    for name in ("Downloads", "Desktop", "Documents"):
        (home / name).mkdir(parents=True)

    platform = detect_platform(home=home, env={"MYAV_PLATFORM": "windows"})
    paths = default_paths(home=home, platform=platform)
    config = Config(paths=paths)
    state = State(paths.state_db)
    engines = make_engines(platform)

    class WinCtx:
        def __init__(self, config, paths, state, platform, engines):
            self.config = config
            self.paths = paths
            self.state = state
            self.platform = platform
            self._engines = engines

        def engines(self):
            return self._engines

    ctx = WinCtx(config, paths, state, platform, engines)
    monkeypatch.setattr(cli, "make_context", lambda create_dirs=True: ctx)

    assert cli.main(["notify", "myav", "threat found", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "notify"
    assert payload["title"] == "myav"
    assert payload["message"] == "threat found"
    assert payload["platform"] == "windows"


# ------------------------------------------------------------------ quarantine


def test_quarantine_budget_show(fake, capsys) -> None:
    assert cli.main(["quarantine", "budget"]) == 0
    out = capsys.readouterr().out
    assert "No budget set" in out


def test_quarantine_budget_set_and_show(fake, tmp_path, capsys) -> None:
    assert cli.main(["quarantine", "budget", "--set", "1048576"]) == 0
    out = capsys.readouterr().out
    assert "1.0 MiB" in out

    assert cli.main(["quarantine", "budget"]) == 0
    out = capsys.readouterr().out
    assert "1.0 MiB" in out


def test_quarantine_budget_json(fake, capsys) -> None:
    assert cli.main(["quarantine", "budget", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "quarantine-budget"
    assert payload["budget_bytes"] is None


def test_quarantine_rotate_under_budget(fake, capsys) -> None:
    assert cli.main(["quarantine", "budget", "--set", "100"]) == 0
    assert cli.main(["quarantine", "rotate"]) == 0
    out = capsys.readouterr().out
    assert "within budget" in out


# ---------------------------------------------------------------------------- report


def test_report_list_and_print(fake, tmp_path, capsys) -> None:
    assert cli.main(["report", "--list"]) == 0
    assert "No reports yet" in capsys.readouterr().out
    assert cli.main(["report"]) == 1

    report = fake.paths.reports_dir / "2026-01-01-0000-full.md"
    report.write_text("# hello report")
    assert cli.main(["report", "--list"]) == 0
    assert "2026-01-01" in capsys.readouterr().out

    assert cli.main(["report"]) == 0
    assert "# hello report" in capsys.readouterr().out

    assert cli.main(["report", "--path", str(report)]) == 0
    assert cli.main(["report", "--path", str(tmp_path / "nope.md")]) == 2


# ------------------------------------------------------------------------------ boot


def test_boot_first_run(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli.bootwatch,
        "check",
        lambda state, platform: {
            "entries": 2,
            "new": [],
            "removed": [],
            "first_run": True,
            "notes": [],
        },
    )
    assert cli.main(["boot"]) == 0
    out = capsys.readouterr().out
    assert "First run" in out
    assert "never disables" in out


def test_boot_new_entry_alerts(fake, monkeypatch, capsys) -> None:
    entry = {"name": "Evil", "location": "Startup", "command": "evil.exe"}
    monkeypatch.setattr(
        cli.bootwatch,
        "check",
        lambda state, platform: {
            "entries": 3,
            "new": [entry],
            "removed": [entry],
            "first_run": False,
            "notes": ["PowerShell not reachable"],
        },
    )
    assert cli.main(["boot"]) == 11
    out = capsys.readouterr().out
    assert "NEW since the last check" in out
    assert "Evil" in out

    assert cli.main(["boot", "--json"]) == 11
    assert json.loads(capsys.readouterr().out)["new"][0]["name"] == "Evil"


# ----------------------------------------------------------------------------- watch


class FakeWatcher:
    def __init__(self, *args, **kwargs) -> None:
        self.stats = WatcherStats(
            roots=[Path("/home/u/Downloads")],
            scanned=1,
            queued=1,
            errors=0,
            dropped=0,
            outcomes=[
                Outcome(
                    path=Path("/home/u/Downloads/a.txt"),
                    verdict=Verdict(level="CLEAN"),
                    sha256="a" * 64,
                    size=1,
                )
            ],
        )

    def run(self, once=False, create_dirs=False):
        return self.stats


def test_watch_text_and_json(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "Watcher", FakeWatcher)
    assert cli.main(["watch", "--once"]) == 0
    out = capsys.readouterr().out
    assert "Watched:" in out
    assert "Scanned 1 file" in out

    assert cli.main(["watch", "--once", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["command"] == "watch"
    assert payload["scanned"] == 1


# -------------------------------------------------------------------------- selftest


def test_selftest_json_and_text(fake, monkeypatch, capsys) -> None:
    from myav.selftest import Assertion, SelfTestResult

    result = SelfTestResult(assertions=[Assertion("ok", True)])
    monkeypatch.setattr(cli, "run_eicar_selftest", lambda *a, **k: result)
    assert cli.main(["selftest"]) == 0
    assert "RESULT: PASS" in capsys.readouterr().out

    assert cli.main(["selftest", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

    inconclusive = SelfTestResult(inconclusive="no clamav")
    monkeypatch.setattr(cli, "run_eicar_selftest", lambda *a, **k: inconclusive)
    assert cli.main(["selftest"]) == 5
    assert "not a myav bug" in capsys.readouterr().out


# -------------------------------------------------------------------- system commands


def test_update_signatures_without_freshclam(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    assert cli.main(["update-signatures"]) == 3
    assert "freshclam is not installed" in capsys.readouterr().err


def test_update_signatures_success(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/freshclam")

    class Completed:
        returncode = 0
        stdout = "Database updated"
        stderr = ""

    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: Completed())
    monkeypatch.setattr(cli, "_systemd_state", lambda: "offline")
    assert cli.main(["update-signatures"]) == 0
    assert "Signature update finished" in capsys.readouterr().out
    assert cli.main(["update-signatures", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["command"] == "update-signatures"


def test_update_signatures_permission_denied(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/bin/freshclam")

    class Completed:
        returncode = 1
        stdout = ""
        stderr = "ERROR: Permission denied"

    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: Completed())
    monkeypatch.setattr(cli, "_systemd_state", lambda: "offline")
    assert cli.main(["update-signatures"]) == 1
    assert "never runs sudo" in capsys.readouterr().err


def test_clamd_already_running(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_daemon_reachable", lambda ctx: True)
    assert cli.main(["clamd-start"]) == 0
    assert "already answering" in capsys.readouterr().out


def test_clamd_missing(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_daemon_reachable", lambda ctx: False)
    monkeypatch.setattr(cli, "_systemd_state", lambda: "offline")
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    monkeypatch.setattr(cli.Path, "exists", lambda self: False)
    assert cli.main(["clamd-start"]) == 3
    assert "not installed" in capsys.readouterr().err


def test_clamd_device_running(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "_daemon_reachable", lambda ctx: True)
    assert cli.main(["clamd-start"]) == 0


# ------------------------------------------------------------------------- schedules


def test_schedules_print(fake, monkeypatch, capsys) -> None:
    artefact = Artifact("watch service", Path("/tmp/x.service"), "content", activate="enable me")
    monkeypatch.setattr(cli, "render_schedules", lambda *a, **k: [artefact])
    assert cli.main(["schedules", "print"]) == 0
    out = capsys.readouterr().out
    assert "watch service" in out
    assert "activate: enable me" in out


def test_schedules_print_without_adapter(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "render_schedules", lambda *a, **k: [])
    assert cli.main(["schedules", "print"]) == 3
    assert "no scheduler adapter" in capsys.readouterr().out


def test_schedules_install_dry_run_and_yes(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(cli, "render_schedules", lambda *a, **k: [])
    monkeypatch.setattr(cli, "install_artifacts", lambda artefacts, yes=False: ["WOULD WRITE: x"])
    assert cli.main(["schedules", "install"]) == 0
    assert "Nothing was written" in capsys.readouterr().out
    assert cli.main(["schedules", "install", "--yes"]) == 0
    assert "WOULD WRITE: x" in capsys.readouterr().out


def test_schedules_status(fake, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli,
        "schedule_status",
        lambda *a, **k: {"scheduler": "systemd-user", "installed": ["myav-watch"], "note": "n"},
    )
    assert cli.main(["schedules", "status"]) == 0
    out = capsys.readouterr().out
    assert "myav-watch" in out
    assert "note: n" in out

    assert cli.main(["schedules", "status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["installed"] == ["myav-watch"]


# ----------------------------------------------------------------------------- inner


def test_inner_writes_log_and_dispatches(fake, monkeypatch) -> None:
    seen = {}
    monkeypatch.setattr(cli, "main", lambda argv: seen.setdefault("argv", argv) and 0)
    cli.cmd_inner(args(inner_command="watch-loop", rest=["--once"]))
    assert seen["argv"] == ["watch", "--once"]
    logs = list(fake.paths.logs_dir.glob("inner-watch.log"))
    assert logs


# --------------------------------------------------------------------- exit contract


def test_require_rejects_unsupported_capability(fake) -> None:
    from myav.platforms import detect_platform

    fake.platform = detect_platform(env={"MYAV_PLATFORM": "ios"})
    with pytest.raises(cli.CapabilityError):
        cli.require(fake, cli.Capability.WATCH_FILES, "watch")


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (ConfigError("bad"), 4),
        (cli.RulesError("bad"), 1),
        (QuarantineError("bad", code=2), 2),
        (cli.UnsafeLocationError("bad"), 4),
        (cli.CapabilityError("bad"), 3),
        (KeyboardInterrupt(), 130),
    ],
)
def test_main_translates_exceptions(monkeypatch, capsys, exception, expected) -> None:
    def boom(argv):
        raise exception

    monkeypatch.setattr(cli, "cmd_version", boom)
    assert cli.main(["version"]) == expected


def test_main_unknown_command_is_usage() -> None:
    with pytest.raises(SystemExit) as caught:
        cli.main(["not-a-command"])
    assert caught.value.code == 2


def test_outcome_line_variants(tmp_path) -> None:
    skipped = Outcome(path=tmp_path / "a")
    skipped.skipped = "symlink"
    assert "SKIP" in cli._outcome_line(skipped)

    errored = Outcome(path=tmp_path / "b")
    errored.error = "unreadable"
    assert "unreadable" in cli._outcome_line(errored)

    record = QuarantineRecord(
        id="abcdefgh",
        original_path=str(tmp_path / "c"),
        sha256="a" * 64,
        size=1,
        mode=0o644,
        mtime=0.0,
        tag="malicious",
        reason="x",
        payload="p.bin",
    )
    quarantined = Outcome(
        path=tmp_path / "c", verdict=Verdict(level="MALICIOUS"), quarantined=record
    )
    assert "quarantined abcdefgh" in cli._outcome_line(quarantined)
