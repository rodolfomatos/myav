"""CLI behaviour and the exit-code contract.

Every command is exercised through its function with a fake context rooted in a temp home,
so no test touches the real ``~/.config/myav``, the real quarantine or the real database.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest
from conftest import StubClam, make_engines

from myav import cli
from myav.config import ConfigError
from myav.engine import MALICIOUS
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
