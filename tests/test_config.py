from __future__ import annotations

from pathlib import Path

import pytest

from myav.config import (
    Config,
    ConfigError,
    unknown_sections,
    write_api_key,
)
from myav.paths import default_paths


def _write_config(paths, text: str, mode: int = 0o600) -> Path:
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    target = paths.config_file
    target.write_text(text, encoding="utf-8")
    target.chmod(mode)
    return target


def test_defaults(paths) -> None:
    config = Config(paths=paths)
    assert config.virustotal.enabled is False
    assert config.clamav.tcp_port == 3310
    assert config.yara.malicious_severity == 7
    assert config.report.retention == 90


def test_load_missing_file_returns_defaults(paths) -> None:
    config = Config.load(home=paths.home)
    assert config.paths.config_dir == paths.config_dir
    assert [p.name for p in config.watcher.watch_dirs] == ["Downloads", "Desktop", "Documents"]


def test_load_rejects_world_readable_config(paths) -> None:
    _write_config(paths, "[scan]\nskip_hidden = true\n", mode=0o644)
    with pytest.raises(ConfigError, match="0600"):
        Config.load(home=paths.home)


def test_windows_skips_posix_mode_enforcement(paths, monkeypatch) -> None:
    """On Windows, POSIX mode bits cannot express 0600; ACLs protect the file instead."""
    import myav.config as config_module

    _write_config(paths, "[scan]\nskip_hidden = true\n", mode=0o644)
    monkeypatch.setattr(config_module, "ENFORCE_POSIX_MODES", False)
    config = Config.load(home=paths.home)
    assert config.scan.skip_hidden is True


def test_write_api_key_windows_skips_posix_check(paths, monkeypatch) -> None:
    import myav.config as config_module

    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("[virustotal]\n", encoding="utf-8")
    paths.config_file.chmod(0o644)
    monkeypatch.setattr(config_module, "ENFORCE_POSIX_MODES", False)
    target = write_api_key(paths, "f" * 64)
    assert "f" * 64 in target.read_text(encoding="utf-8")


def test_load_applies_overrides(paths) -> None:
    _write_config(
        paths,
        """
[clamav]
tcp_port = 3311
timeout = 5

[yara]
malicious_severity = 8

[virustotal]
enabled = true

[watcher]
settle_seconds = 0.5
watch_dirs = ["~/Downloads"]

[scan]
skip_hidden = true

[report]
retention = 7
""",
    )
    config = Config.load(home=paths.home)
    assert config.clamav.tcp_port == 3311
    assert config.clamav.timeout == 5
    assert config.yara.malicious_severity == 8
    # No key -> the engine cannot be enabled, whatever the file says.
    assert config.virustotal.enabled is False
    assert config.watcher.settle_seconds == 0.5
    assert config.watcher.watch_dirs == [paths.home / "Downloads"]
    assert config.scan.skip_hidden is True
    assert config.report.retention == 7


def test_load_vt_key_and_enabled_flag(paths) -> None:
    key = "a" * 64
    _write_config(
        paths,
        f'[virustotal]\nenabled = true\napi_key = "{key}"\n',
    )
    config = Config.load(home=paths.home)
    assert config.virustotal.enabled is True
    assert config.virustotal.api_key == key


def test_load_vt_key_with_enabled_false_stays_off(paths) -> None:
    _write_config(paths, f'[virustotal]\nenabled = false\napi_key = "{"b" * 64}"\n')
    config = Config.load(home=paths.home)
    assert config.virustotal.enabled is False


def test_load_invalid_toml(paths) -> None:
    _write_config(paths, "this is not toml [[[")
    with pytest.raises(ConfigError, match="invalid TOML"):
        Config.load(home=paths.home)


def test_unknown_sections_are_warned(paths) -> None:
    _write_config(paths, "[mystery]\nx = 1\n")
    config = Config.load(home=paths.home)
    assert any("mystery" in warning for warning in config.warnings)
    assert unknown_sections({"a": {}, "b": {}}) == [
        "unknown config section [a] ignored",
        "unknown config section [b] ignored",
    ]


def test_section_must_be_a_table(paths) -> None:
    with pytest.raises(ConfigError, match="must be a table"):
        Config(paths=paths).with_overrides({"clamav": "not-a-table"})


def test_validation_errors(paths) -> None:
    config = Config(paths=paths)
    config.yara.suspicious_severity = 9
    config.yara.malicious_severity = 5
    with pytest.raises(ConfigError, match="suspicious_severity"):
        config.validate()

    config = Config(paths=paths)
    config.watcher.settle_seconds = -1
    with pytest.raises(ConfigError, match="settle_seconds"):
        config.validate()

    config = Config(paths=paths)
    config.watcher.workers = 0
    with pytest.raises(ConfigError, match="workers"):
        config.validate()

    config = Config(paths=paths)
    config.report.retention = 0
    with pytest.raises(ConfigError, match="retention"):
        config.validate()

    config = Config(paths=paths)
    config.watcher.watch_dirs = [Path("relative/dir")]
    with pytest.raises(ConfigError, match="absolute"):
        config.validate()


def test_public_dict_redacts_key(paths) -> None:
    config = Config(paths=paths)
    config.virustotal.api_key = "a" * 64
    payload = config.public_dict()
    assert payload["virustotal"]["api_key"] != "a" * 64
    assert "…" in payload["virustotal"]["api_key"]
    assert payload["virustotal"]["configured"] is True
    assert config.public_dict(redact=False)["virustotal"]["api_key"] == "a" * 64
    config.virustotal.api_key = "short"
    assert config.public_dict()["virustotal"]["api_key"] == "***"


def test_write_api_key_new_file(paths) -> None:
    key = "c" * 64
    target = write_api_key(paths, key)
    assert target == paths.config_file
    assert target.stat().st_mode & 0o777 == 0o600
    assert key in target.read_text(encoding="utf-8")
    assert "[virustotal]" in target.read_text(encoding="utf-8")


def test_write_api_key_replaces_existing(paths) -> None:
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(
        '[scan]\nskip_hidden = true\n\n[virustotal]\nenabled = false\napi_key = "old"\n',
        encoding="utf-8",
    )
    paths.config_file.chmod(0o600)
    new_key = "d" * 64
    target = write_api_key(paths, new_key)
    text = target.read_text(encoding="utf-8")
    assert new_key in text
    assert "enabled = true" in text
    assert "skip_hidden = true" in text
    assert "old" not in text


def test_write_api_key_refuses_loose_permissions(paths) -> None:
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text("[virustotal]\n", encoding="utf-8")
    paths.config_file.chmod(0o644)
    with pytest.raises(ConfigError, match="chmod 600"):
        write_api_key(paths, "e" * 64)


def test_default_paths_are_used_when_none_given() -> None:
    config = Config()
    assert config.paths.config_dir.name == "myav"
    assert default_paths().home == Path.home()
