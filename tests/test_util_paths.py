from __future__ import annotations

import os
from pathlib import Path

import pytest

from myav import util
from myav.hashutil import digests, sha256_file
from myav.paths import (
    Paths,
    UnsafeLocationError,
    assert_writable_location,
    classify_mount,
    default_paths,
    discover_removable_mounts,
    ensure_dirs,
    is_windows_path,
    is_within,
    read_mounts,
)


def test_format_bytes() -> None:
    assert util.format_bytes(0) == "0 B"
    assert util.format_bytes(512) == "512 B"
    assert util.format_bytes(1536) == "1.5 KiB"
    assert util.format_bytes(5 * 1024**2) == "5.0 MiB"


def test_short_hash_and_redaction() -> None:
    assert util.short_hash("abcdef0123456789") == "abcdef012345"
    key = "a" * 64
    assert util.redact(f"key={key}") == "key=***REDACTED***"
    assert util.redact("key=secretvalue", ["secretvalue"]) == "key=***REDACTED***"
    assert util.redact("") == ""
    assert util.redact("short", ["key"]) == "short"
    mapping = {"api_key": "abc", "nested": {"token": "xyz"}, "keep": 1}
    redacted = util.redact_mapping_keys(mapping)
    assert redacted["api_key"] == "***REDACTED***"
    assert redacted["nested"]["token"] == "***REDACTED***"
    assert redacted["keep"] == 1


def test_human_age() -> None:
    assert util.human_age(-5) == "0s"
    assert util.human_age(30) == "30s"
    assert util.human_age(120) == "2m"
    assert util.human_age(7200) == "2.0h"
    assert util.human_age(3 * 86400) == "3.0d"


def test_display_path_uses_home(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert util.display_path(tmp_path / "Downloads" / "a.txt") == "~/Downloads/a.txt"
    assert util.display_path(Path("/etc/hosts")) == "/etc/hosts"


def test_now_helpers_are_iso_and_int() -> None:
    assert "T" in util.now_iso()
    assert isinstance(util.now_ts(), int)


def test_digests_and_sha256(tmp_path: Path) -> None:
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello myav")
    result = digests(target)
    assert result["sha256"] == sha256_file(target)
    assert len(result["md5"]) == 32


def test_is_within_and_windows_path(tmp_path: Path) -> None:
    root = tmp_path / "root"
    child = root / "a" / "b"
    child.mkdir(parents=True)
    assert is_within(child, root)
    assert is_within(root, root)
    assert not is_within(tmp_path, root)
    assert is_windows_path("/mnt/c/Users/x")
    assert not is_windows_path("/mnt/d/Users/x")


def test_assert_writable_location_refuses_windows_mount() -> None:
    with pytest.raises(UnsafeLocationError):
        assert_writable_location(Path("/mnt/c/tmp/x"))
    assert assert_writable_location(Path("/tmp/x")) == Path("/tmp/x")


def test_ensure_dirs_is_owner_only(tmp_path: Path, platform) -> None:
    paths = default_paths(home=tmp_path, platform=platform)
    ensure_dirs(paths)
    for directory in paths.all_dirs():
        assert directory.is_dir()
        assert directory.stat().st_mode & 0o777 == 0o700


def test_paths_properties(tmp_path: Path, platform) -> None:
    paths = default_paths(home=tmp_path, platform=platform)
    assert isinstance(paths, Paths)
    assert paths.config_file.parent == paths.config_dir
    assert paths.quarantine_dir.parent == paths.data_dir
    assert paths.reports_dir.parent == paths.state_dir
    assert paths.logs_dir.parent == paths.state_dir
    assert paths.state_db.parent == paths.state_dir
    assert paths.rules_dir.parent == paths.data_dir
    assert paths.yara_cache.parent == paths.cache_dir


def test_read_mounts_parses_escaped_spaces(tmp_path: Path) -> None:
    mounts = tmp_path / "mounts"
    mounts.write_text(
        "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /media/My\\040Disk vfat rw 0 0\nmalformed\n",
        encoding="utf-8",
    )
    parsed = read_mounts(mounts)
    assert ("/dev/sda1", "/", "ext4") in parsed
    assert ("/dev/sdb1", "/media/My Disk", "vfat") in parsed


def test_read_mounts_missing_file_is_empty(tmp_path: Path) -> None:
    assert read_mounts(tmp_path / "nope") == []


def test_classify_mount() -> None:
    assert classify_mount("/mnt/c") == "windows"
    assert classify_mount("/mnt/c/Users/x") == "windows"
    assert classify_mount("/mnt/d") == "usb"
    assert classify_mount("/mnt/wsl") == "ignore"
    assert classify_mount("/mnt") == "ignore"
    assert classify_mount("/media/user/USB") == "portable"
    assert classify_mount("/run/media/user/USB") == "portable"
    assert classify_mount("/home/user") == "ignore"


def test_discover_removable_mounts(monkeypatch, tmp_path: Path) -> None:
    mounts = tmp_path / "mounts"
    mounts.write_text(
        "/dev/sda1 / ext4 rw 0 0\n"
        "/dev/sdb1 /mnt/d vfat rw 0 0\n"
        "/dev/sdc1 /mnt/c ntfs rw 0 0\n"
        "/dev/sdd1 /media/user/USB vfat rw 0 0\n"
        "/dev/sde1 /mnt/wsl tmpfs rw 0 0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(Path, "exists", lambda self: True)
    found = discover_removable_mounts(mounts)
    assert found == [Path("/mnt/d"), Path("/media/user/USB")]


def test_sha256_of_known_content(tmp_path: Path) -> None:
    target = tmp_path / "abc.txt"
    target.write_bytes(b"abc")
    assert sha256_file(target) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_secret_keys_cover_common_names() -> None:
    for key in ("api_key", "apikey", "x-apikey", "token", "password"):
        assert key in util.SECRET_KEYS


def test_is_windows_path_never_confuses_prefix() -> None:
    # /mnt/cc is NOT /mnt/c even though the strings share a prefix.
    assert not is_windows_path("/mnt/cc/foo")
    assert os.sep in str(Path("/mnt/cc"))
