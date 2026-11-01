from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from myav import quarantine as quarantine_module
from myav.hashutil import sha256_file
from myav.quarantine import Quarantine, QuarantineError
from myav.verdict import LEVEL_MALICIOUS, LEVEL_SUSPICIOUS, Verdict


@pytest.fixture
def quarantine(paths, state, config) -> Quarantine:
    return Quarantine(paths, state, config)


@pytest.fixture
def sample(tmp_path: Path) -> Path:
    target = tmp_path / "bad.bin"
    target.write_bytes(b"malicious payload")
    target.chmod(0o640)
    return target


def _verdict(level: str = LEVEL_MALICIOUS) -> Verdict:
    return Verdict(level=level, reasons=["clamav: Eicar"])


def test_quarantine_moves_and_records(quarantine: Quarantine, sample: Path, state) -> None:
    digest = sha256_file(sample)
    record = quarantine.quarantine(sample, _verdict())
    assert record is not None
    assert record.state == "complete"
    assert record.sha256 == digest
    assert record.tag == "malicious"
    assert record.mode == 0o640
    assert not sample.exists()
    payload = quarantine.payload_path(record)
    assert payload.exists()
    # The payload is deliberately 000; a reader must lift that first, exactly like restore does.
    os.chmod(payload, 0o600)
    assert sha256_file(payload) == digest
    os.chmod(payload, 0o000)
    assert payload.stat().st_mode & 0o777 == 0
    assert state.get_quarantine(record.id).state == "complete"


def test_quarantine_suspicious_tag(quarantine: Quarantine, sample: Path) -> None:
    record = quarantine.quarantine(sample, _verdict(LEVEL_SUSPICIOUS))
    assert record.tag == "suspicious"


def test_allowlisted_file_is_untouched(quarantine: Quarantine, sample: Path, state) -> None:
    state.allow(sha256_file(sample), reason="known good")
    assert quarantine.quarantine(sample, _verdict()) is None
    assert sample.exists()


def test_missing_source(quarantine: Quarantine, tmp_path: Path) -> None:
    with pytest.raises(QuarantineError) as excinfo:
        quarantine.quarantine(tmp_path / "ghost", _verdict())
    assert excinfo.value.code == 2


def test_refuses_directory_and_symlink(quarantine: Quarantine, tmp_path: Path) -> None:
    with pytest.raises(QuarantineError) as excinfo:
        quarantine.quarantine(tmp_path, _verdict())
    assert excinfo.value.code == 2

    target = tmp_path / "real.bin"
    target.write_bytes(b"x")
    link = tmp_path / "link.bin"
    link.symlink_to(target)
    with pytest.raises(QuarantineError):
        quarantine.quarantine(link, _verdict())
    assert target.exists()


def test_copy_path_when_rename_crosses_filesystems(
    quarantine: Quarantine, sample: Path, monkeypatch
) -> None:
    def no_rename(*args, **kwargs):
        raise OSError(errno.EXDEV, "cross-device link")

    monkeypatch.setattr(quarantine_module.os, "rename", no_rename)
    record = quarantine.quarantine(sample, _verdict())
    assert record.state == "complete"
    assert not sample.exists()
    payload = quarantine.payload_path(record)
    os.chmod(payload, 0o600)
    assert sha256_file(payload) == record.sha256


def test_hash_mismatch_keeps_both_and_marks_partial(
    quarantine: Quarantine, sample: Path, state, monkeypatch
) -> None:
    digest = sha256_file(sample)
    calls = {"n": 0}

    def fake_hash(path):
        calls["n"] += 1
        return digest if calls["n"] == 1 else "0" * 64

    def no_rename(*args, **kwargs):
        raise OSError(errno.EXDEV, "cross-device link")

    monkeypatch.setattr(quarantine_module, "sha256_file", fake_hash)
    monkeypatch.setattr(quarantine_module.os, "rename", no_rename)
    with pytest.raises(QuarantineError) as excinfo:
        quarantine.quarantine(sample, _verdict())
    assert excinfo.value.code == 5
    # The original is still there: a mismatch must never lose data.
    assert sample.exists()
    records = state.list_quarantines()
    assert records[0].state == "partial"


def test_unreadable_destination_marks_partial(
    quarantine: Quarantine, sample: Path, state, monkeypatch
) -> None:
    digest = sha256_file(sample)

    def explode(path):
        if str(path).endswith(".bin") and "quarantine" in str(path):
            raise OSError("unreadable")
        return digest

    def no_rename(*args, **kwargs):
        raise OSError(errno.EXDEV, "cross-device link")

    monkeypatch.setattr(quarantine_module.os, "rename", no_rename)
    monkeypatch.setattr(quarantine_module, "sha256_file", explode)
    with pytest.raises(QuarantineError) as excinfo:
        quarantine.quarantine(sample, _verdict())
    assert excinfo.value.code == 4
    assert sample.exists()
    assert state.list_quarantines()[0].state == "partial"


def test_copy_verified_but_source_unlink_fails(
    quarantine: Quarantine, sample: Path, state, monkeypatch
) -> None:
    def no_rename(*args, **kwargs):
        raise OSError(errno.EXDEV, "cross-device link")

    original_unlink = Path.unlink

    def fake_unlink(self, *args, **kwargs):
        if self == sample:
            raise OSError("busy")
        return original_unlink(self, *args, **kwargs)

    monkeypatch.setattr(quarantine_module.os, "rename", no_rename)
    monkeypatch.setattr(Path, "unlink", fake_unlink)
    with pytest.raises(QuarantineError) as excinfo:
        quarantine.quarantine(sample, _verdict())
    assert excinfo.value.code == 6
    assert sample.exists()
    assert state.list_quarantines()[0].state == "partial"


def test_rename_failure_other_than_exdev_fails_cleanly(
    quarantine: Quarantine, sample: Path, state, monkeypatch
) -> None:
    def broken(*args, **kwargs):
        raise OSError(errno.EACCES, "denied")

    monkeypatch.setattr(quarantine_module.os, "rename", broken)
    with pytest.raises(QuarantineError) as excinfo:
        quarantine.quarantine(sample, _verdict())
    assert excinfo.value.code == 3
    assert sample.exists()
    assert state.list_quarantines()[0].state == "failed"


def test_restore_round_trip(quarantine: Quarantine, sample: Path, state) -> None:
    original_mtime = sample.stat().st_mtime
    record = quarantine.quarantine(sample, _verdict())
    restored = quarantine.restore(record.id)
    assert restored == sample
    assert restored.read_bytes() == b"malicious payload"
    assert restored.stat().st_mode & 0o777 == 0o640
    assert restored.stat().st_mtime == pytest.approx(original_mtime, abs=0.01)
    assert quarantine.payload_path(record).stat().st_mode & 0o777 == 0
    assert state.get_quarantine(record.id).state == "restored"


def test_restore_to_alternate_path(quarantine: Quarantine, sample: Path, tmp_path: Path) -> None:
    record = quarantine.quarantine(sample, _verdict())
    other = tmp_path / "elsewhere" / "renamed.bin"
    restored = quarantine.restore(record.id, target=other)
    assert restored == other
    assert other.read_bytes() == b"malicious payload"


def test_restore_errors(quarantine: Quarantine, sample: Path, state, tmp_path: Path) -> None:
    with pytest.raises(QuarantineError) as excinfo:
        quarantine.restore("nope")
    assert excinfo.value.code == 2

    record = quarantine.quarantine(sample, _verdict())
    quarantine.restore(record.id)
    with pytest.raises(QuarantineError, match="already restored"):
        quarantine.restore(record.id)

    # Missing payload.
    second = tmp_path / "second.bin"
    second.write_bytes(b"data2")
    record2 = quarantine.quarantine(second, _verdict())
    quarantine.payload_path(record2).unlink()
    with pytest.raises(QuarantineError) as excinfo:
        quarantine.restore(record2.id)
    assert excinfo.value.code == 3


def test_restore_refuses_tampered_payload(quarantine: Quarantine, sample: Path) -> None:
    record = quarantine.quarantine(sample, _verdict())
    payload = quarantine.payload_path(record)
    os.chmod(payload, 0o600)
    payload.write_bytes(b"tampered")
    with pytest.raises(QuarantineError) as excinfo:
        quarantine.restore(record.id)
    assert excinfo.value.code == 4
    assert not sample.exists()


def test_restore_refuses_to_overwrite(quarantine: Quarantine, sample: Path, tmp_path: Path) -> None:
    record = quarantine.quarantine(sample, _verdict())
    sample.write_bytes(b"new file with the same name")
    with pytest.raises(QuarantineError) as excinfo:
        quarantine.restore(record.id)
    assert excinfo.value.code == 5
    assert sample.read_bytes() == b"new file with the same name"

    restored = quarantine.restore(record.id, force=True)
    assert restored.read_bytes() == b"malicious payload"


def test_restore_to_windows_path_warns(
    quarantine: Quarantine, sample: Path, monkeypatch, capsys
) -> None:
    record = quarantine.quarantine(sample, _verdict())
    monkeypatch.setattr(quarantine_module, "_is_windows_path", lambda path: True)
    restored = quarantine.restore(record.id)
    assert "warning: restoring to a Windows-mounted path" in capsys.readouterr().out
    assert restored.exists()


def test_purge_requires_yes(quarantine: Quarantine, sample: Path, state, capsys) -> None:
    record = quarantine.quarantine(sample, _verdict())
    payload = quarantine.payload_path(record)
    assert quarantine.purge(record.id) is False
    assert payload.exists()
    assert "--yes" in capsys.readouterr().out
    assert state.get_quarantine(record.id) is not None

    assert quarantine.purge(record.id, yes=True) is True
    assert not payload.exists()
    assert state.get_quarantine(record.id) is None


def test_purge_unknown_id(quarantine: Quarantine) -> None:
    with pytest.raises(QuarantineError) as excinfo:
        quarantine.purge("missing", yes=True)
    assert excinfo.value.code == 2
