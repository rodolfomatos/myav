"""Reversible quarantine. The "never delete" guarantee lives in this file.

Protocol (docs/ARCHITECTURE.md §4), enforced by tests:

1. hash the source;
2. write a ``staged`` row before touching the file;
3. move atomically when the destination is on the same filesystem, otherwise
   copy → fsync(file) → fsync(dir) → verify hash → unlink source;
4. hash the stored payload and compare;
5. on any mismatch the source is **not** unlinked and the record is marked ``partial``;
6. the payload is stored ``0000`` with a generated name, so it cannot be executed by accident.

``restore`` re-verifies, refuses to overwrite, restores mode and mtime, and re-hashes.
``purge`` is the only delete path and requires ``yes=True``.
"""

from __future__ import annotations

import errno
import os
import shutil
import uuid
from pathlib import Path

from .config import Config
from .hashutil import sha256_file
from .paths import Paths, UnsafeLocationError, assert_writable_location
from .state import QuarantineRecord, State
from .util import display_path, now_iso
from .verdict import Verdict


class QuarantineError(RuntimeError):
    """A quarantine operation refused or failed safely."""

    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


class Quarantine:
    def __init__(self, paths: Paths, state: State, config: Config | None = None):
        self.paths = paths
        self.state = state
        self.config = config or Config(paths=paths)

    # ------------------------------------------------------------------ helpers

    def payload_path(self, record: QuarantineRecord) -> Path:
        return self.paths.quarantine_dir / record.payload

    def _ensure_dir(self) -> Path:
        directory = assert_writable_location(self.paths.quarantine_dir)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        return directory

    # --------------------------------------------------------------- quarantine

    def quarantine(self, path: Path, verdict: Verdict, reason: str = "") -> QuarantineRecord | None:
        """Move ``path`` into quarantine. Returns ``None`` when allowlisted."""
        source = Path(path)
        try:
            stat = source.lstat()
        except FileNotFoundError:
            raise QuarantineError(
                f"{display_path(source)} vanished before quarantine", code=2
            ) from None
        if not os.path.isfile(source) or os.path.islink(source):
            raise QuarantineError(f"refusing to quarantine non-regular file: {source}", code=2)

        digest = sha256_file(source)
        if self.state.is_allowed(digest):
            return None

        qdir = self._ensure_dir()
        quarantine_id = uuid.uuid4().hex
        payload_name = f"{quarantine_id}.bin"
        record = QuarantineRecord(
            id=quarantine_id,
            original_path=str(source.absolute()),
            sha256=digest,
            size=stat.st_size,
            mode=stat.st_mode & 0o7777,
            mtime=stat.st_mtime,
            tag=verdict.quarantine_tag,
            reason=reason or "; ".join(verdict.reasons) or verdict.level,
            payload=payload_name,
            state="staged",
            evidence=[result.as_dict() for result in verdict.results],
            ts=now_iso(),
        )
        # 2. Persist the intent first: a crash leaves a reconcilable ``staged`` row.
        self.state.add_quarantine(record)

        destination = qdir / payload_name
        try:
            moved = self._move(source, destination)
        except OSError as exc:
            self.state.set_quarantine_state(record.id, "failed")
            raise QuarantineError(f"could not move {display_path(source)}: {exc}", code=3) from exc

        try:
            stored_digest = sha256_file(destination)
        except OSError as exc:
            self.state.set_quarantine_state(record.id, "partial")
            raise QuarantineError(
                f"quarantined copy unreadable ({exc}); source left at {display_path(source)}",
                code=4,
            ) from exc

        if stored_digest != digest:
            # Never lose data: keep both, mark partial, tell the caller.
            self.state.set_quarantine_state(record.id, "partial")
            record.state = "partial"
            raise QuarantineError(
                "hash mismatch after quarantine move: source kept, copy kept as "
                f"{display_path(destination)}",
                code=5,
            )

        os.chmod(destination, 0o000)
        if moved == "copy":
            try:
                source.unlink()
            except OSError as exc:
                self.state.set_quarantine_state(record.id, "partial")
                record.state = "partial"
                raise QuarantineError(
                    f"copy verified but source could not be removed ({exc}); "
                    f"source kept at {display_path(source)}",
                    code=6,
                ) from exc

        self.state.set_quarantine_state(record.id, "complete")
        record.state = "complete"
        return record

    def _move(self, source: Path, destination: Path) -> str:
        """Atomic rename when possible, verified copy otherwise. Never deletes first."""
        if not destination.exists():
            try:
                os.rename(source, destination)
                return "rename"
            except OSError as exc:
                if exc.errno != errno.EXDEV:
                    raise
        self._copy_verified(source, destination)
        return "copy"

    def _copy_verified(self, source: Path, destination: Path) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(destination, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as out, open(source, "rb") as src:
                shutil.copyfileobj(src, out, length=1024 * 1024)
                out.flush()
                os.fsync(out.fileno())
            dir_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            try:
                os.unlink(destination)
            except OSError:
                pass
            raise

    # -------------------------------------------------------------------- restore

    def restore(
        self,
        quarantine_id: str,
        target: Path | None = None,
        force: bool = False,
    ) -> Path:
        record = self.state.get_quarantine(quarantine_id)
        if record is None:
            raise QuarantineError(f"no quarantine entry: {quarantine_id}", code=2)
        if record.state == "restored":
            raise QuarantineError(f"{quarantine_id} was already restored", code=2)

        payload = self.payload_path(record)
        if not payload.exists():
            raise QuarantineError(f"payload missing for {quarantine_id}: {payload}", code=3)

        os.chmod(payload, 0o600)
        if sha256_file(payload) != record.sha256:
            raise QuarantineError(
                f"payload for {quarantine_id} does not match its recorded hash; "
                "refusing to restore",
                code=4,
            )

        destination = Path(target) if target else Path(record.original_path)
        if destination.exists() and not force:
            raise QuarantineError(
                f"{display_path(destination)} exists; use --force to overwrite", code=5
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        if _is_windows_path(destination):
            # Restoring a user's own file is legitimate, but never silent.
            print(f"warning: restoring to a Windows-mounted path: {destination}")
        else:
            assert_writable_location(destination)

        temp = destination.parent / f".myav-restore-{uuid.uuid4().hex}.tmp"
        try:
            shutil.copyfile(payload, temp)
            with open(temp, "rb+") as handle:
                handle.flush()
                os.fsync(handle.fileno())
            if sha256_file(temp) != record.sha256:
                raise QuarantineError(
                    "restored copy failed hash verification; original untouched", code=6
                )
            os.chmod(temp, record.mode or 0o600)
            os.replace(temp, destination)
        except BaseException:
            if temp.exists():
                temp.unlink(missing_ok=True)
            raise
        os.utime(destination, (record.mtime, record.mtime))
        os.chmod(payload, 0o000)
        self.state.set_quarantine_state(record.id, "restored")
        return destination

    # --------------------------------------------------------------------- purge

    def purge(self, quarantine_id: str, yes: bool = False) -> bool:
        record = self.state.get_quarantine(quarantine_id)
        if record is None:
            raise QuarantineError(f"no quarantine entry: {quarantine_id}", code=2)
        payload = self.payload_path(record)
        if not yes:
            print(
                f"would delete {display_path(payload)} "
                f"({record.size} bytes, sha256 {record.sha256[:12]}…) — re-run with --yes"
            )
            return False
        os.chmod(payload, 0o600)
        payload.unlink(missing_ok=True)
        self.state.delete_quarantine(record.id)
        return True


def _is_windows_path(path: Path) -> bool:
    try:
        from ..paths import is_windows_path

        return is_windows_path(path)
    except (ImportError, UnsafeLocationError):  # pragma: no cover - defensive
        return False
