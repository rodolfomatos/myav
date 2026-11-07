"""SQLite persistence for scans, quarantine records, startup baselines and VT cache.

One connection per operation (WAL mode) keeps the watcher, the CLI and the scheduler from
fighting over a long-lived handle. Volume is low: a few rows per minute at worst.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .util import now_iso, now_ts

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    path          TEXT NOT NULL,
    size          INTEGER NOT NULL,
    sha256        TEXT NOT NULL,
    verdict       TEXT NOT NULL,
    quarantine_id TEXT,
    engines       TEXT NOT NULL DEFAULT '[]',
    degraded      TEXT NOT NULL DEFAULT '[]',
    kind          TEXT NOT NULL DEFAULT 'manual'
);
CREATE INDEX IF NOT EXISTS idx_scans_sha ON scans(sha256);
CREATE INDEX IF NOT EXISTS idx_scans_ts  ON scans(ts);
CREATE TABLE IF NOT EXISTS quarantines (
    id            TEXT PRIMARY KEY,
    ts            TEXT NOT NULL,
    original_path TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    size          INTEGER NOT NULL,
    mode          INTEGER NOT NULL,
    mtime         REAL NOT NULL,
    tag           TEXT NOT NULL,
    reason        TEXT NOT NULL,
    evidence      TEXT NOT NULL DEFAULT '[]',
    state         TEXT NOT NULL,
    payload       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quarantine_sha ON quarantines(sha256);
CREATE TABLE IF NOT EXISTS allowlist (
    sha256   TEXT PRIMARY KEY,
    path     TEXT,
    reason   TEXT,
    added_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS boot_entries (
    key        TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    command    TEXT NOT NULL DEFAULT '',
    location   TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS boot_runs (
    ts            TEXT PRIMARY KEY,
    new_count     INTEGER NOT NULL,
    removed_count INTEGER NOT NULL,
    total         INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vt_cache (
    sha256     TEXT PRIMARY KEY,
    status     TEXT NOT NULL,
    positives  INTEGER NOT NULL DEFAULT 0,
    total      INTEGER NOT NULL DEFAULT 0,
    checked_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vt_requests (
    ts INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS intel_iocs (
    ioc_type   TEXT NOT NULL,
    value      TEXT NOT NULL,
    source     TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 50,
    tags       TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (ioc_type, value, source)
);
CREATE INDEX IF NOT EXISTS idx_intel_lookup ON intel_iocs(ioc_type, value);
CREATE TABLE IF NOT EXISTS intel_feeds (
    name       TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    format     TEXT NOT NULL,
    ioc_count  INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
"""


@dataclass
class QuarantineRecord:
    id: str
    original_path: str
    sha256: str
    size: int
    mode: int
    mtime: float
    tag: str
    reason: str
    payload: str
    state: str = "staged"
    evidence: list[dict[str, Any]] = field(default_factory=list)
    ts: str = field(default_factory=now_iso)


@dataclass
class BootEntry:
    key: str
    name: str
    command: str = ""
    location: str = ""


class State:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            yield conn
            conn.commit()
        finally:
            conn.close()

    def init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    # ------------------------------------------------------------------ meta

    def get_meta(self, key: str, default: str | None = None) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    # ----------------------------------------------------------------- scans

    def record_scan(
        self,
        *,
        path: str,
        size: int,
        sha256: str,
        verdict: str,
        engines: list[dict[str, Any]],
        degraded: list[str] | None = None,
        quarantine_id: str | None = None,
        kind: str = "manual",
    ) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scans(ts, path, size, sha256, verdict, quarantine_id, engines,"
                " degraded, kind) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    now_iso(),
                    path,
                    size,
                    sha256,
                    verdict,
                    quarantine_id,
                    json.dumps(engines),
                    json.dumps(degraded or []),
                    kind,
                ),
            )
            return int(cursor.lastrowid or 0)

    def scan_stats(self, since_ts: str | None = None) -> dict[str, int]:
        query = "SELECT verdict, COUNT(*) AS n FROM scans"
        params: tuple = ()
        if since_ts:
            query += " WHERE ts >= ?"
            params = (since_ts,)
        query += " GROUP BY verdict"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        stats = {"CLEAN": 0, "SUSPICIOUS": 0, "MALICIOUS": 0, "UNKNOWN": 0}
        for row in rows:
            stats[row["verdict"]] = row["n"]
        stats["total"] = sum(value for key, value in stats.items() if key != "total")
        return stats

    def last_scan_ts(self, kind: str | None = None) -> str | None:
        with self._connect() as conn:
            if kind:
                row = conn.execute(
                    "SELECT ts FROM scans WHERE kind=? ORDER BY id DESC LIMIT 1", (kind,)
                ).fetchone()
            else:
                row = conn.execute("SELECT ts FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return row["ts"] if row else None

    # ------------------------------------------------------------------ baseline

    def get_baseline_established_at(self) -> str | None:
        return self.get_meta("baseline_established_at")

    def set_baseline_established_at(self, ts: str) -> None:
        self.set_meta("baseline_established_at", ts)

    def scans_for_sha(self, sha256: str) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM scans WHERE sha256=? ORDER BY id DESC", (sha256,)
            ).fetchall()

    # ------------------------------------------------------------ quarantine

    def add_quarantine(self, record: QuarantineRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO quarantines(id, ts, original_path, sha256, size, mode, mtime,"
                " tag, reason, evidence, state, payload) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.id,
                    record.ts,
                    record.original_path,
                    record.sha256,
                    record.size,
                    record.mode,
                    record.mtime,
                    record.tag,
                    record.reason,
                    json.dumps(record.evidence),
                    record.state,
                    record.payload,
                ),
            )

    def set_quarantine_state(self, quarantine_id: str, state: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE quarantines SET state=? WHERE id=?", (state, quarantine_id))

    def get_quarantine(self, quarantine_id: str) -> QuarantineRecord | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM quarantines WHERE id=?", (quarantine_id,)).fetchone()
        return _row_to_record(row) if row else None

    def list_quarantines(self, include_restored: bool = False) -> list[QuarantineRecord]:
        query = "SELECT * FROM quarantines"
        if not include_restored:
            query += " WHERE state != 'restored'"
        query += " ORDER BY ts DESC"
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return [_row_to_record(row) for row in rows]

    def find_quarantine_by_sha(self, sha256: str) -> QuarantineRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM quarantines WHERE sha256=? AND state != 'restored' "
                "ORDER BY ts DESC LIMIT 1",
                (sha256,),
            ).fetchone()
        return _row_to_record(row) if row else None

    def quarantine_total_size(self) -> int:
        """Sum of payload sizes (bytes) of all non-restored quarantine entries."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(size), 0) AS total FROM quarantines WHERE state != 'restored'"
            ).fetchone()
        return int(row["total"])

    def delete_quarantine(self, quarantine_id: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM quarantines WHERE id=?", (quarantine_id,))

    # -------------------------------------------------------------- allowlist

    def allow(self, sha256: str, path: str | None = None, reason: str = "") -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO allowlist(sha256, path, reason, added_at) VALUES(?,?,?,?) "
                "ON CONFLICT(sha256) DO UPDATE SET path=excluded.path, reason=excluded.reason",
                (sha256, path, reason, now_iso()),
            )

    def disallow(self, sha256: str) -> bool:
        """Remove ``sha256`` from the allowlist. Returns True if a row was deleted."""
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM allowlist WHERE sha256=?", (sha256,))
        return cursor.rowcount > 0

    def is_allowed(self, sha256: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM allowlist WHERE sha256=?", (sha256,)).fetchone()
        return row is not None

    def list_allowlist(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM allowlist ORDER BY added_at DESC").fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------ boot entries

    def boot_apply(self, entries: Iterable[BootEntry]) -> tuple[list[BootEntry], list[BootEntry]]:
        """Replace the baseline; return ``(new, removed)``.

        The very first run has no baseline: every entry is new *for storage* but must not
        be reported as an alert (the caller checks ``boot_run_count``).
        """
        now = now_iso()
        entries = list(entries)
        incoming = {entry.key: entry for entry in entries}
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM boot_entries WHERE active=1").fetchall()
            previous = {row["key"]: row for row in rows}

            new = [entry for key, entry in incoming.items() if key not in previous]
            removed = [
                BootEntry(
                    key=row["key"],
                    name=row["name"],
                    command=row["command"],
                    location=row["location"],
                )
                for key, row in previous.items()
                if key not in incoming
            ]

            conn.execute("UPDATE boot_entries SET active=0")
            for entry in entries:
                conn.execute(
                    "INSERT INTO boot_entries(key, name, command, location, first_seen,"
                    " last_seen, active) VALUES(?,?,?,?,?,?,1) "
                    "ON CONFLICT(key) DO UPDATE SET name=excluded.name,"
                    " command=excluded.command, location=excluded.location,"
                    " last_seen=excluded.last_seen, active=1",
                    (entry.key, entry.name, entry.command, entry.location, now, now),
                )
            conn.execute(
                "INSERT INTO boot_runs(ts, new_count, removed_count, total) VALUES(?,?,?,?)",
                (now, len(new), len(removed), len(entries)),
            )
        return new, removed

    def boot_run_count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM boot_runs").fetchone()
        return int(row["n"]) if row else 0

    def boot_snapshot(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM boot_entries WHERE active=1 ORDER BY name"
            ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------- vt caching

    def vt_get(self, sha256: str, ttl_positive: int, ttl_negative: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM vt_cache WHERE sha256=?", (sha256,)).fetchone()
        if not row:
            return None
        ttl = ttl_positive if row["status"] == "known" else ttl_negative
        if now_ts() - int(row["checked_at"]) > ttl:
            return None
        return dict(row)

    def vt_put(self, sha256: str, status: str, positives: int, total: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO vt_cache(sha256, status, positives, total, checked_at)"
                " VALUES(?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET"
                " status=excluded.status, positives=excluded.positives,"
                " total=excluded.total, checked_at=excluded.checked_at",
                (sha256, status, positives, total, now_ts()),
            )

    def vt_requests_since(self, since_ts: int) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM vt_requests WHERE ts >= ?", (since_ts,)
            ).fetchone()
        return int(row["n"]) if row else 0

    def vt_record_request(self) -> None:
        cutoff = now_ts() - 48 * 3600
        with self._connect() as conn:
            conn.execute("INSERT INTO vt_requests(ts) VALUES(?)", (now_ts(),))
            conn.execute("DELETE FROM vt_requests WHERE ts < ?", (cutoff,))

    # --------------------------------------------------------- threat intel

    def upsert_intel(self, iocs: Iterable[Any]) -> int:
        """Insert or refresh indicators of compromise.

        Each item may be an :class:`myav.intel.IntelIOC` or a mapping with
        ``ioc_type``/``value``/``source``/``confidence``/``tags``. ``first_seen``
        is preserved across updates; ``last_seen`` is refreshed.
        """
        stamp = now_iso()
        rows = [_intel_row(ioc, stamp) for ioc in iocs]
        rows = [row for row in rows if row is not None]
        if not rows:
            return 0
        with self._connect() as conn:
            conn.executemany(
                "INSERT INTO intel_iocs"
                "(ioc_type, value, source, confidence, tags, first_seen, last_seen)"
                " VALUES(?,?,?,?,?,?,?) ON CONFLICT(ioc_type, value, source)"
                " DO UPDATE SET confidence=excluded.confidence,"
                " tags=excluded.tags, last_seen=excluded.last_seen",
                rows,
            )
        return len(rows)

    def lookup_intel(self, ioc_type: str, value: str) -> list[dict[str, Any]]:
        """Return every source that published an exact indicator, best first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM intel_iocs WHERE ioc_type=? AND value=?"
                " ORDER BY confidence DESC, source",
                (ioc_type, value.lower()),
            ).fetchall()
        return [_intel_dict(row) for row in rows]

    def intel_summary(self) -> dict[str, Any]:
        """Aggregate cache statistics for ``myav intel status``."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS n FROM intel_iocs").fetchone()["n"]
            by_type = {
                row["ioc_type"]: row["n"]
                for row in conn.execute(
                    "SELECT ioc_type, COUNT(*) AS n FROM intel_iocs GROUP BY ioc_type"
                ).fetchall()
            }
            sources = conn.execute(
                "SELECT COUNT(DISTINCT source) AS n FROM intel_iocs"
            ).fetchone()["n"]
            feeds = conn.execute("SELECT COUNT(*) AS n FROM intel_feeds").fetchone()["n"]
            last = conn.execute(
                "SELECT MAX(updated_at) AS ts FROM intel_feeds"
            ).fetchone()["ts"]
        return {
            "total": int(total),
            "by_type": dict(sorted(by_type.items())),
            "sources": int(sources),
            "feeds": int(feeds),
            "last_update": last,
        }

    def intel_feeds(self) -> list[dict[str, Any]]:
        """Return every imported feed with its provenance."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM intel_feeds ORDER BY name"
            ).fetchall()
        return [dict(row) for row in rows]

    def record_intel_feed(
        self, *, name: str, source: str, fmt: str, ioc_count: int
    ) -> None:
        """Record (or refresh) the provenance of one imported feed."""
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO intel_feeds(name, source, format, ioc_count, updated_at)"
                " VALUES(?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET"
                " source=excluded.source, format=excluded.format,"
                " ioc_count=excluded.ioc_count, updated_at=excluded.updated_at",
                (name, source, fmt, ioc_count, now_iso()),
            )

    def clear_intel(self) -> int:
        """Delete every cached indicator and feed. Returns the IOC count removed."""
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS n FROM intel_iocs").fetchone()["n"]
            conn.execute("DELETE FROM intel_iocs")
            conn.execute("DELETE FROM intel_feeds")
        return int(total)


def _intel_row(ioc: Any, stamp: str) -> tuple[Any, ...] | None:
    if isinstance(ioc, dict):
        ioc_type = ioc.get("ioc_type") or ioc.get("type")
        value = ioc.get("value")
        source = ioc.get("source")
        confidence = ioc.get("confidence", 50)
        tags = ioc.get("tags", [])
    else:
        ioc_type = getattr(ioc, "ioc_type", None)
        value = getattr(ioc, "value", None)
        source = getattr(ioc, "source", None)
        confidence = getattr(ioc, "confidence", 50)
        tags = getattr(ioc, "tags", [])
    if not ioc_type or not value or not source:
        return None
    return (
        str(ioc_type),
        str(value).lower(),
        str(source),
        int(confidence),
        json.dumps(sorted({str(tag) for tag in tags if tag})),
        stamp,
        stamp,
    )


def _intel_dict(row: sqlite3.Row) -> dict[str, Any]:
    try:
        tags = json.loads(row["tags"])
    except (TypeError, ValueError):
        tags = []
    return {
        "type": row["ioc_type"],
        "value": row["value"],
        "source": row["source"],
        "confidence": row["confidence"],
        "tags": tags,
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
    }


def _row_to_record(row: sqlite3.Row) -> QuarantineRecord:
    return QuarantineRecord(
        id=row["id"],
        original_path=row["original_path"],
        sha256=row["sha256"],
        size=row["size"],
        mode=row["mode"],
        mtime=row["mtime"],
        tag=row["tag"],
        reason=row["reason"],
        payload=row["payload"],
        state=row["state"],
        evidence=json.loads(row["evidence"]),
        ts=row["ts"],
    )
