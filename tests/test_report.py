"""Report rendering and retention.

The report is the only part of myav most users will read, so the tests assert the
promises the text makes: counts reconcile, a clean scan never says "safe", and a
degraded engine is always visible.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from conftest import StubClam, StubVirusTotal, StubYara, make_engines

from myav.engine import MALICIOUS, SKIPPED, SUSPICIOUS
from myav.pipeline import Outcome
from myav.report import (
    ReportContext,
    build_context,
    prune_reports,
    render_report,
    report_path,
    utcnow,
    write_report,
)
from myav.state import QuarantineRecord
from myav.verdict import Verdict


def outcome(path: Path, level: str, **kwargs) -> Outcome:
    return Outcome(path=path, verdict=Verdict(level=level), **kwargs)


def test_counts_reconcile_and_clean_scan_is_honest() -> None:
    started = utcnow() - timedelta(seconds=4)
    context = ReportContext(
        kind="manual",
        started=started,
        finished=utcnow(),
        outcomes=[
            outcome(Path("/home/u/Downloads/a.txt"), "CLEAN", sha256="a" * 64, size=10),
            outcome(Path("/home/u/Downloads/b.txt"), "CLEAN", sha256="b" * 64, size=20),
            Outcome(path=Path("/home/u/Downloads/c.txt"), skipped="vanished"),
        ],
        engine_state={"ClamAV": "ok", "YARA": "ok"},
        quarantine=[],
        attention=[],
        scope=[Path("/home/u/Downloads")],
    )

    text = render_report(context)

    assert "| CLEAN | 2 |" in text
    assert "| **total** | **2** |" in text
    assert "1 file(s) were not scanned" in text
    assert "Nothing is currently in quarantine." in text
    assert "It does not mean the file is safe" in text
    assert "Duration:" in text


def test_findings_show_evidence_and_sha() -> None:
    verdict = Verdict(
        level="MALICIOUS",
        results=[
            type(
                "R",
                (),
                {
                    "fired": True,
                    "engine": "clamav",
                    "signature": "Eicar-Test",
                    "status": "MALICIOUS",
                    "as_dict": lambda self: {},
                },
            )(),
        ],
    )
    clean_verdict = Verdict(level="CLEAN", results=[])
    context = ReportContext(
        kind="manual",
        started=utcnow(),
        finished=utcnow(),
        outcomes=[
            Outcome(
                path=Path("/home/u/Downloads/bad.exe"),
                verdict=verdict,
                sha256="deadbeef" * 8,
                size=68,
                quarantined=QuarantineRecord(
                    id="1234567890abcdef",
                    original_path="/home/u/Downloads/bad.exe",
                    sha256="deadbeef" * 8,
                    size=68,
                    mode=0o644,
                    mtime=0.0,
                    tag="malicious",
                    reason="clamav",
                    payload="1234567890abcdef.bin",
                ),
            ),
            Outcome(
                path=Path("/home/u/Downloads/ok.txt"),
                verdict=clean_verdict,
                sha256="c" * 64,
                size=1,
            ),
        ],
        engine_state={"ClamAV": "ok"},
        quarantine=[
            QuarantineRecord(
                id="1234567890abcdef",
                original_path="/home/u/Downloads/bad.exe",
                sha256="deadbeef" * 8,
                size=68,
                mode=0o644,
                mtime=0.0,
                tag="malicious",
                reason="clamav",
                payload="1234567890abcdef.bin",
            )
        ],
        attention=[],
        scope=[],
    )

    text = render_report(context)

    assert "clamav:Eicar-Test" in text
    assert "`deadbeefdeadbeef…`" in text
    assert "MALICIOUS" in text
    assert "12345678" in text
    assert "myav restore <id>" in text


def test_attention_deduplicates_and_includes_errors_and_degraded() -> None:
    outcome_with_error = Outcome(path=Path("/tmp/x"), error="unreadable: nope")
    verdict = Verdict(level="CLEAN", degraded=["clamav: signature database is older than 48h"])
    outcome_with_degraded = Outcome(path=Path("/tmp/y"), verdict=verdict)
    context = ReportContext(
        kind="manual",
        started=utcnow(),
        finished=utcnow(),
        outcomes=[outcome_with_error, outcome_with_degraded, outcome_with_error],
        engine_state={},
        quarantine=[],
        attention=["clamav: signature database is older than 48h"],
        scope=[],
    )

    text = render_report(context)

    assert text.count("clamav: signature database is older than 48h") == 1
    assert "unreadable: nope" in text


def test_write_and_prune(paths) -> None:
    context = ReportContext(
        kind="manual",
        started=utcnow(),
        finished=utcnow(),
        outcomes=[],
        engine_state={},
        quarantine=[],
        attention=[],
        scope=[],
    )
    written = write_report(paths, context)
    assert written.exists()
    assert written.parent == paths.reports_dir
    assert report_path(paths, "full").name.endswith("-full.md")

    for index in range(5):
        (paths.reports_dir / f"2020-01-0{index}-0000-full.md").write_text("x")
    removed = prune_reports(paths, retention=2)
    assert len(removed) == 4
    assert len(list(paths.reports_dir.glob("*.md"))) == 2


def test_build_context_states(paths, state, platform, config) -> None:
    engines = make_engines(
        platform,
        clam=StubClam(),
        yara=StubYara(files=3),
        vt=StubVirusTotal(configured=False),
    )
    context = build_context(
        kind="full",
        started=utcnow(),
        outcomes=[],
        engines=engines,
        state=state,
        scope=[Path("/home/u/Downloads")],
    )
    assert "ClamAV 1.5.4" in context.engine_state["ClamAV"]
    assert "3 rule files" in context.engine_state["YARA"]
    assert "not configured (optional)" in context.engine_state["VirusTotal"]
    assert context.scope == [Path("/home/u/Downloads")]


def test_build_context_unavailable_and_missing_rules(paths, state, platform, config) -> None:
    clam = StubClam(available=False, signature_info=None)
    clam.info = type("Info", (), {"available": False, "detail": "clamd missing", "stale": False})()
    engines = make_engines(
        platform, clam=clam, yara=StubYara(files=0), vt=StubVirusTotal(configured=True)
    )
    context = build_context(
        kind="watch", started=utcnow(), outcomes=[], engines=engines, state=state
    )
    assert "unavailable — clamd missing" in context.engine_state["ClamAV"]
    assert "rules missing" in context.engine_state["YARA"]
    assert "hash-only lookups enabled" in context.engine_state["VirusTotal"]


def test_stale_signature_is_marked(paths, state, platform, config) -> None:
    clam = StubClam()
    clam.info = type(
        "Info",
        (),
        {
            "available": True,
            "version": "1.5.4",
            "db_version": "1",
            "age": timedelta(days=5),
            "stale": True,
            "detail": "",
        },
    )()
    engines = make_engines(platform, clam=clam)
    context = build_context(
        kind="manual", started=utcnow(), outcomes=[], engines=engines, state=state
    )
    assert "STALE" in context.engine_state["ClamAV"]


def test_status_engine_variants_are_rendered() -> None:
    """SUSPICIOUS/SKIPPED/MALICIOUS developments must not crash the table."""
    results = []
    for engine, status in (("clamav", MALICIOUS), ("yara", SUSPICIOUS), ("virustotal", SKIPPED)):
        results.append(
            type(
                "R",
                (),
                {
                    "fired": status in (MALICIOUS, SUSPICIOUS),
                    "engine": engine,
                    "signature": "sig" if status != SKIPPED else None,
                    "status": status,
                    "as_dict": lambda self: {},
                },
            )()
        )
    verdict = Verdict(level="MALICIOUS", results=results)
    context = ReportContext(
        kind="manual",
        started=utcnow(),
        finished=utcnow(),
        outcomes=[Outcome(path=Path("/tmp/a"), verdict=verdict, sha256="a" * 64)],
        engine_state={},
        quarantine=[],
        attention=[],
        scope=[],
    )
    text = render_report(context)
    assert "clamav:sig" in text
    assert "yara:sig" in text
