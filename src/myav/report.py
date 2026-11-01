"""Plain-English scan reports.

A report is the user interface. It must be readable by someone who has never heard of a
signature database, and it must never claim more confidence than the engines earned.
The counts are reconciled: ``scanned == clean + suspicious + malicious + unknown``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .paths import Paths
from .pipeline import Outcome
from .state import QuarantineRecord, State
from .util import display_path, format_bytes, human_age

VERDICT_ORDER = ("MALICIOUS", "SUSPICIOUS", "UNKNOWN", "CLEAN")


@dataclass
class ReportContext:
    kind: str
    started: datetime
    finished: datetime
    outcomes: list[Outcome]
    engine_state: dict
    quarantine: list[QuarantineRecord]
    attention: list[str]
    scope: list[Path]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def render_report(context: ReportContext) -> str:
    counts = _counts(context.outcomes)
    total_bytes = sum(outcome.size for outcome in context.outcomes)
    lines: list[str] = []
    add = lines.append

    add(f"# myav report — {context.kind}")
    add("")
    add(f"- Started: {context.started.isoformat(timespec='seconds')}")
    add(f"- Finished: {context.finished.isoformat(timespec='seconds')}")
    add(f"- Duration: {human_age((context.finished - context.started).total_seconds())}")
    add(f"- Files scanned: {counts['scanned']} ({format_bytes(total_bytes)})")
    if context.scope:
        add(f"- Scope: {', '.join(display_path(path) for path in context.scope)}")
    add("")

    add("## What ran")
    add("")
    add("| Engine | State |")
    add("|---|---|")
    for name, state in context.engine_state.items():
        add(f"| {name} | {state} |")
    add("")

    add("## What was scanned")
    add("")
    add("| Verdict | Files |")
    add("|---|---:|")
    for level in VERDICT_ORDER:
        add(f"| {level} | {counts[level]} |")
    add(f"| **total** | **{counts['scanned']}** |")
    if counts["skipped"]:
        add("")
        add(f"{counts['skipped']} file(s) were not scanned (vanished, symlink, unreadable).")
    add("")

    add("## What was found")
    add("")
    findings = [o for o in context.outcomes if o.level in {"MALICIOUS", "SUSPICIOUS"}]
    if not findings:
        add("Nothing. Every scanned file came back clean by the engines listed above.")
    else:
        add("| File | Verdict | Evidence | SHA-256 |")
        add("|---|---|---|---|")
        for outcome in findings:
            evidence = _evidence(outcome)
            add(
                f"| {display_path(outcome.path)} | {outcome.level} | {evidence} "
                f"| `{outcome.sha256[:16]}…` |"
            )
    add("")

    add("## What is quarantined")
    add("")
    if not context.quarantine:
        add("Nothing is currently in quarantine.")
    else:
        add("| ID | Original location | Tag | Size | When |")
        add("|---|---|---|---:|---|")
        for record in context.quarantine:
            add(
                f"| `{record.id[:8]}` | {display_path(Path(record.original_path))} "
                f"| {record.tag} | {format_bytes(record.size)} | {record.ts} |"
            )
        add("")
        add(
            "Restore anything from here with `myav restore <id>`. Nothing is deleted automatically."
        )
    add("")

    add("## Needs your attention")
    add("")
    attention = list(context.attention)
    for outcome in context.outcomes:
        if outcome.error and outcome.error not in attention:
            attention.append(f"{display_path(outcome.path)}: {outcome.error}")
        if outcome.verdict:
            for item in outcome.verdict.degraded:
                if item not in attention:
                    attention.append(item)
    if not attention:
        add("Nothing. No degraded engine, no stale signatures, no unreadable file.")
    else:
        for item in _dedupe(attention):
            add(f"- {item}")
    add("")

    add("## How to read this report")
    add("")
    add(
        "- **CLEAN** — every engine that was configured ran and none of them recognised the file. "
        "It does not mean the file is safe; it means nothing known was found."
    )
    add(
        "- **SUSPICIOUS** — something matched, but not strongly enough to call it malware "
        "(for example 1–2 VirusTotal engines, or a YARA rule without a high severity)."
    )
    add(
        "- **MALICIOUS** — a signature or rule fired, or at least 3 VirusTotal engines agree. "
        "The file was moved to quarantine and can be restored."
    )
    add(
        "- **UNKNOWN** — evidence is missing: an engine failed, was not installed, or the file "
        "could not be read. myav reports this instead of pretending the file is clean."
    )
    add("")
    return "\n".join(lines)


def _evidence(outcome: Outcome) -> str:
    if not outcome.verdict:
        return "no verdict"
    parts = []
    for result in outcome.verdict.results:
        if result.fired:
            parts.append(f"{result.engine}:{result.signature or result.status}")
    return "; ".join(parts) or "—"


def _counts(outcomes: Iterable[Outcome]) -> dict[str, int]:
    counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "UNKNOWN": 0, "CLEAN": 0, "skipped": 0, "scanned": 0}
    for outcome in outcomes:
        if outcome.skipped:
            counts["skipped"] += 1
            continue
        counts["scanned"] += 1
        counts[outcome.level] = counts.get(outcome.level, 0) + 1
    return counts


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def report_path(paths: Paths, kind: str, when: datetime | None = None) -> Path:
    stamp = (when or utcnow()).strftime("%Y-%m-%d-%H%M")
    return paths.reports_dir / f"{stamp}-{kind}.md"


def write_report(paths: Paths, context: ReportContext) -> Path:
    text = render_report(context)
    target = report_path(paths, context.kind, context.finished)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_text(text, encoding="utf-8")
    return target


def prune_reports(paths: Paths, retention: int) -> list[Path]:
    reports = sorted(paths.reports_dir.glob("*.md"))
    if len(reports) <= retention:
        return []
    removed = []
    for path in reports[: len(reports) - retention]:
        path.unlink(missing_ok=True)
        removed.append(path)
    return removed


def build_context(
    *,
    kind: str,
    started: datetime,
    outcomes: list[Outcome],
    engines,
    state: State,
    scope: list[Path] | None = None,
    extra_attention: list[str] | None = None,
) -> ReportContext:
    signature = engines.signature_info
    yara_status = engines.yara.status()
    vt_status = engines.virustotal.status()

    if signature.available:
        age = signature.age
        clam_state = (
            f"ClamAV {signature.version}, signatures {signature.db_version}, "
            f"age {human_age(age.total_seconds()) if age else 'unknown'}"
            + (" — **STALE**" if signature.stale else "")
        )
    else:
        clam_state = f"unavailable — {signature.detail or 'not installed'}"

    if yara_status["source"] == "missing":
        yara_state = "rules missing — run `myav rules fetch`"
    else:
        yara_state = f"{yara_status['rule_files']} rule files ({yara_status['source']})"

    if vt_status["configured"]:
        vt_state = (
            f"hash-only lookups enabled "
            f"({vt_status['requests_last_day']}/{vt_status['limits']['per_day']} today)"
        )
    else:
        vt_state = "not configured (optional) — verdicts rely on ClamAV + YARA"

    return ReportContext(
        kind=kind,
        started=started,
        finished=utcnow(),
        outcomes=outcomes,
        engine_state={
            "ClamAV": clam_state,
            "YARA": yara_state,
            "VirusTotal": vt_state,
            "Platform": f"{engines.platform.label} ({engines.platform.key})",
        },
        quarantine=state.list_quarantines(),
        attention=extra_attention or [],
        scope=scope or [],
    )
