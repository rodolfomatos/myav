"""Command-line interface.

Design rules for this file:

* it dispatches, it does not decide policy — the modules do;
* every command that needs a capability asks the platform adapter first;
* nothing runs ``sudo``; when root is required the command explains and exits 3;
* exit codes are part of the contract (docs/ARCHITECTURE.md §3 and docs/RUNBOOK.md):

  ====  ==========================================================
  0     success / everything clean
  1     command failed
  2     usage error (bad arguments, unknown ID)
  3     this platform cannot do that / root is required
  4     configuration is invalid or unsafe
  5     self-test inconclusive (e.g. Windows Defender removed EICAR)
  10    at least one file MALICIOUS
  11    at least one file SUSPICIOUS
  12    at least one file UNKNOWN (evidence missing)
  ====  ==========================================================
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, bootwatch
from .config import Config, ConfigError, write_api_key
from .intel import SUPPORTED_FORMATS as SUPPORTED_INTEL_FORMATS
from .paths import (
    Paths,
    UnsafeLocationError,
    default_paths,
    ensure_dirs,
)
from .pipeline import Engines, Outcome, build_engines, default_scope, scan_targets, walk_directory
from .platforms import Capability, Platform, detect_platform
from .progress import ProgressBar
from .quarantine import Quarantine, QuarantineError
from .report import ReportContext, build_context, render_report, write_report
from .rules import RulesError
from .rules import fetch as fetch_rules
from .rules import status as rules_status
from .scheduler import install as install_artifacts
from .scheduler import render as render_schedules
from .scheduler import status as schedule_status
from .selftest import run_eicar_selftest
from .state import State
from .util import display_path, format_bytes, human_age
from .watcher import Watcher

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_PLATFORM = 3
EXIT_CONFIG = 4
EXIT_INCONCLUSIVE = 5
EXIT_MALICIOUS = 10
EXIT_SUSPICIOUS = 11
EXIT_UNKNOWN = 12

_LEVEL_RANK = {"CLEAN": 0, "UNKNOWN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}
_LEVEL_EXIT = {
    "CLEAN": EXIT_OK,
    "UNKNOWN": EXIT_UNKNOWN,
    "SUSPICIOUS": EXIT_SUSPICIOUS,
    "MALICIOUS": EXIT_MALICIOUS,
}


class CapabilityError(RuntimeError):
    """The platform cannot do what was asked. Carries exit code 3."""


# --------------------------------------------------------------------------- context


@dataclass
class Context:
    config: Config
    paths: Paths
    state: State
    platform: Platform

    def engines(self) -> Engines:
        return build_engines(self.config, self.paths, self.state, self.platform)


def make_context(create_dirs: bool = True) -> Context:
    paths = default_paths()
    config = Config.load()
    platform = detect_platform()
    if create_dirs:
        ensure_dirs(paths)
    state = State(paths.state_db)
    return Context(config=config, paths=paths, state=state, platform=platform)


def require(ctx: Context, capability: Capability, command: str) -> None:
    if not ctx.platform.supports(capability):
        raise CapabilityError(
            f"`myav {command}` is not available on {ctx.platform.label}. {ctx.platform.notes}"
        )


# ------------------------------------------------------------------------- formatting


def _emit(payload: dict) -> None:
    print(json.dumps(payload, indent=2, default=str))


def _worst(outcomes: list[Outcome]) -> str:
    level = "CLEAN"
    for outcome in outcomes:
        candidate = outcome.level
        if _LEVEL_RANK[candidate] > _LEVEL_RANK[level]:
            level = candidate
    return level


def _outcome_line(outcome: Outcome) -> str:
    if outcome.skipped:
        return f"{'SKIP':<10} {display_path(outcome.path)} — {outcome.skipped}"
    detail = ""
    if outcome.verdict:
        fired = [r for r in outcome.verdict.results if r.fired]
        detail = ", ".join(f"{r.engine}: {r.signature or r.status}" for r in fired)
    if outcome.quarantined:
        detail = (detail + " " if detail else "") + f"[quarantined {outcome.quarantined.id[:8]}]"
    if outcome.error:
        detail = (detail + " " if detail else "") + outcome.error
    return f"{outcome.level:<10} {display_path(outcome.path)}" + (f" — {detail}" if detail else "")


def _print_outcomes(outcomes: list[Outcome], quiet: bool = False) -> None:
    if quiet:
        return
    for outcome in outcomes:
        print(_outcome_line(outcome))
    counts: dict[str, int] = {}
    for outcome in outcomes:
        key = "skipped" if outcome.skipped else outcome.level
        counts[key] = counts.get(key, 0) + 1
    summary = ", ".join(f"{count} {name.lower()}" for name, count in sorted(counts.items()))
    print("")
    print(f"{len(outcomes)} file(s): {summary or 'nothing to do'}")


def _outcome_payload(command: str, outcomes: list[Outcome], **extra) -> dict:
    worst = _worst(outcomes)
    return {
        "command": command,
        "exit_code": _LEVEL_EXIT[worst],
        "verdict": worst,
        "files": len(outcomes),
        "results": [outcome.as_dict() for outcome in outcomes],
        **extra,
    }


# ---------------------------------------------------------------------------- version


def cmd_version(args: argparse.Namespace) -> int:
    platform = detect_platform()
    text = f"myav {__version__} (Python {sys.version.split()[0]}, {platform.label})"
    if args.json:
        _emit(
            {
                "name": "myav",
                "version": __version__,
                "python": sys.version.split()[0],
                "platform": platform.key,
                "platform_label": platform.label,
            }
        )
    else:
        print(text)
    return EXIT_OK


def cmd_platforms(args: argparse.Namespace) -> int:
    """Show every adapter and what it can do. Useful before promising a platform."""
    current = detect_platform()
    rows = []
    for key in ("linux", "wsl", "macos", "windows", "android", "ios"):
        platform = detect_platform(env={**os.environ, "MYAV_PLATFORM": key})
        rows.append(platform)
    if args.json:
        _emit(
            {
                "current": current.key,
                "platforms": [
                    {**platform.as_dict(), "current": platform.key == current.key}
                    for platform in rows
                ],
            }
        )
        return EXIT_OK
    print(f"current platform: {current.label} ({current.key})")
    print("")
    print(f"{'key':<9} {'scheduler':<15} {'capabilities'}")
    print(f"{'-' * 9} {'-' * 15} {'-' * 40}")
    for platform in rows:
        mark = "*" if platform.key == current.key else " "
        caps = ", ".join(sorted(capability.value for capability in platform.capabilities)) or "none"
        print(f"{mark}{platform.key:<8} {platform.scheduler:<15} {caps}")
    print("")
    print("* = this machine. Capabilities are enforced: unavailable commands exit 3.")
    return EXIT_OK


# ----------------------------------------------------------------------------- doctor


def cmd_doctor(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    checks: list[tuple[str, str, str]] = []

    def add(status: str, label: str, detail: str = "") -> None:
        checks.append((status, label, detail))

    python_ok = sys.version_info >= (3, 10)
    add("ok" if python_ok else "fail", "Python >= 3.10", sys.version.split()[0])

    add(
        "ok" if ctx.platform.family != "unknown" else "fail",
        "Platform adapter",
        f"{ctx.platform.label} ({ctx.platform.key})",
    )

    bad_modes = []
    for directory in ctx.paths.all_dirs():
        try:
            mode = directory.stat().st_mode & 0o777
        except OSError as exc:
            bad_modes.append(f"{directory}: {exc}")
            continue
        if mode & 0o077:
            bad_modes.append(f"{display_path(directory)} is {mode:04o}")
    add("ok" if not bad_modes else "warn", "Private directories (0700)", "; ".join(bad_modes))

    clam = ctx.engines().clamav
    signature = clam.signature_info()
    if not clam.available():
        add("fail", "ClamAV", "not installed — run scripts/install-system.sh (see docs/INSTALL.md)")
    elif not signature.available:
        add("warn", "ClamAV", signature.detail or "version unknown")
    else:
        age = signature.age
        status = "warn" if signature.stale else "ok"
        add(
            status,
            "ClamAV signatures",
            f"version {signature.db_version}, "
            f"age {human_age(age.total_seconds()) if age else 'unknown'}",
        )

    yara_binary = shutil.which("yara")
    ystat = rules_status(ctx.paths)
    if not yara_binary:
        add("warn", "YARA", "yara not installed — YARA stage will be skipped")
    elif not ystat["rule_files"]:
        add("warn", "YARA rules", "none fetched — run `myav rules fetch --accept-license`")
    else:
        add(
            "ok", "YARA rules", f"{ystat['rule_files']} files, compiled={ystat.get('cache_exists')}"
        )

    vt = ctx.config.virustotal
    if vt.enabled and vt.api_key:
        add("ok", "VirusTotal", "hash-only lookups enabled")
    else:
        add("warn", "VirusTotal", "not configured (optional) — see docs/CONFIGURATION.md")

    free = shutil.disk_usage(str(ctx.paths.state_dir)).free
    add("ok" if free > 1024**3 else "warn", "Free space for quarantine", format_bytes(free))

    if ctx.platform.is_wsl:
        windows = Path("/mnt/c")
        if windows.exists():
            c_free = shutil.disk_usage(str(windows)).free
            add(
                "warn" if c_free < 1024**3 else "ok",
                "Windows C: free space",
                f"{format_bytes(c_free)} (myav never writes there)",
            )
        systemd = _systemd_state()
        add("ok" if systemd != "offline" else "warn", "systemd", systemd)
    else:
        add("ok", "Scheduler", ctx.platform.scheduler)

    install_state = schedule_status(ctx.platform, _install_root(), _user())
    installed = install_state.get("installed", [])
    add(
        "ok" if installed else "warn",
        "Scheduled jobs",
        ", ".join(installed) if installed else "not installed — run `myav schedules install`",
    )

    baseline_ts = ctx.state.get_baseline_established_at()
    add(
        "ok" if baseline_ts else "warn",
        "Baseline scan",
        baseline_ts if baseline_ts else "not established — run `myav baseline`",
    )

    failed = sum(1 for status, _label, _detail in checks if status == "fail")
    warned = sum(1 for status, _label, _detail in checks if status == "warn")

    if args.json:
        _emit(
            {
                "command": "doctor",
                "exit_code": EXIT_FAIL if failed else EXIT_OK,
                "failed": failed,
                "warned": warned,
                "checks": [
                    {"status": status, "check": label, "detail": detail}
                    for status, label, detail in checks
                ],
            }
        )
        return EXIT_FAIL if failed else EXIT_OK

    print("myav doctor")
    print("")
    for status, label, detail in checks:
        mark = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}[status]
        print(f"{mark}  {label}" + (f": {detail}" if detail else ""))
    print("")
    if failed:
        print(f"{failed} problem(s) must be fixed before myav can protect this machine.")
    elif warned:
        print(f"Healthy, with {warned} warning(s). Read docs/RUNBOOK.md for what each means.")
    else:
        print("Everything myav depends on is present and fresh.")
    return EXIT_FAIL if failed else EXIT_OK


# ----------------------------------------------------------------------------- config


def cmd_config(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    if args.action == "path":
        print(ctx.paths.config_file)
        return EXIT_OK

    if args.action == "show":
        payload = ctx.config.public_dict(redact=not args.reveal)
        if args.json:
            _emit({"command": "config-show", **payload})
        else:
            print(json.dumps(payload, indent=2, default=str))
        return EXIT_OK

    # set-vt-key
    key = args.key
    if not key:
        key = os.environ.get("MYAV_VT_API_KEY", "").strip()
    if not key:
        print(
            "Paste your VirusTotal API key (it is not echoed, and it never leaves this "
            "machine except as the x-apikey header on hash lookups).\n"
            "Get one free at https://www.virustotal.com/gui/my-apikey — docs/CONFIGURATION.md "
            "walks through it."
        )
        try:
            import getpass

            key = getpass.getpass("API key: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled; nothing was written.")
            return EXIT_USAGE
    key = key.strip()
    if len(key) != 64 or any(character not in "0123456789abcdefABCDEF" for character in key):
        print(
            "That does not look like a VirusTotal API key. A VT key is exactly 64 "
            "hexadecimal characters (0-9, a-f). Nothing was written.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    target = write_api_key(ctx.paths, key)
    print(f"Wrote {target} (mode 0600).")
    print("VirusTotal will now be asked about file *hashes* only — never file contents.")
    print("Check with: myav doctor")
    return EXIT_OK


# ------------------------------------------------------------------------------- scan


def cmd_scan(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    require(ctx, Capability.SCAN_FILES, "scan")
    targets = [Path(item).expanduser() for item in args.paths]
    missing = [target for target in targets if not target.exists()]
    if missing:
        for target in missing:
            print(f"myav: no such file or directory: {target}", file=sys.stderr)
        return EXIT_USAGE

    engines = ctx.engines()
    started = _now()
    outcomes = list(
        scan_targets(
            targets,
            ctx.config,
            ctx.paths,
            ctx.state,
            engines,
            kind=args.kind,
            dry_run=args.dry_run,
        )
    )
    if args.report:
        context = build_context(
            kind=args.kind,
            started=started,
            outcomes=outcomes,
            engines=engines,
            state=ctx.state,
            scope=targets,
            quarantine_budget_bytes=ctx.config.quarantine.budget_bytes,
            blocked_count=0,
        )
        _finish_report(ctx, context)
    if args.json:
        _emit(_outcome_payload("scan", outcomes))
    else:
        _print_outcomes(outcomes)
        if args.dry_run:
            print("dry run: nothing was quarantined")
    return _LEVEL_EXIT[_worst(outcomes)]


def cmd_full_scan(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    require(ctx, Capability.SCAN_FILES, "full-scan")
    if args.paths:
        targets = [Path(item).expanduser() for item in args.paths]
    else:
        targets = default_scope(ctx.config, ctx.platform)
    existing = [target for target in targets if target.exists()]
    if not existing:
        print(
            "Nothing to scan: none of the configured folders exist "
            f"({', '.join(display_path(t) for t in targets) or 'no scope'}).",
            file=sys.stderr,
        )
        return EXIT_FAIL

    show_progress = args.progress and not args.json and not args.quiet

    # Count total files for the progress denominator.
    total = 0
    if show_progress:
        for target in existing:
            if target.is_dir():
                total += sum(1 for _ in walk_directory(target, ctx.config))
            elif target.is_file():
                total += 1

    bar = ProgressBar(total) if show_progress else None

    engines = ctx.engines()
    started = _now()
    scanned = 0
    outcomes = []
    for outcome in scan_targets(
        existing,
        ctx.config,
        ctx.paths,
        ctx.state,
        engines,
        kind="full",
        dry_run=args.dry_run,
    ):
        scanned += 1
        if bar:
            bar.update(scanned, label=str(outcome.path))
        outcomes.append(outcome)
    if bar:
        bar.close()

    context = build_context(
        kind="full",
        started=started,
        outcomes=outcomes,
        engines=engines,
        state=ctx.state,
        scope=existing,
        quarantine_budget_bytes=ctx.config.quarantine.budget_bytes,
        blocked_count=0,
    )
    target = _finish_report(ctx, context)
    if args.json:
        _emit(_outcome_payload("full-scan", outcomes, report=str(target)))
    else:
        print(render_report(context))
        print(f"Report saved to {display_path(target)}")
    return _LEVEL_EXIT[_worst(outcomes)]


def _finish_report(ctx: Context, context: ReportContext) -> Path:
    target = write_report(ctx.paths, context)
    prune = getattr(ctx.config.report, "retention", 0)
    if prune:
        from .report import prune_reports

        prune_reports(ctx.paths, prune)
    return target


# --------------------------------------------------------------------------- baseline


def cmd_baseline(args: argparse.Namespace) -> int:
    """Baseline scan: scans all pre-existing files in the default scope and records
    the result as kind="baseline", establishing a point-in-time snapshot the operator
    can compare future scans against."""
    ctx = make_context(create_dirs=True)
    require(ctx, Capability.SCAN_FILES, "baseline")
    if args.paths:
        targets = [Path(item).expanduser() for item in args.paths]
    else:
        targets = default_scope(ctx.config, ctx.platform)
    existing = [target for target in targets if target.exists()]
    if not existing:
        print(
            "Nothing to baseline: none of the configured folders exist "
            f"({', '.join(display_path(t) for t in targets) or 'no scope'}).",
            file=sys.stderr,
        )
        return EXIT_FAIL

    engines = ctx.engines()
    started = _now()
    outcomes = list(
        scan_targets(
            existing,
            ctx.config,
            ctx.paths,
            ctx.state,
            engines,
            kind="baseline",
            dry_run=args.dry_run,
        )
    )
    context = build_context(
        kind="baseline",
        started=started,
        outcomes=outcomes,
        engines=engines,
        state=ctx.state,
        scope=existing,
    )
    target = _finish_report(ctx, context)

    # Record when the baseline was established.
    ctx.state.set_baseline_established_at(context.finished.isoformat())

    if args.json:
        _emit(
            _outcome_payload("baseline", outcomes, report=str(target),
                             baseline_established_at=context.finished.isoformat())
        )
    else:
        print(render_report(context))
        print(f"Report saved to {display_path(target)}")
        print("")
        print(f"Baseline established at {context.finished.isoformat(timespec='seconds')}.")
        print("Compare future scans against this snapshot with `myav full-scan`.")
    return _LEVEL_EXIT[_worst(outcomes)]


# ---------------------------------------------------------------------- notify


def cmd_notify(args: argparse.Namespace) -> int:
    """Show a toast notification. Windows-only (gated on Capability.TOAST); other
    platforms exit 3 with a clear message."""
    ctx = make_context(create_dirs=False)
    require(ctx, Capability.TOAST, "notify")

    payload = {
        "command": "notify",
        "title": args.title,
        "message": args.message,
        "platform": ctx.platform.key,
    }
    if args.json:
        _emit({**payload, "exit_code": EXIT_OK, "toast": "would-show-on-windows"})
        return EXIT_OK
    print(f"[toast] {args.title}: {args.message}")
    print("(On Windows this renders as a native toast notification.)")
    return EXIT_OK


# ----------------------------------------------------------------------------- intel


def cmd_intel(args: argparse.Namespace) -> int:
    """Manage the offline threat-intel cache. Scans never touch the network."""
    from .engines.intel_engine import IntelEngine
    from .intel import IntelError, normalise_indicator, update_from_source

    ctx = make_context(create_dirs=False)

    if args.action == "status":
        payload = IntelEngine(ctx.config.intel, ctx.state).status()
        payload["feed_list"] = ctx.state.intel_feeds()
        if args.json:
            _emit({"command": "intel-status", **payload})
            return EXIT_OK
        print(
            f"Intel cache: {payload['ioc_count']} indicator(s) "
            f"from {payload['sources']} source(s)"
        )
        if payload["by_type"]:
            for ioc_type, count in payload["by_type"].items():
                print(f"  {ioc_type:<8} {count}")
        if payload["feed_list"]:
            print(f"Feeds ({len(payload['feed_list'])}):")
            for feed in payload["feed_list"]:
                print(
                    f"  {feed['name']:<20} {feed['format']:<18} "
                    f"{feed['ioc_count']:>6} ioc(s)  {feed['updated_at']}"
                )
        else:
            print("Feeds: none — run `myav intel update` or `myav intel import`.")
        state = "enabled" if payload["enabled"] else "disabled"
        print(f"Pipeline engine: {state} ([intel].enabled)")
        return EXIT_OK

    if args.action in ("update", "import"):
        source = getattr(args, "source", None) or getattr(args, "path", None)
        if not source:
            print("myav: no feed source given", file=sys.stderr)
            return EXIT_USAGE
        try:
            result = update_from_source(
                ctx.state,
                name=args.name,
                source=source,
                fmt=args.format,
                confidence=args.confidence,
                timeout=ctx.config.intel.timeout,
            )
        except IntelError as exc:
            print(f"myav: {exc}", file=sys.stderr)
            return EXIT_FAIL
        if args.json:
            _emit({"command": "intel-update", **result.to_dict()})
            return EXIT_OK
        print(
            f"Imported {result.ioc_count} indicator(s) from {result.name} "
            f"({result.format})"
        )
        print("Scans consult this cache offline; no network I/O happens during a scan.")
        return EXIT_OK

    if args.action == "check":
        try:
            ioc_type, value = normalise_indicator(args.indicator)
        except ValueError as exc:
            print(f"myav: {exc}", file=sys.stderr)
            return EXIT_USAGE
        hits = ctx.state.lookup_intel(ioc_type, value)
        if args.json:
            _emit(
                {
                    "command": "intel-check",
                    "type": ioc_type,
                    "value": value,
                    "found": bool(hits),
                    "hits": hits,
                }
            )
            return EXIT_OK if hits else EXIT_FAIL
        if not hits:
            print(f"not found: {ioc_type} {value}")
            return EXIT_FAIL
        print(f"found: {ioc_type} {value}")
        for hit in hits:
            tags = ", ".join(hit["tags"]) if hit["tags"] else "—"
            print(
                f"  {hit['source']}  confidence {hit['confidence']}  "
                f"tags: {tags}  last seen {hit['last_seen']}"
            )
        return EXIT_OK

    if args.action == "clear":
        if not args.yes:
            print(
                "myav: refusing to clear the intel cache without --yes",
                file=sys.stderr,
            )
            return EXIT_USAGE
        removed = ctx.state.clear_intel()
        if args.json:
            _emit({"command": "intel-clear", "removed": removed})
        else:
            print(f"Removed {removed} cached indicator(s) and all feed records.")
        return EXIT_OK

    print(f"myav: unknown intel action: {args.action}", file=sys.stderr)
    return EXIT_USAGE


# ------------------------------------------------------------------------------ rules


def cmd_rules(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    if args.action == "status":
        payload = rules_status(ctx.paths)
        if args.json:
            _emit({"command": "rules-status", **payload})
        else:
            print(f"rules directory: {payload['rules_dir']}")
            print(f"rule files:      {payload['rule_files']}")
            print(f"compiled cache:  {'yes' if payload['cache_exists'] else 'no'}")
            if payload.get("commit"):
                print(f"pinned commit:   {payload['commit']}")
                print(f"archive sha256:  {payload.get('archive_sha256', '')[:16]}…")
                print(f"licence:         {payload.get('license', '')}")
            else:
                print("provenance:      missing — run `myav rules fetch --accept-license`")
        return EXIT_OK

    if args.action == "refresh":
        return _cmd_rules_refresh(ctx, args.json)

    result = fetch_rules(ctx.paths, accept_license=args.accept_license, update=args.update)
    if args.json:
        _emit({"command": "rules-fetch", **result})
    else:
        if result.get("changed"):
            print(
                f"Fetched {result['rule_files']} rule files from "
                f"{result['repo']}@{result['commit'][:12]}"
            )
            print(f"archive sha256: {result['archive_sha256']}")
            compile_info = result.get("compile", {})
            if compile_info.get("compiled"):
                print(f"compiled {compile_info.get('rules', 0)} rule file(s) into a YARA cache")
            else:
                print(f"not compiled: {compile_info.get('reason', 'unknown reason')}")
            skipped = result.get("skipped_rules", [])
            if skipped:
                print(
                    f"{len(skipped)} rule file(s) failed to compile and were "
                    "skipped (kept on disk):"
                )
                for item in skipped[:5]:
                    print(f"  - {item['file']}: {item['error'][:80]}")
        else:
            print("Rules are already pinned. Use --update to fetch a newer pack.")
    return EXIT_OK


def _cmd_rules_refresh(ctx, json_output: bool = False) -> int:
    """Refresh the YARA pack and show a rule-diff against the previous pin."""

    # --- before: snapshot current state ---
    rules_dir = ctx.paths.rules_dir
    before_files = set()
    if rules_dir.exists():
        before_files = {
            p.relative_to(rules_dir).as_posix()
            for p in rules_dir.rglob("*")
            if p.is_file() and p.suffix in {".yar", ".yara"}
        }
    before_commit = None
    prov_path = rules_dir / "PROVENANCE.json"
    if prov_path.exists():
        import json as _json

        try:
            prov = _json.loads(prov_path.read_text(encoding="utf-8"))
            before_commit = prov.get("commit")
        except (ValueError, OSError):
            pass

    # --- fetch newer pack ---
    result = fetch_rules(ctx.paths, accept_license=True, update=True)

    # --- after: snapshot new state ---
    after_files = set()
    if rules_dir.exists():
        after_files = {
            p.relative_to(rules_dir).as_posix()
            for p in rules_dir.rglob("*")
            if p.is_file() and p.suffix in {".yar", ".yara"}
        }

    added = sorted(after_files - before_files)
    removed = sorted(before_files - after_files)
    unchanged = after_files & before_files

    if json_output:
        payload = {
            "command": "rules-refresh",
            "changed": result.get("changed", False),
            "before_commit": before_commit,
            "after_commit": result.get("commit"),
            "before_rule_count": len(before_files),
            "after_rule_count": len(after_files),
            "added": added,
            "removed": removed,
            "unchanged_count": len(unchanged),
        }
        _emit(payload)
        return EXIT_OK

    if not result.get("changed"):
        print("Rules are already up to date. No refresh needed.")
        return EXIT_OK

    print(f"YARA pack refreshed: {before_commit or 'unknown'} → {result['commit'][:12]}")
    print(f"Rule files: {len(before_files)} → {len(after_files)}")
    if added:
        print(f"\nAdded ({len(added)}):")
        for f in added[:10]:
            print(f"  + {f}")
        if len(added) > 10:
            print(f"  ... and {len(added) - 10} more")
    if removed:
        print(f"\nRemoved ({len(removed)}):")
        for f in removed[:10]:
            print(f"  - {f}")
        if len(removed) > 10:
            print(f"  ... and {len(removed) - 10} more")
    if not added and not removed:
        print("No rule files changed (only metadata updated).")
    compile_info = result.get("compile", {})
    if compile_info.get("compiled"):
        print(f"\nCompiled {compile_info.get('rules', 0)} rule file(s) into YARA cache")
    else:
        print(f"\nNot compiled: {compile_info.get('reason', 'unknown reason')}")
    return EXIT_OK


# ------------------------------------------------------------------------- quarantine


def cmd_quarantine(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    require(ctx, Capability.QUARANTINE, "quarantine")
    quarantine = Quarantine(ctx.paths, ctx.state, ctx.config)

    if args.action == "list":
        records = ctx.state.list_quarantines(include_restored=args.all)
        if args.json:
            _emit(
                {
                    "command": "quarantine-list",
                    "records": [record.__dict__ for record in records],
                }
            )
            return EXIT_OK
        if not records:
            print("Quarantine is empty. Nothing has been moved.")
            return EXIT_OK
        print(f"{'id':<10} {'state':<9} {'tag':<10} {'size':>8}  original location")
        print(f"{'-' * 10} {'-' * 9} {'-' * 10} {'-' * 8}  {'-' * 40}")
        for record in records:
            print(
                f"{record.id[:8]:<10} {record.state:<9} {record.tag:<10} "
                f"{format_bytes(record.size):>8}  {display_path(Path(record.original_path))}"
            )
        print("")
        print("Restore one with: myav quarantine restore <id>")
        return EXIT_OK

    if args.action == "budget":
        total = ctx.state.quarantine_total_size()
        budget = ctx.config.quarantine.budget_bytes
        if args.set is not None:
            ctx.config.quarantine.budget_bytes = args.set
            budget = args.set
            # Persist to config file.
            target = ctx.paths.config_file
            existing = ""
            if target.exists():
                existing = target.read_text(encoding="utf-8")
            if "[quarantine]" in existing:
                lines = []
                in_q = False
                saw_budget = False
                for line in existing.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("[") and stripped.endswith("]"):
                        in_q = stripped == "[quarantine]"
                        lines.append(line)
                        continue
                    if in_q and stripped.startswith("budget_bytes"):
                        lines.append(f"budget_bytes = {args.set}")
                        saw_budget = True
                    else:
                        lines.append(line)
                if not saw_budget and in_q:
                    lines.append(f"budget_bytes = {args.set}")
            else:
                lines = [existing.rstrip("\n")] if existing else []
                lines.append("")
                lines.append("[quarantine]")
                lines.append(f"budget_bytes = {args.set}")
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
            os.chmod(target, 0o600)
            print(f"Quarantine budget set to {format_bytes(args.set)}.")
            if args.json:
                _emit(
                    {
                        "command": "quarantine-budget",
                        "total_bytes": total,
                        "budget_bytes": args.set,
                        "set": True,
                    }
                )
            return EXIT_OK
        if args.json:
            _emit(
                {
                    "command": "quarantine-budget",
                    "total_bytes": total,
                    "budget_bytes": budget,
                    "usage_percent": round(total / budget * 100, 1) if budget else None,
                }
            )
            return EXIT_OK
        if budget is None:
            print(f"Quarantine total: {format_bytes(total)}")
            print("No budget set. Set one with: myav quarantine budget --set <bytes>")
            return EXIT_OK
        usage = total / budget * 100
        print(f"Quarantine total: {format_bytes(total)}")
        print(f"Budget:           {format_bytes(budget)}")
        print(f"Usage:            {usage:.1f}%")
        return EXIT_OK

    if args.action == "rotate":
        purged = quarantine.rotate()
        if args.json:
            _emit({"command": "quarantine-rotate", "purged": purged})
            return EXIT_OK
        if purged:
            suffix = "y" if purged == 1 else "ies"
            print(f"Rotated {purged} quarantine entr{suffix} (oldest first).")
        else:
            print("Quarantine is within budget. Nothing rotated.")
        return EXIT_OK

    if args.action == "restore":
        target = Path(args.to).expanduser() if args.to else None
        restored = quarantine.restore(args.id, target=target, force=args.force)
        print(f"Restored to {restored}")
        print("The file was hash-verified before and after the restore.")
        return EXIT_OK

    # purge
    removed = quarantine.purge(args.id, yes=args.yes)
    if removed:
        print(f"Deleted quarantine entry {args.id}. This action cannot be undone.")
        return EXIT_OK
    return EXIT_OK


# -------------------------------------------------------------------------- allowlist


def cmd_allow(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    if args.action == "list":
        rows = ctx.state.list_allowlist()
        if args.json:
            _emit({"command": "allow-list", "records": rows})
            return EXIT_OK
        if not rows:
            print("Allowlist is empty.")
            return EXIT_OK
        for row in rows:
            print(f"{row['sha256'][:16]}…  {row['path'] or '-'}  {row['reason'] or ''}")
        return EXIT_OK

    if args.action == "add":
        from .hashutil import sha256_file

        target = Path(args.path).expanduser()
        if not target.is_file():
            print(f"myav: not a regular file: {target}", file=sys.stderr)
            return EXIT_USAGE
        digest = sha256_file(target)
        ctx.state.allow(digest, str(target.absolute()), args.reason or "")
        if args.json:
            _emit(
                {
                    "command": "allow-add",
                    "sha256": digest,
                    "path": str(target.absolute()),
                    "reason": args.reason or "",
                }
            )
            return EXIT_OK
        print(f"Allowlisted {display_path(target)}")
        print(f"sha256 {digest}")
        print("Future scans of this exact content will be CLEAN. Delete the file to revoke.")
        return EXIT_OK

    # remove
    digest = args.hash
    if args.path:
        from .hashutil import sha256_file

        target = Path(args.path).expanduser()
        if not target.is_file():
            print(f"myav: not a regular file: {target}", file=sys.stderr)
            return EXIT_USAGE
        digest = sha256_file(target)

    if digest is None:
        if args.json:
            _emit(
                {
                    "command": "allow-remove",
                    "sha256": None,
                    "removed": False,
                    "error": "no hash or path provided",
                }
            )
            return EXIT_USAGE
        print("myav: provide a sha256 hash or --path to a file.", file=sys.stderr)
        return EXIT_USAGE

    short = digest[:16] + "…"
    if not ctx.state.disallow(digest):
        if args.json:
            _emit(
                {
                    "command": "allow-remove",
                    "sha256": digest,
                    "removed": False,
                    "error": "not allowlisted",
                }
            )
            return EXIT_USAGE
        print(f"sha256 {short} was not allowlisted.", file=sys.stderr)
        return EXIT_USAGE

    shown = display_path(Path(args.path)) if args.path else short
    if args.json:
        _emit({"command": "allow-remove", "sha256": digest, "removed": True})
        return EXIT_OK
    print(f"Removed {shown} from the allowlist.")
    return EXIT_OK


# ----------------------------------------------------------------------------- report


def cmd_report(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=False)
    reports = sorted(ctx.paths.reports_dir.glob("*.md"))
    if args.list:
        if args.json:
            _emit(
                {
                    "command": "report-list",
                    "reports": [str(p) for p in reports],
                }
            )
            return EXIT_OK
        if not reports:
            print("No reports yet. Run `myav full-scan`.")
            return EXIT_OK
        for path in reports:
            print(display_path(path))
        return EXIT_OK
    if not reports:
        print("No reports yet. Run `myav full-scan`.", file=sys.stderr)
        return EXIT_FAIL
    target = reports[-1] if not args.path else Path(args.path).expanduser()
    if not target.exists():
        print(f"myav: no such report: {target}", file=sys.stderr)
        return EXIT_USAGE
    if args.json:
        _emit(
            {
                "command": "report",
                "path": str(target),
                "content": target.read_text(encoding="utf-8"),
            }
        )
        return EXIT_OK
    print(target.read_text(encoding="utf-8"))
    return EXIT_OK


# ------------------------------------------------------------------------------- boot


def cmd_completion(args: argparse.Namespace) -> int:
    """Emit a shell completion script for bash.

    Source it with:  source <(myav completion)
    """
    shell = args.shell or "bash"
    if shell == "bash":
        script = (
            "_myav_completion() {\n"
            "    local cur prev opts\n"
            "    COMPREPLY=()\n"
            "    cur=\"${COMP_WORDS[COMP_CWORD]}\"\n"
            "    prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n"
            "    opts=\"version platforms doctor config scan full-scan rules quarantine allow "
            "report boot watch selftest update-signatures clamd-start schedules notify "
            "completion baseline help\"\n"
            "\n"
            "    if [[ ${cur} == -* ]] ; then\n"
            "        COMPREPLY=( $(compgen -W \"--help --json --yes --dry-run --force --no-clamd "
            "--accept-license --update --set --list --all --path --to --force --reason "
            "--kind --dry-run --report --shell --reveal\" -- ${cur}) )\n"
            "    else\n"
            "        COMPREPLY=( $(compgen -W \"${opts}\" -- ${cur}) )\n"
            "    fi\n"
            "    return 0\n"
            "}\n"
            "complete -o default -o nospace -F _myav_completion myav\n"
        )
    elif shell == "zsh":
        script = (
            "#compdef myav\n"
            "_myav_completion() {\n"
            "    local -a commands\n"
            "    commands=(version platforms doctor config scan full-scan rules quarantine allow "
            "report boot watch selftest update-signatures clamd-start schedules notify "
            "completion baseline help)\n"
            "    _describe 'commands' commands\n"
            "}\n"
            "compdef _myav_completion myav\n"
        )
    else:
        print(f"myav: unsupported shell for completion: {shell}", file=sys.stderr)
        return EXIT_USAGE

    if args.json:
        _emit({"command": "completion", "shell": shell, "script": script})
        return EXIT_OK
    print(script, end="")
    return EXIT_OK


def cmd_boot(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    require(ctx, Capability.STARTUP_INVENTORY, "boot")
    result = bootwatch.check(ctx.state, ctx.platform)
    new = result["new"]
    if args.json:
        _emit({"command": "boot", **result, "exit_code": EXIT_SUSPICIOUS if new else EXIT_OK})
        return EXIT_SUSPICIOUS if new else EXIT_OK

    print(f"Startup entries seen: {result['entries']}")
    if result["first_run"]:
        print("First run: this is now the baseline. Nothing is flagged yet.")
    elif new:
        print("")
        print("NEW since the last check — look at these:")
        for entry in new:
            print(f"  + {entry['name']}  ({entry['location']})")
            if entry.get("command"):
                print(f"    {entry['command']}")
    else:
        print("No new startup entries since the last check.")
    if result["removed"]:
        print(f"{len(result['removed'])} entry(ies) disappeared (uninstalled, or disabled).")
    for note in result["notes"]:
        print(f"note: {note}")
    print("")
    print("myav never disables a startup entry. Decide yourself; docs/RUNBOOK.md explains how.")
    return EXIT_SUSPICIOUS if new else EXIT_OK


# ------------------------------------------------------------------------------ watch


def cmd_watch(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    require(ctx, Capability.WATCH_FILES, "watch")
    engines = ctx.engines()
    watcher = Watcher(
        ctx.config,
        ctx.paths,
        ctx.state,
        engines,
        ctx.platform,
        block_on_malicious=args.watch_block,
    )
    started = _now()
    stats = watcher.run(once=args.once, create_dirs=args.create_dirs)
    outcomes = list(stats.outcomes)

    context = build_context(
        kind="watch",
        started=started,
        outcomes=outcomes,
        engines=engines,
        state=ctx.state,
        scope=stats.roots,
        extra_attention=[f"watcher: {stats.dropped} event(s) dropped (queue full)"]
        if stats.dropped
        else [],
        quarantine_budget_bytes=ctx.config.quarantine.budget_bytes,
        blocked_count=stats.blocked,
    )
    target = _finish_report(ctx, context)
    if args.json:
        _emit(
            {
                "command": "watch",
                "exit_code": _LEVEL_EXIT[_worst(outcomes)] if outcomes else EXIT_OK,
                "roots": [str(root) for root in stats.roots],
                "queued": stats.queued,
                "scanned": stats.scanned,
                "errors": stats.errors,
                "dropped": stats.dropped,
                "blocked": stats.blocked,
                "report": str(target),
                "results": [outcome.as_dict() for outcome in outcomes],
            }
        )
    else:
        print(f"Watched: {', '.join(display_path(root) for root in stats.roots) or 'nothing'}")
        print(
            f"Scanned {stats.scanned} file(s), {stats.errors} error(s), "
            f"{stats.dropped} dropped, {stats.blocked} blocked."
        )
        if outcomes:
            _print_outcomes(outcomes)
        print(f"Report: {display_path(target)}")
    return EXIT_OK


# ---------------------------------------------------------------------------- selftest


def cmd_selftest(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    engines = ctx.engines()
    result = run_eicar_selftest(ctx.config, ctx.paths, ctx.state, engines)
    if args.json:
        _emit({"command": "selftest", **result.as_dict(), "exit_code": result.exit_code})
    else:
        print(result.render())
        if result.inconclusive:
            print("")
            print(
                "This is not a myav bug. Read the INCONCLUSIVE line above before changing anything."
            )
    return result.exit_code


# --------------------------------------------------------------------- research


def cmd_research(args: argparse.Namespace) -> int:
    """Research-track commands. These are measurement tools only — nothing here
    ships as MYAV Core protection. See docs/RESEARCH_TRACK.md."""
    if args.action == "fp-baseline":
        return _cmd_research_fp_baseline(args)
    if args.action == "behaviour-baseline":
        return _cmd_research_behaviour_baseline(args)
    if args.action == "behaviour-detect":
        return _cmd_research_behaviour_detect(args)
    if args.action == "ml-baseline":
        return _cmd_research_ml_baseline(args)
    if args.action == "sandbox":
        return _cmd_research_sandbox(args)
    if args.action == "campaign-graph":
        return _cmd_research_campaign_graph(args)
    if args.action == "gui":
        return _cmd_research_gui(args)
    if args.action == "honesty-dashboard":
        return _cmd_research_honesty_dashboard(args)
    print(f"myav: unknown research action: {args.action}", file=sys.stderr)
    return EXIT_USAGE


def _cmd_research_fp_baseline(args: argparse.Namespace) -> int:
    """Measure the false-positive rate on a corpus of known-good files, and
    optionally the false-negative rate on a corpus of known-bad files.

    Read-only: scans directories with dry-run semantics (nothing quarantined,
    nothing mutated) and reports false-positive rate, false-negative rate and
    a confusion matrix. A temporary state database is used so the user's real
    state is untouched.
    """
    directory = Path(args.directory).expanduser()
    if not directory.is_dir():
        print(
            f"myav: not a directory: {directory}", file=sys.stderr
        )
        return EXIT_USAGE

    malicious_dir = None
    if args.malicious_dir is not None:
        malicious_dir = Path(args.malicious_dir).expanduser()
        if not malicious_dir.is_dir():
            print(
                f"myav: not a directory: {malicious_dir}", file=sys.stderr
            )
            return EXIT_USAGE

    ctx = make_context(create_dirs=True)
    engines = ctx.engines()

    from .research.fp_baseline import measure_fp_fn

    result = measure_fp_fn(
        directory,
        ctx.config,
        ctx.paths,
        engines,
        malicious_dir=malicious_dir,
    )

    c = result.confusion
    if args.json:
        payload = {
            "command": "research-fp-baseline",
            "clean_dir": result.clean_dir,
            "malicious_dir": result.malicious_dir,
            "total_scanned": c.total,
            "true_negative": c.true_negative,
            "false_positive": c.false_positive,
            "false_negative": c.false_negative,
            "true_positive": c.true_positive,
            "false_positive_rate": round(c.false_positive_rate, 4),
            "false_negative_rate": round(c.false_negative_rate, 4),
            "precision": round(c.precision, 4),
            "recall": round(c.recall, 4),
            "clean_details": result.clean_details,
            "malicious_details": result.malicious_details,
        }
        _emit(payload)
        return EXIT_OK

    print(f"Honest measurement: {result.clean_dir}")
    if result.malicious_dir:
        print(f"Malicious corpus:   {result.malicious_dir}")
    print("")
    print("Confusion matrix:")
    print(f"  True negative  (clean, not flagged):  {c.true_negative}")
    print(f"  False positive (clean, flagged):      {c.false_positive}")
    print(f"  False negative (malicious, missed):   {c.false_negative}")
    print(f"  True positive  (malicious, flagged):  {c.true_positive}")
    print("")
    print(f"  Files scanned (clean):   {c.total_clean}")
    print(f"  Files scanned (malicious): {c.total_malicious}")
    print(f"  Total files scanned:     {c.total}")
    print("")
    print(f"  False positive rate:  {c.false_positive_rate:.2f}%")
    print(f"  False negative rate:  {c.false_negative_rate:.2f}%")
    print(f"  Precision:            {c.precision:.2f}%")
    print(f"  Recall:               {c.recall:.2f}%")
    print("")
    print(
        "This is a research measurement, not a detection verdict. "
        "False positives and false negatives must both be inspected before "
        "drawing conclusions about detection quality."
    )
    if result.clean_details:
        print("")
        print("False positives (clean files flagged):")
        for item in result.clean_details:
            print(f"  {item['level']:<11} {item['path']}  ({item['evidence']})")
    if result.malicious_details:
        print("")
        print("False negatives (malicious files missed):")
        # malicious_details currently contains flagged malicious files (true
        # positives); false negatives are the unflagged ones, which are not
        # individually listed here because they produced no engine output.
        print(
            f"  {c.false_negative} malicious file(s) were not flagged by any engine."
        )
    return EXIT_OK


def _cmd_research_behaviour_baseline(args: argparse.Namespace) -> int:
    """Learn a behaviour baseline from *directory* and/or check current
    activity against a previously learned baseline.

    Read-only: scans the directory with dry-run semantics (nothing quarantined,
    nothing mutated) and reports deviations from the learned baseline. Never
    blocks.
    """
    directory = Path(args.directory).expanduser()
    if not directory.is_dir():
        print(
            f"myav: not a directory: {directory}", file=sys.stderr
        )
        return EXIT_USAGE

    if args.learn and args.check:
        print(
            "myav: specify only one of --learn or --check", file=sys.stderr
        )
        return EXIT_USAGE
    if not args.learn and not args.check:
        print(
            "myav: specify --learn or --check", file=sys.stderr
        )
        return EXIT_USAGE

    ctx = make_context(create_dirs=True)
    engines = ctx.engines()

    from .research.behaviour_baseline import run_behaviour_baseline

    result = run_behaviour_baseline(
        directory,
        ctx.config,
        ctx.paths,
        ctx.state,
        engines,
        learn=args.learn,
        check=args.check,
    )

    if args.json:
        payload = {
            "command": "research-behaviour-baseline",
            "directory": str(directory.resolve()),
            "learn": args.learn,
            "check": args.check,
            "baseline_learned": result.baseline_learned,
            "total_observations": result.total_observations,
            "deviation_count": result.deviation_count,
            "deviation_rate": round(result.deviation_rate, 4),
        }
        if result.baseline:
            payload["baseline"] = result.baseline.to_dict()
        if result.deviations:
            payload["deviations"] = [
                {"type": d.type, "value": d.value} for d in result.deviations
            ]
        _emit(payload)
        return EXIT_OK

    if args.learn:
        b = result.baseline
        print(f"Behaviour baseline learned: {directory.resolve()}")
        print(f"  Observations:  {result.total_observations}")
        print(f"  Processes:     {', '.join(sorted(b.processes)) or 'none'}")
        print(f"  Hours:         {', '.join(str(h) for h in sorted(b.hours)) or 'none'}")
        print(f"  Directories:   {len(b.directories)} unique")
        print(f"  Connections:   {len(b.connections)} unique")
        print(f"  Modified files:{len(b.modified_files)} unique")
        print("")
        print(
            "This is a research baseline, not a detection verdict. "
            "Use `myav research behaviour-baseline --check` to compare "
            "future activity against it."
        )
        return EXIT_OK

    # check
    b = result.baseline
    print(f"Behaviour baseline check: {directory.resolve()}")
    print(f"  Observations:  {result.total_observations}")
    print(f"  Deviations:    {result.deviation_count}")
    print(f"  Deviation rate:{result.deviation_rate:.2f}%")
    print("")
    if result.deviations:
        print("Deviations from baseline:")
        for d in result.deviations:
            print(f"  {d.type:<20} {d.value}")
    else:
        print("No deviations from baseline.")
    print("")
    print(
        "This is a research measurement, not a detection verdict. "
        "Deviations are alerts only — nothing is blocked."
    )
    return EXIT_OK


def _cmd_research_behaviour_detect(args: argparse.Namespace) -> int:
    """Run purpose-specific behavioural detectors against *path*.

    Read-only: scans files but never writes, quarantines, or blocks.
    Detectors: ransomware canary/bulk-rename, fileless/LOTL obfuscated
    scripts, document macros.
    """
    path = Path(args.path).expanduser()
    if not path.exists():
        print(f"myav: no such path: {path}", file=sys.stderr)
        return EXIT_USAGE

    from .research.behaviour_detectors import detect_all

    result = detect_all(
        path,
        canary_names=None,
        window_files=args.window_files,
        suspicious_ratio=args.suspicious_ratio,
        entropy_threshold=args.entropy_threshold,
    )

    if args.json:
        payload = {
            "command": "research-behaviour-detect",
            "path": result.path,
            "total_files_scanned": result.total_files_scanned,
            "match_count": result.match_count,
            "matches": [
                {
                    "detector": m.detector,
                    "severity": m.severity,
                    "description": m.description,
                    "path": m.path,
                    "detail": m.detail,
                }
                for m in result.matches
            ],
        }
        _emit(payload)
        return EXIT_OK

    print(f"Behaviour detection: {result.path}")
    print(f"  Files scanned: {result.total_files_scanned}")
    print(f"  Matches:       {result.match_count}")
    print("")
    if result.matches:
        for m in result.matches:
            print(
                f"  [{m.severity:<5}] {m.detector:<30} {m.path}"
            )
            print(f"      {m.description}")
            if m.detail:
                print(f"      {m.detail}")
    else:
        print("  No behavioural matches.")
    print("")
    print(
        "This is a research measurement, not a detection verdict. "
        "Matches are heuristic alerts — nothing is blocked."
    )
    return EXIT_OK


def _cmd_research_ml_baseline(args: argparse.Namespace) -> int:
    """Train/evaluate a simple ML baseline on EMBER-style features with
    temporal evaluation. Reports FPR, FNR, precision, recall and confusion
    matrix — never bare accuracy. Read-only: nothing ships as protection.
    """
    train_dir = Path(args.train_dir).expanduser() if args.train_dir else None
    test_dir = Path(args.test_dir).expanduser() if args.test_dir else None

    if train_dir is not None and not train_dir.exists():
        print(f"myav: not a directory: {train_dir}", file=sys.stderr)
        return EXIT_USAGE
    if test_dir is not None and not test_dir.exists():
        print(f"myav: not a directory: {test_dir}", file=sys.stderr)
        return EXIT_USAGE

    from .research.ml_baseline import run_ml_baseline

    result = run_ml_baseline(train_dir, test_dir, temporal=args.temporal)

    if args.json:
        _emit(result)
        return EXIT_OK

    print(f"ML baseline: {result.get('split_method', 'unknown')} split")
    print(f"  Train size: {result.get('train_size', 0)}")
    print(f"  Test size:  {result.get('test_size', 0)}")
    print("")
    if "error" in result:
        print(f"  Error: {result['error']}")
        return EXIT_OK
    c = result["confusion"]
    print("Confusion matrix:")
    print(f"  True negative  (clean, not flagged):  {c['true_negative']}")
    print(f"  False positive (clean, flagged):      {c['false_positive']}")
    print(f"  False negative (malicious, missed):   {c['false_negative']}")
    print(f"  True positive  (malicious, flagged):  {c['true_positive']}")
    print("")
    print(f"  False positive rate:  {result['false_positive_rate']:.2f}%")
    print(f"  False negative rate:  {result['false_negative_rate']:.2f}%")
    print(f"  Precision:            {result['precision']:.2f}%")
    print(f"  Recall:               {result['recall']:.2f}%")
    print("")
    return EXIT_OK


def _cmd_research_sandbox(args: argparse.Namespace) -> int:
    """Run a file in a sandbox for observation.

    Read-only: executes the file with resource limits and monitors
    process spawns, file modifications, network connections and
    autostart changes. With ``--syscalls`` it also traces file/process/network
    syscalls and flags mass encryption, mass deletion and evasion patterns.
    Reports a behavioural timeline — not a verdict. Never blocks.
    """
    target = Path(args.path).expanduser()
    if not target.exists():
        print(f"myav: no such path: {target}", file=sys.stderr)
        return EXIT_USAGE
    if not target.is_file():
        print(f"myav: not a regular file: {target}", file=sys.stderr)
        return EXIT_USAGE

    from .research.sandbox import result_to_dict, run_in_sandbox

    result = run_in_sandbox(
        target,
        duration_seconds=args.duration,
        use_syscalls=args.syscalls,
    )

    if args.json:
        _emit(result_to_dict(result))
        return EXIT_OK

    print(f"Sandbox: {result.target}")
    print(f"  Duration: {result.duration_seconds:.2f}s")
    print(f"  Timeout killed: {result.timeout_killed}")
    print(f"  Exit code: {result.exit_code}")
    print(f"  Events: {result.event_count}")
    print(f"  Evasions: {result.evasion_count}")
    print(f"  Findings: {result.finding_count}")
    print("")
    if result.syscalls is not None:
        s = result.syscalls
        print("Syscall summary:")
        print(f"  Total syscalls: {s.total_syscalls}")
        print(f"  Files written:  {len(s.unique_files_written)}")
        print(f"  Renames:        {len(s.renames)}")
        print(f"  Unlinks:        {len(s.unlinks)}")
        print(f"  Execs:          {len(s.execs)}")
        print(f"  Connects:       {len(s.connects)}")
        print("")
    elif args.syscalls:
        print("Syscall summary: unavailable (strace missing or failed).")
        print("")
    if result.events:
        print("Behavioural timeline:")
        for e in result.events:
            print(f"  [{e.timestamp:6.2f}s] {e.event_type:<12} {e.detail}"
                  + (f" ({e.path})" if e.path else ""))
    else:
        print("  No events observed.")
    print("")
    if result.evasions:
        print("Sandbox evasion indicators:")
        for ev in result.evasions:
            print(f"  [{ev.severity}] {ev.type}: {ev.description}")
    else:
        print("  No sandbox evasion indicators.")
    print("")
    if result.findings:
        print("Behavioural findings:")
        for finding in result.findings:
            print(f"  [{finding.severity}] {finding.kind}: {finding.description}")
            if finding.detail:
                print(f"      {finding.detail}")
    else:
        print("  No behavioural findings.")
    print("")
    print(
        "This is a research measurement, not a detection verdict. "
        "Events are observed only — nothing is blocked."
    )
    return EXIT_OK


def _cmd_research_campaign_graph(args: argparse.Namespace) -> int:
    """Build a correlation graph from research events.

    Links file → process → outbound connection → another file → startup
    entry to detect campaigns. Reports clusters with heuristic risk
    scores — never a detection verdict.
    """
    window_days = args.days

    from .research.campaign_graph import build_campaign_graph, example_events, result_to_dict

    # For now, use example events as a demo. In the future this will read
    # from the state DB / watcher events.
    events = example_events()

    result = build_campaign_graph(events, window_days=window_days)

    if args.json:
        _emit(result_to_dict(result))
        return EXIT_OK

    print(f"Campaign graph: {result.node_count} nodes, {result.edge_count} edges")
    print(f"  Clusters: {result.cluster_count}")
    print(f"  Window: {result.window_days} days")
    print("")
    if result.clusters:
        print("Campaign clusters (by risk score):")
        for c in result.clusters:
            print(f"  [{c.risk_score:.2f}] {c.node_count} nodes, {c.edge_count} edges")
            for n in c.nodes:
                print(f"    - {n.type}: {n.label}")
    else:
        print("  No clusters found.")
    print("")
    print(
        "This is a research measurement, not a detection verdict. "
        "Risk scores are heuristic — nothing is blocked."
    )
    return EXIT_OK


def _cmd_research_gui(args: argparse.Namespace) -> int:
    """Launch the Tkinter GUI desktop application.

    The GUI is a separate process that reads the myav state DB and config
    and serves as a front-end over the existing CLI commands. Nothing runs
    sudo here.
    """
    from .research.gui import main as gui_main

    return gui_main()


def _cmd_research_honesty_dashboard(args: argparse.Namespace) -> int:
    """Run the honesty dashboard: compute real measured metrics, generate
    SBOM, sign release, and report an honest confidence level.

    Read-only: reads the state DB, generates SBOM, attempts signing —
    nothing is blocked.
    """
    state_db = Path(args.state_db).expanduser() if args.state_db else None

    from .research.honesty_dashboard import run_honesty_dashboard

    result = run_honesty_dashboard(state_db, json_output=args.json)

    if args.json:
        _emit(result)
        return EXIT_OK

    # Already printed inside run_honesty_dashboard when not json.
    return EXIT_OK


# ------------------------------------------------------------------ system/privileged


def cmd_update_signatures(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    freshclam = shutil.which("freshclam")
    if not freshclam:
        print(
            "freshclam is not installed. Run scripts/install-system.sh (docs/INSTALL.md).",
            file=sys.stderr,
        )
        return EXIT_PLATFORM

    systemd = _systemd_state()
    if systemd not in {"offline", "unknown"} and not args.no_service:
        completed = subprocess.run(
            ["systemctl", "start", "clamav-freshclam"], capture_output=True, text=True
        )
        if completed.returncode != 0:
            print(
                "Could not start clamav-freshclam through systemd; "
                "falling back to direct freshclam.",
                file=sys.stderr,
            )
    else:
        completed = subprocess.run([freshclam], capture_output=True, text=True)

    output = (completed.stdout or "").strip()
    error = (completed.stderr or "").strip()
    if completed.returncode != 0:
        if "permission" in error.lower() or "denied" in error.lower():
            print(
                "freshclam needs to write the system signature database, which requires root.\n"
                "Ask the operator to run:  sudo myav update-signatures\n"
                "myav itself never runs sudo.",
                file=sys.stderr,
            )
        else:
            print(error[-800:] or output[-800:] or "freshclam failed", file=sys.stderr)
        return EXIT_FAIL

    info = ctx.engines().clamav.signature_info()
    if args.json:
        _emit({"command": "update-signatures", "exit_code": EXIT_OK, **info.as_dict()})
    else:
        tail = "\n".join(output.splitlines()[-5:])
        if tail:
            print(tail)
        if info.available:
            print(f"Signatures: version {info.db_version}")
        print("Signature update finished.")
    return EXIT_OK


def cmd_clamd_start(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    require(ctx, Capability.DAEMON, "clamd-start")

    if _daemon_reachable(ctx):
        print("clamd is already answering on 127.0.0.1:3310.")
        return EXIT_OK

    systemd = _systemd_state()
    if systemd not in {"offline", "unknown"}:
        completed = subprocess.run(
            ["systemctl", "start", "clamav-daemon"], capture_output=True, text=True
        )
        if completed.returncode == 0 and _daemon_reachable(ctx):
            print("clamd started through systemd (clamav-daemon).")
            return EXIT_OK
        if completed.returncode != 0:
            print(
                "systemd could not start clamav-daemon. If this says 'permission denied', "
                "the operator must run: sudo myav clamd-start",
                file=sys.stderr,
            )

    clamd = shutil.which("clamd") or "/usr/sbin/clamd"
    if not Path(clamd).exists():
        print(
            "clamd is not installed. Run scripts/install-system.sh (docs/INSTALL.md).",
            file=sys.stderr,
        )
        return EXIT_PLATFORM
    completed = subprocess.run([clamd], capture_output=True, text=True)
    if completed.returncode == 0 and _daemon_reachable(ctx):
        print("clamd started.")
        return EXIT_OK
    error = (completed.stderr or "").strip()
    if "permission" in error.lower():
        print("Root is required. Ask the operator to run:  sudo myav clamd-start", file=sys.stderr)
    else:
        print(error[-800:] or "clamd did not start", file=sys.stderr)
    return EXIT_FAIL


# ---------------------------------------------------------------------------- schedules


def cmd_schedules(args: argparse.Namespace) -> int:
    ctx = make_context(create_dirs=True)
    require(ctx, Capability.SCHEDULER, "schedules")
    artifacts = render_schedules(
        ctx.platform, _install_root(), _user(), _distro(), binary=_binary()
    )
    if args.action == "print":
        if not artifacts:
            print(f"{ctx.platform.label} has no scheduler adapter.")
            return EXIT_PLATFORM
        for artifact in artifacts:
            print(f"# --- {artifact.label} ---")
            if artifact.path:
                print(f"# file: {artifact.path}")
            if artifact.needs_root:
                print("# needs root: yes (myav prints, never writes)")
            print(artifact.content)
            if artifact.activate:
                print(f"# activate: {artifact.activate}")
            print("")
        return EXIT_OK

    if args.action == "install":
        actions = install_artifacts(artifacts, yes=args.yes)
        for action in actions:
            print(action)
        if not args.yes:
            print("")
            print("Nothing was written. Re-run with --yes to install the user-level jobs.")
        return EXIT_OK

    payload = schedule_status(ctx.platform, _install_root(), _user())
    if args.json:
        _emit({"command": "schedules-status", **payload})
        return EXIT_OK
    print(f"scheduler: {payload['scheduler']}")
    installed = payload.get("installed", [])
    if installed:
        for name in installed:
            print(f"  installed: {name}")
    else:
        print("  nothing installed yet — `myav schedules install --yes`")
    if payload.get("note"):
        print(f"  note: {payload['note']}")
    return EXIT_OK


# ------------------------------------------------------------------------------- inner


def cmd_inner(args: argparse.Namespace) -> int:
    """Quiet entry point used by schedulers. Output goes to a log, not a console."""
    mapping = {
        "clamd-start": "clamd-start",
        "update-sigs": "update-signatures",
        "watch-loop": "watch",
        "full-scan": "full-scan",
        "boot": "boot",
    }
    command = mapping.get(args.inner_command, args.inner_command)
    ctx = make_context(create_dirs=True)
    log_path = ctx.paths.logs_dir / f"inner-{command}.log"
    with open(log_path, "a", encoding="utf-8") as handle:
        handle.write(f"\n=== {datetime.now(timezone.utc).isoformat()} {command} ===\n")
        handle.flush()
        with contextlib.redirect_stdout(handle), contextlib.redirect_stderr(handle):
            return main([command, *args.rest])


# ---------------------------------------------------------------------------- helpers


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _systemd_state() -> str:
    if not shutil.which("systemctl"):
        return "offline"
    try:
        completed = subprocess.run(
            ["systemctl", "is-system-running"], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (completed.stdout or completed.stderr or "unknown").strip().splitlines()[0]


def _daemon_reachable(ctx: Context) -> bool:
    try:
        with socket.create_connection(
            (ctx.config.clamav.tcp_host, ctx.config.clamav.tcp_port), timeout=1.0
        ):
            return True
    except OSError:
        pass
    socket_path = Path(ctx.config.clamav.local_socket)
    return socket_path.exists()


def _install_root() -> Path:
    candidate = Path(__file__).resolve().parents[2]
    if (candidate / "bin" / "myav").exists():
        return candidate
    return Path.cwd()


def _binary() -> Path:
    root = _install_root()
    candidate = root / "bin" / "myav"
    if candidate.exists():
        return candidate
    found = shutil.which("myav")
    return Path(found) if found else Path("myav")


def _user() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME") or "user"


def _distro() -> str:
    return os.environ.get("WSL_DISTRO_NAME", "Ubuntu")


# ------------------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="myav",
        description=(
            "Local open-source antivirus: ClamAV + YARA + optional VirusTotal hash checks, "
            "with reversible quarantine. Nothing is ever deleted without your confirmation."
        ),
        epilog="Documentation: docs/INSTALL.md, docs/CONFIGURATION.md, docs/RUNBOOK.md.",
    )
    parser.add_argument("--version", action="version", version=f"myav {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, func, help_text: str) -> argparse.ArgumentParser:
        child = sub.add_parser(name, help=help_text, description=help_text)
        child.set_defaults(func=func)
        return child

    version = add("version", cmd_version, "Show the version and the detected platform.")
    version.add_argument("--json", action="store_true")

    platforms = add("platforms", cmd_platforms, "Show every platform adapter and its capabilities.")
    platforms.add_argument("--json", action="store_true")

    doctor = add("doctor", cmd_doctor, "Check every dependency and say what is missing.")
    doctor.add_argument("--json", action="store_true")

    config = add("config", cmd_config, "Show or edit myav configuration.")
    config_sub = config.add_subparsers(dest="action", required=True)
    show = config_sub.add_parser("show", help="Print the effective configuration.")
    show.add_argument("--json", action="store_true")
    show.add_argument("--reveal", action="store_true", help="Show the full VirusTotal key.")
    show.set_defaults(func=cmd_config, action="show")
    path = config_sub.add_parser("path", help="Print the config file location.")
    path.set_defaults(func=cmd_config, action="path")
    set_key = config_sub.add_parser(
        "set-vt-key", help="Store a VirusTotal API key with 0600 permissions."
    )
    set_key.add_argument(
        "--key", help="The 64-character key (otherwise read from MYAV_VT_API_KEY or a prompt)."
    )
    set_key.set_defaults(func=cmd_config, action="set-vt-key")

    scan = add("scan", cmd_scan, "Scan specific files or folders now.")
    scan.add_argument("paths", nargs="+", help="Files or folders to scan.")
    scan.add_argument(
        "--kind", default="manual", help="Label stored with each scan (default: manual)."
    )
    scan.add_argument("--dry-run", action="store_true", help="Detect but do not quarantine.")
    scan.add_argument("--report", action="store_true", help="Also write a markdown report file.")
    scan.add_argument("--json", action="store_true")

    full = add(
        "full-scan", cmd_full_scan, "Scan the default scope and write a plain-English report."
    )
    full.add_argument("paths", nargs="*", help="Override the default scope.")
    full.add_argument("--dry-run", action="store_true", help="Detect but do not quarantine.")
    full.add_argument("--json", action="store_true")
    full.add_argument(
        "--quiet", action="store_true", help="Suppress progress and summary output."
    )
    full.add_argument(
        "--progress",
        action="store_true",
        default=True,
        help="Show per-file progress (default on, off with --json or --quiet).",
    )

    baseline = add(
        "baseline",
        cmd_baseline,
        "Baseline scan of pre-existing files (default scope).",
    )
    baseline.add_argument("paths", nargs="*", help="Override the default scope.")
    baseline.add_argument("--dry-run", action="store_true", help="Detect but do not quarantine.")
    baseline.add_argument("--json", action="store_true")

    rules = add("rules", cmd_rules, "Fetch or inspect the public YARA rule pack.")
    rules_sub = rules.add_subparsers(dest="action", required=True)
    rules_fetch = rules_sub.add_parser("fetch", help="Download and compile the pinned rule pack.")
    rules_fetch.add_argument(
        "--accept-license", action="store_true", help="Accept the DRL 1.1 licence."
    )
    rules_fetch.add_argument(
        "--update", action="store_true", help="Fetch a newer pack even if pinned."
    )
    rules_fetch.add_argument("--json", action="store_true")
    rules_fetch.set_defaults(func=cmd_rules, action="fetch")
    rules_status_cmd = rules_sub.add_parser("status", help="Show provenance and rule counts.")
    rules_status_cmd.add_argument("--json", action="store_true")
    rules_status_cmd.set_defaults(func=cmd_rules, action="status")

    rules_refresh = rules_sub.add_parser(
        "refresh", help="Fetch the latest YARA pack and show a rule-diff."
    )
    rules_refresh.add_argument("--json", action="store_true")
    rules_refresh.set_defaults(func=cmd_rules, action="refresh")

    quarantine = add(
        "quarantine", cmd_quarantine, "List, restore or (explicitly) delete quarantined files."
    )
    quarantine_sub = quarantine.add_subparsers(dest="action", required=True)
    q_list = quarantine_sub.add_parser("list", help="List quarantined files.")
    q_list.add_argument("--all", action="store_true", help="Include already-restored entries.")
    q_list.add_argument("--json", action="store_true")
    q_list.set_defaults(func=cmd_quarantine, action="list")
    q_restore = quarantine_sub.add_parser("restore", help="Put a quarantined file back.")
    q_restore.add_argument("id", help="Quarantine ID (first 8 characters are enough).")
    q_restore.add_argument("--to", help="Restore somewhere other than the original path.")
    q_restore.add_argument("--force", action="store_true", help="Overwrite an existing file.")
    q_restore.set_defaults(func=cmd_quarantine, action="restore")
    q_purge = quarantine_sub.add_parser("purge", help="Delete a quarantined file permanently.")
    q_purge.add_argument("id")
    q_purge.add_argument("--yes", action="store_true", help="Required. There is no undo.")
    q_purge.set_defaults(func=cmd_quarantine, action="purge")

    q_budget = quarantine_sub.add_parser(
        "budget", help="Show or set the quarantine size budget."
    )
    q_budget.add_argument("--json", action="store_true")
    q_budget.add_argument(
        "--set", type=int, help="Set the budget in bytes (omit to show current)."
    )
    q_budget.set_defaults(func=cmd_quarantine, action="budget")

    q_rotate = quarantine_sub.add_parser(
        "rotate", help="Purge oldest quarantine entries until within budget."
    )
    q_rotate.add_argument("--json", action="store_true")
    q_rotate.set_defaults(func=cmd_quarantine, action="rotate")

    allow = add("allow", cmd_allow, "Manage the sha256 allowlist (false-positive escape hatch).")
    allow_sub = allow.add_subparsers(dest="action", required=True)
    allow_list = allow_sub.add_parser("list", help="Show allowlisted hashes.")
    allow_list.add_argument("--json", action="store_true")
    allow_list.set_defaults(func=cmd_allow, action="list")
    allow_add = allow_sub.add_parser("add", help="Allowlist one file by content hash.")
    allow_add.add_argument("path")
    allow_add.add_argument("--reason", default="")
    allow_add.add_argument("--json", action="store_true")
    allow_add.set_defaults(func=cmd_allow, action="add")

    allow_remove = allow_sub.add_parser(
        "remove", help="Remove a hash from the allowlist."
    )
    allow_remove.add_argument(
        "hash", nargs="?", help="sha256 hash to remove (required unless --path)."
    )
    allow_remove.add_argument(
        "--path", help="Hash this file and remove the resulting sha256 from the allowlist."
    )
    allow_remove.add_argument("--json", action="store_true")
    allow_remove.set_defaults(func=cmd_allow, action="remove")

    intel = add(
        "intel",
        cmd_intel,
        "Import and query offline threat-intel feeds (exact indicators only).",
    )
    intel_sub = intel.add_subparsers(dest="action", required=True)

    intel_status = intel_sub.add_parser("status", help="Show the local IOC cache.")
    intel_status.add_argument("--json", action="store_true")
    intel_status.set_defaults(func=cmd_intel, action="status")

    intel_update = intel_sub.add_parser(
        "update", help="Fetch a feed from a URL or file and cache its indicators."
    )
    intel_update.add_argument("--name", required=True, help="Feed label recorded with each IOC.")
    intel_update.add_argument("--source", required=True, help="HTTP(S) URL or local file.")
    intel_update.add_argument(
        "--format",
        default="auto",
        choices=sorted(SUPPORTED_INTEL_FORMATS),
        help="Feed format (default: auto).",
    )
    intel_update.add_argument("--confidence", type=int, default=50)
    intel_update.add_argument("--json", action="store_true")
    intel_update.set_defaults(func=cmd_intel, action="update")

    intel_import = intel_sub.add_parser(
        "import", help="Import a local feed export (no network)."
    )
    intel_import.add_argument("path", help="Local file to import.")
    intel_import.add_argument("--name", required=True, help="Feed label recorded with each IOC.")
    intel_import.add_argument(
        "--format",
        default="auto",
        choices=sorted(SUPPORTED_INTEL_FORMATS),
        help="Feed format (default: auto).",
    )
    intel_import.add_argument("--confidence", type=int, default=50)
    intel_import.add_argument("--json", action="store_true")
    intel_import.set_defaults(func=cmd_intel, action="import")

    intel_check = intel_sub.add_parser(
        "check", help="Look up one indicator (exit 0 found, 1 not found)."
    )
    intel_check.add_argument("indicator", help="sha256, URL, domain or IP.")
    intel_check.add_argument("--json", action="store_true")
    intel_check.set_defaults(func=cmd_intel, action="check")

    intel_clear = intel_sub.add_parser("clear", help="Delete every cached indicator.")
    intel_clear.add_argument("--yes", action="store_true", help="Required. There is no undo.")
    intel_clear.add_argument("--json", action="store_true")
    intel_clear.set_defaults(func=cmd_intel, action="clear")

    report = add("report", cmd_report, "Print the most recent report, or list all reports.")
    report.add_argument("--list", action="store_true", help="List report files.")
    report.add_argument("--path", help="Print a specific report file.")
    report.add_argument("--json", action="store_true", help="Output report as JSON.")

    boot = add("boot", cmd_boot, "List startup entries and flag new ones.")
    boot.add_argument("--json", action="store_true")

    watch = add("watch", cmd_watch, "Watch Downloads, Desktop and removable volumes.")
    watch.add_argument("--once", action="store_true", help="Scan what is already there, then exit.")
    watch.add_argument("--create-dirs", action="store_true", help="Create missing watch folders.")
    watch.add_argument("--json", action="store_true")
    watch.add_argument(
        "--quiet", action="store_true", help="Suppress progress and summary output."
    )
    watch.add_argument(
        "--watch-block",
        action="store_true",
        default=False,
        help="Block MALICIOUS files (chmod 000) when detected by watcher.",
    )

    selftest = add(
        "selftest", cmd_selftest, "Prove the whole chain with the harmless EICAR test file."
    )
    selftest.add_argument("--json", action="store_true")

    notify = add(
        "notify", cmd_notify, "Show a toast notification (Windows only)."
    )
    notify.add_argument("title")
    notify.add_argument("message")
    notify.add_argument("--json", action="store_true")

    update = add(
        "update-signatures",
        cmd_update_signatures,
        "Update ClamAV signatures (needs root on Linux).",
    )
    update.add_argument(
        "--no-service", action="store_true", help="Skip systemd, call freshclam directly."
    )
    update.add_argument("--json", action="store_true")

    clamd = add("clamd-start", cmd_clamd_start, "Start clamd, the fast on-access scanner daemon.")
    clamd.add_argument("--json", action="store_true")

    schedules = add("schedules", cmd_schedules, "Print, install or inspect the recurring jobs.")
    schedules_sub = schedules.add_subparsers(dest="action", required=True)
    s_print = schedules_sub.add_parser(
        "print", help="Show the files/commands that would be installed."
    )
    s_print.set_defaults(func=cmd_schedules, action="print")
    s_install = schedules_sub.add_parser("install", help="Write the user-level scheduler files.")
    s_install.add_argument("--yes", action="store_true", help="Actually write them.")
    s_install.set_defaults(func=cmd_schedules, action="install")
    s_status = schedules_sub.add_parser("status", help="Show what is installed.")
    s_status.add_argument("--json", action="store_true")
    s_status.set_defaults(func=cmd_schedules, action="status")

    research = add(
        "research", cmd_research, "Research-track measurement tools (not protection)."
    )
    research_sub = research.add_subparsers(dest="action", required=True)
    research_fp = research_sub.add_parser(
        "fp-baseline",
        help="Measure false-positive and false-negative rates (honest measurement).",
    )
    research_fp.add_argument(
        "directory", help="Directory of known-good files to scan (read-only)."
    )
    research_fp.add_argument(
        "--malicious-dir",
        help="Optional directory of known-bad files to measure false negatives.",
    )
    research_fp.add_argument("--json", action="store_true")
    research_fp.set_defaults(func=cmd_research, action="fp-baseline")

    research_behaviour = research_sub.add_parser(
        "behaviour-baseline",
        help="Learn a behaviour baseline and/or check activity against it.",
    )
    research_behaviour.add_argument(
        "directory", help="Directory to observe activity from (read-only)."
    )
    research_behaviour.add_argument(
        "--learn",
        action="store_true",
        help="Learn a baseline from the directory's activity.",
    )
    research_behaviour.add_argument(
        "--check",
        action="store_true",
        help="Check current activity against a previously learned baseline.",
    )
    research_behaviour.add_argument("--json", action="store_true")
    research_behaviour.set_defaults(
        func=cmd_research, action="behaviour-baseline"
    )

    research_detect = research_sub.add_parser(
        "behaviour-detect",
        help="Run purpose-specific behavioural detectors (ransomware, fileless/LOTL, documents).",
    )
    research_detect.add_argument(
        "path", help="Path or directory to scan (read-only)."
    )
    research_detect.add_argument(
        "--window-files",
        type=int,
        default=10,
        help="Min files in window for bulk-rename detector (default: 10).",
    )
    research_detect.add_argument(
        "--suspicious-ratio",
        type=float,
        default=0.6,
        help="Suspicious ratio threshold for bulk-rename (default: 0.6).",
    )
    research_detect.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.5,
        help="Entropy threshold (bits/byte) for obfuscated script detector (default: 4.5).",
    )
    research_detect.add_argument("--json", action="store_true")
    research_detect.set_defaults(
        func=cmd_research, action="behaviour-detect"
    )

    research_ml = research_sub.add_parser(
        "ml-baseline",
        help="Train/evaluate ML baseline on EMBER-style features with temporal evaluation.",
    )
    research_ml.add_argument(
        "--train-dir", help="Directory of training samples (read-only)."
    )
    research_ml.add_argument(
        "--test-dir", help="Directory of test samples (read-only)."
    )
    research_ml.add_argument(
        "--temporal",
        action="store_true",
        default=True,
        help="Use temporal split (train=older, test=newer) instead of random.",
    )
    research_ml.add_argument("--json", action="store_true")
    research_ml.set_defaults(
        func=cmd_research, action="ml-baseline"
    )

    research_sandbox = research_sub.add_parser(
        "sandbox",
        help="Execute a file in a lightweight sandbox and observe behaviour.",
    )
    research_sandbox.add_argument(
        "path", help="File to execute in the sandbox (read-only)."
    )
    research_sandbox.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help="Observation window in seconds (default: 30.0).",
    )
    research_sandbox.add_argument(
        "--syscalls",
        action="store_true",
        default=False,
        help="Trace file/process/network syscalls with strace (opt-in).",
    )
    research_sandbox.add_argument("--json", action="store_true")
    research_sandbox.set_defaults(
        func=cmd_research, action="sandbox"
    )

    research_campaign = research_sub.add_parser(
        "campaign-graph",
        help="Build correlation graph of file → process → connection → startup events.",
    )
    research_campaign.add_argument(
        "--days",
        type=int,
        default=7,
        help="Time window in days for graph events (default: 7).",
    )
    research_campaign.add_argument("--json", action="store_true")
    research_campaign.set_defaults(
        func=cmd_research, action="campaign-graph"
    )

    research_gui = research_sub.add_parser(
        "gui",
        help="Launch the Tkinter GUI desktop application.",
    )
    research_gui.set_defaults(
        func=cmd_research, action="gui"
    )

    research_honesty = research_sub.add_parser(
        "honesty-dashboard",
        help="Run honesty dashboard: real measured metrics, SBOM, signing.",
    )
    research_honesty.add_argument(
        "--state-db",
        default=None,
        help="Path to myav state DB (default: ~/.local/state/myav/state.db).",
    )
    research_honesty.add_argument("--json", action="store_true")
    research_honesty.set_defaults(
        func=cmd_research, action="honesty-dashboard"
    )

    inner = add("inner", cmd_inner, "Internal quiet entry point used by schedulers.")
    inner.add_argument("inner_command")
    inner.add_argument("rest", nargs=argparse.REMAINDER)

    completion = add("completion", cmd_completion, "Generate shell completion script.")
    completion.add_argument(
        "shell", nargs="?", default="bash", help="Shell type: bash or zsh (default: bash)."
    )
    completion.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    try:
        return int(args.func(args))
    except CapabilityError as exc:
        print(f"myav: {exc}", file=sys.stderr)
        return EXIT_PLATFORM
    except ConfigError as exc:
        print(f"myav: configuration problem: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except RulesError as exc:
        print(f"myav: {exc}", file=sys.stderr)
        return EXIT_FAIL
    except QuarantineError as exc:
        print(f"myav: {exc}", file=sys.stderr)
        return exc.code or EXIT_FAIL
    except UnsafeLocationError as exc:
        print(f"myav: refusing unsafe location: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except KeyboardInterrupt:
        print("\nmyav: interrupted. Nothing was deleted.", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
