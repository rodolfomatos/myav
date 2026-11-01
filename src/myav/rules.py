"""Fetch a pinned public YARA pack with provenance.

Policy (docs/THREAT_MODEL.md B1): rules are never vendored into git. A fetch records the
upstream commit and the SHA-256 of the downloaded archive, extracts only ``*.yar``/``*.yara``
files (no path traversal), compiles them, and keeps a per-file report of rules that failed
to compile instead of silently dropping the whole pack.
"""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

from .paths import Paths
from .util import now_iso

DEFAULT_REPO = "Neo23x0/signature-base"
PACK_LICENSE = "Detection Rule License (DRL) 1.1 — free for non-commercial use"
API_LATEST = f"https://api.github.com/repos/{DEFAULT_REPO}/commits?per_page=1"
TARBALL = f"https://codeload.github.com/{DEFAULT_REPO}/tar.gz/"

Fetcher = Callable[[str, int], bytes]


def urllib_fetch(url: str, timeout: int = 60) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "myav-rules-fetcher"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


class RulesError(RuntimeError):
    pass


def _pin_file(paths: Paths) -> Path:
    return paths.rules_dir / "PROVENANCE.json"


def status(paths: Paths) -> dict:
    pin_path = _pin_file(paths)
    pin = {}
    if pin_path.exists():
        try:
            pin = json.loads(pin_path.read_text(encoding="utf-8"))
        except ValueError:
            pin = {"error": "PROVENANCE.json is not valid JSON"}
    files = list(paths.rules_dir.rglob("*.yar")) + list(paths.rules_dir.rglob("*.yara"))
    return {
        "rules_dir": str(paths.rules_dir),
        "cache": str(paths.yara_cache),
        "rule_files": len(files),
        "cache_exists": paths.yara_cache.exists(),
        "pinned": bool(pin),
        **pin,
    }


def resolve_commit(fetch: Fetcher = urllib_fetch) -> str:
    try:
        payload = json.loads(fetch(API_LATEST, 30).decode("utf-8"))
        return payload[0]["sha"]
    except (urllib.error.URLError, ValueError, KeyError, IndexError) as exc:
        raise RulesError(f"could not resolve the upstream commit: {exc}") from exc


def _safe_extract(archive: bytes, destination: Path) -> int:
    """Extract only .yar/.yara members, refusing absolute or traversing paths."""
    count = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            if not (member.name.endswith(".yar") or member.name.endswith(".yara")):
                continue
            relative = Path(*Path(member.name).parts[1:])  # drop the top-level dir
            if relative.is_absolute() or ".." in relative.parts:
                continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                continue
            target.write_bytes(source.read())
            count += 1
    return count


def compile_pack(rules_dir: Path, cache_path: Path, yarac: str | None = None) -> dict:
    """Compile every rule file, skipping (and reporting) the ones that fail."""
    yarac = yarac or shutil.which("yarac")
    if yarac is None:
        return {"compiled": False, "reason": "yarac not installed", "skipped": []}
    rule_files = sorted(rules_dir.rglob("*.yar")) + sorted(rules_dir.rglob("*.yara"))
    if not rule_files:
        return {"compiled": False, "reason": "no rule files", "skipped": []}

    skipped: list[dict[str, str]] = []
    good: list[Path] = []
    for rule_file in rule_files:
        probe = cache_path.with_suffix(".probe")
        completed = subprocess.run(
            [yarac, str(rule_file), str(probe)], capture_output=True, text=True, timeout=120
        )
        probe.unlink(missing_ok=True)
        if completed.returncode == 0:
            good.append(rule_file)
        else:
            skipped.append(
                {
                    "file": str(rule_file.relative_to(rules_dir)),
                    "error": completed.stderr.strip()[:200],
                }
            )
    if not good:
        return {"compiled": False, "reason": "no rule file compiled", "skipped": skipped}

    cache_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    completed = subprocess.run(
        [yarac, *[str(path) for path in good], str(cache_path)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if completed.returncode != 0:
        return {
            "compiled": False,
            "reason": completed.stderr.strip()[:300],
            "skipped": skipped,
        }
    return {
        "compiled": True,
        "rules": len(good),
        "skipped": skipped,
        "cache": str(cache_path),
    }


def fetch(
    paths: Paths,
    accept_license: bool = False,
    update: bool = False,
    fetch: Fetcher = urllib_fetch,
) -> dict:
    if not accept_license:
        raise RulesError(
            "the signature-base pack is distributed under the "
            f"{PACK_LICENSE}. Re-run with --accept-license to confirm you accept it."
        )
    pin_path = _pin_file(paths)
    if pin_path.exists() and not update:
        return {**status(paths), "changed": False}

    commit = resolve_commit(fetch)
    archive = fetch(TARBALL + commit, 180)
    digest = hashlib.sha256(archive).hexdigest()

    paths.rules_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    for child in paths.rules_dir.iterdir():
        if child.name == "PROVENANCE.json":
            continue
        if child.is_dir():
            shutil.rmtree(child)

    extracted = _safe_extract(archive, paths.rules_dir)
    compile_result = compile_pack(paths.rules_dir, paths.yara_cache)
    provenance = {
        "repo": DEFAULT_REPO,
        "commit": commit,
        "archive_sha256": digest,
        "license": PACK_LICENSE,
        "fetched_at": now_iso(),
        "rule_files": extracted,
        "compile": {k: v for k, v in compile_result.items() if k != "skipped"},
        "skipped_rules": compile_result.get("skipped", []),
    }
    pin_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    os_chmod(pin_path, 0o644)
    return {**provenance, "changed": True}


def os_chmod(path: Path, mode: int) -> None:
    import os

    os.chmod(path, mode)
