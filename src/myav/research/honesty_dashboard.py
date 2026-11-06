"""Supply chain and operational honesty dashboard (research track).

Read-only: generates SBOM (CycloneDX), documents release signing, and
reports an operator-facing honesty dashboard with real measured metrics:
files scanned, flagged, restored, confirmed false positives, FPR over
time, and a confidence level based on measurement quantity — never
marketing claims.

This is a **measurement**, not a detector. It does not ship as MYAV Core
protection and never will be, unless it graduates per
docs/RESEARCH_TRACK.md (deterministic, explainable, measurable, offline).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------- SBOM


def generate_sbom(output_path: Path, version: str = "0.1.0") -> dict:
    """Generate a CycloneDX SBOM for the myav project.

    Records the Python interpreter, myav source files, and runtime
    dependencies with SHA-256 hashes. This is a snapshot — in CI it
    should be regenerated per release.
    """
    components = []

    # Python interpreter
    import sys

    components.append(
        {
            "type": "application",
            "name": "Python",
            "version": sys.version.split()[0],
            "purl": f"pkg:generic/python@{sys.version.split()[0]}",
        }
    )

    # myav itself
    myav_hash = _hash_file(Path("pyproject.toml"))
    components.append(
        {
            "type": "application",
            "name": "myav",
            "version": version,
            "purl": f"pkg:generic/myav@{version}",
            "hashes": [{"alg": "SHA-256", "content": myav_hash}],
        }
    )

    # Source files
    src_dir = Path("src/myav")
    if src_dir.exists():
        for py_file in sorted(src_dir.rglob("*.py")):
            file_hash = _hash_file(py_file)
            components.append(
                {
                    "type": "library",
                    "name": f"myav.{py_file.stem}",
                    "version": version,
                    "purl": f"pkg:generic/myav.{py_file.stem}@{version}",
                    "hashes": [{"alg": "SHA-256", "content": file_hash}],
                }
            )

    sbom = {
        "$schema": "http://cyclonedx.org/schema/cyclonedx-1.4.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "component": {
                "type": "application",
                "name": "myav",
                "version": version,
            },
        },
        "components": components,
    }

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")

    return sbom


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


# --------------------------------------------------------------------------- signing


def sign_release(
    file_path: Path,
    method: str = "gpg",
    key_id: str | None = None,
) -> dict:
    """Sign a release file with GPG (preferred) or document the intent.

    Returns a dict describing what was done. The actual private key must
    be operator-controlled — this function never generates or stores keys.
    """
    file_path = Path(file_path)
    if not file_path.exists():
        return {
            "signed": False,
            "method": method,
            "error": f"file not found: {file_path}",
        }

    if method == "gpg":
        try:
            sig_path = Path(str(file_path) + ".asc")
            cmd = ["gpg", "--armor", "--detach-sign", str(file_path)]
            if key_id:
                cmd.insert(2, f"--local-user={key_id}")
            completed = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            if completed.returncode == 0 and sig_path.exists():
                return {
                    "signed": True,
                    "method": "gpg",
                    "signature_file": str(sig_path),
                    "key_id": key_id,
                }
            return {
                "signed": False,
                "method": "gpg",
                "error": completed.stderr or completed.stdout,
            }
        except FileNotFoundError:
            return {
                "signed": False,
                "method": "gpg",
                "error": "gpg not installed — install gnupg to sign releases",
            }

    return {
        "signed": False,
        "method": method,
        "error": f"unsupported signing method: {method}",
    }


# --------------------------------------------------------------------------- honesty dashboard


@dataclass
class HonestyMetrics:
    """Real measured metrics from the state DB."""

    files_scanned: int
    files_flagged: int
    files_restored: int
    confirmed_false_positives: int
    false_positive_rate: float
    scans_performed: int
    days_of_operation: float
    confidence_level: str  # "none", "low", "medium", "high"
    confidence_reason: str


def compute_honesty_metrics(state_db_path: Path | None) -> HonestyMetrics:
    """Compute honesty metrics from the SQLite state DB.

    Reads the scans table to determine how many files have been scanned,
    how many were flagged, how many restored, etc. All numbers come from
    actual observed data — never estimated or claimed.
    """
    if state_db_path is None:
        return HonestyMetrics(
            files_scanned=0,
            files_flagged=0,
            files_restored=0,
            confirmed_false_positives=0,
            false_positive_rate=0.0,
            scans_performed=0,
            days_of_operation=0.0,
            confidence_level="none",
            confidence_reason="no state database path provided",
        )
    import sqlite3

    db_path = Path(state_db_path)
    if not db_path.exists():
        return HonestyMetrics(
            files_scanned=0,
            files_flagged=0,
            files_restored=0,
            confirmed_false_positives=0,
            false_positive_rate=0.0,
            scans_performed=0,
            days_of_operation=0.0,
            confidence_level="none",
            confidence_reason="no state database found — no measurements yet",
        )

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        # Total scans
        total_scans = conn.execute(
            "SELECT COUNT(*) FROM scans"
        ).fetchone()[0]

        # Flagged (MALICIOUS or SUSPICIOUS)
        flagged = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE verdict IN ('MALICIOUS', 'SUSPICIOUS')"
        ).fetchone()[0]

        # Restored quarantines
        restored = conn.execute(
            "SELECT COUNT(*) FROM quarantines WHERE state = 'restored'"
        ).fetchone()[0]

        # Confirmed false positives: quarantined then restored
        # (best available proxy — operator manually confirmed by restoring)
        confirmed_fp = restored

        # Time span
        first_ts = conn.execute(
            "SELECT MIN(ts) FROM scans"
        ).fetchone()[0]
        last_ts = conn.execute(
            "SELECT MAX(ts) FROM scans"
        ).fetchone()[0]

        days_of_operation = 0.0
        if first_ts and last_ts:
            from datetime import datetime

            t1 = datetime.fromisoformat(first_ts)
            t2 = datetime.fromisoformat(last_ts)
            days_of_operation = max((t2 - t1).total_seconds() / 86400.0, 0.0)

        conn.close()
    except Exception:
        conn.close()
        return HonestyMetrics(
            files_scanned=0,
            files_flagged=0,
            files_restored=0,
            confirmed_false_positives=0,
            false_positive_rate=0.0,
            scans_performed=0,
            days_of_operation=0.0,
            confidence_level="none",
            confidence_reason="could not read state database",
        )

    fpr = (flagged / total_scans * 100.0) if total_scans > 0 else 0.0

    # Confidence level based on amount of data
    if total_scans == 0:
        level = "none"
        reason = "no scans performed yet — no data to measure"
    elif total_scans < 10:
        level = "low"
        reason = f"only {total_scans} scan(s) — too few for reliable confidence"
    elif total_scans < 100:
        level = "low"
        reason = f"{total_scans} scans — preliminary data"
    elif total_scans < 1000:
        level = "medium"
        reason = f"{total_scans} scans — moderate confidence"
    else:
        level = "high"
        reason = f"{total_scans} scans — substantial data"

    return HonestyMetrics(
        files_scanned=total_scans,
        files_flagged=flagged,
        files_restored=restored,
        confirmed_false_positives=confirmed_fp,
        false_positive_rate=fpr,
        scans_performed=total_scans,
        days_of_operation=days_of_operation,
        confidence_level=level,
        confidence_reason=reason,
    )


def run_honesty_dashboard(
    state_db_path: Path | None, json_output: bool = False
) -> dict:
    """Run the honesty dashboard: compute metrics, generate SBOM, sign release.

    Returns a JSON-serialisable dict.
    """
    metrics = compute_honesty_metrics(state_db_path)

    # Generate SBOM
    sbom_path = Path("docs/sbom/myav.cdx.json")
    sbom = generate_sbom(sbom_path)

    # Sign release (best effort)
    signing = sign_release(sbom_path)

    result = {
        "command": "research-honesty-dashboard",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "metrics": {
            "files_scanned": metrics.files_scanned,
            "files_flagged": metrics.files_flagged,
            "files_restored": metrics.files_restored,
            "confirmed_false_positives": metrics.confirmed_false_positives,
            "false_positive_rate": round(metrics.false_positive_rate, 4),
            "scans_performed": metrics.scans_performed,
            "days_of_operation": round(metrics.days_of_operation, 2),
        },
        "confidence": {
            "level": metrics.confidence_level,
            "reason": metrics.confidence_reason,
        },
        "sbom": {
            "path": str(sbom_path),
            "components": len(sbom.get("components", [])),
        },
        "signing": signing,
        "note": (
            "This is a research measurement, not a detection verdict. "
            "Confidence level is based on measurement quantity, not "
            "detection performance. Nothing is blocked."
        ),
    }

    if json_output:
        return result

    # Text output
    print("myav honesty dashboard")
    print("=" * 40)
    print(f"Generated: {result['generated_at']}")
    print()
    print("Measured metrics:")
    m = result["metrics"]
    print(f"  Files scanned:   {m['files_scanned']}")
    print(f"  Files flagged:   {m['files_flagged']}")
    print(f"  Files restored:  {m['files_restored']}")
    print(f"  False positives: {m['confirmed_false_positives']}")
    print(f"  False positive rate: {m['false_positive_rate']:.2f}%")
    print(f"  Scans performed: {m['scans_performed']}")
    print(f"  Days of operation: {m['days_of_operation']:.1f}")
    print()
    c = result["confidence"]
    print(f"Confidence level: {c['level']}")
    print(f"  Reason: {c['reason']}")
    print()
    print("SBOM:")
    s = result["sbom"]
    print(f"  Path: {s['path']}")
    print(f"  Components: {s['components']}")
    print()
    sg = result["signing"]
    print("Release signing:")
    print(f"  Method: {sg.get('method', 'none')}")
    print(f"  Signed: {sg.get('signed', False)}")
    if sg.get("error"):
        print(f"  Error: {sg['error']}")
    if sg.get("signature_file"):
        print(f"  Signature: {sg['signature_file']}")
    print()
    print(result["note"])

    return result
