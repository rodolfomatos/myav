"""Proof of life: the EICAR end-to-end self-test.

EICAR is a harmless 68-byte string every antivirus agrees to flag. The test proves the whole
chain, not just the signature: detect → quarantine → source gone → restore → byte-identical.

The literal is assembled from parts so this repository is never itself flagged.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .hashutil import sha256_file
from .paths import Paths, assert_writable_location
from .pipeline import Engines, scan_file
from .quarantine import Quarantine, QuarantineError
from .state import State

EICAR_PARTS = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
    "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
    "!$H+H*",
)


def eicar_bytes() -> bytes:
    return "".join(EICAR_PARTS).encode("ascii")


@dataclass
class Assertion:
    name: str
    passed: bool
    detail: str = ""


@dataclass
class SelfTestResult:
    assertions: list[Assertion] = field(default_factory=list)
    inconclusive: str | None = None

    @property
    def ok(self) -> bool:
        return self.inconclusive is None and all(item.passed for item in self.assertions)

    @property
    def exit_code(self) -> int:
        if self.inconclusive:
            return 5
        return 0 if self.ok else 1

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "inconclusive": self.inconclusive,
            "assertions": [item.__dict__ for item in self.assertions],
        }

    def render(self) -> str:
        lines = ["EICAR self-test", ""]
        if self.inconclusive:
            lines.append(f"INCONCLUSIVE: {self.inconclusive}")
            lines.append("")
        lines.append(f"{'result':<8} assertion")
        lines.append(f"{'-' * 8} {'-' * 52}")
        for item in self.assertions:
            mark = "PASS" if item.passed else "FAIL"
            lines.append(f"{mark:<8} {item.name}" + (f" — {item.detail}" if item.detail else ""))
        lines.append("")
        lines.append(
            "RESULT: " + ("PASS" if self.ok else ("INCONCLUSIVE" if self.inconclusive else "FAIL"))
        )
        return "\n".join(lines)


def run_eicar_selftest(
    config: Config, paths: Paths, state: State, engines: Engines
) -> SelfTestResult:
    result = SelfTestResult()

    if not engines.clamav.available():
        result.inconclusive = (
            "ClamAV is not installed, so the EICAR signature cannot be tested. "
            "Run the system installer first (see docs/INSTALL.md)."
        )
        return result

    sandbox = assert_writable_location(paths.state_dir / "selftest" / uuid.uuid4().hex)
    sandbox.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = sandbox / "eicar-test-file.txt"
    payload = eicar_bytes()
    target.write_bytes(payload)
    os.chmod(target, 0o600)
    original_hash = sha256_file(target)

    def check(name: str, condition: bool, detail: str = "") -> None:
        result.assertions.append(Assertion(name=name, passed=bool(condition), detail=detail))

    check("test file written", target.exists(), str(target))
    check("test file hash recorded", len(original_hash) == 64, original_hash[:16] + "…")

    outcome = scan_file(target, config, paths, state, engines, kind="selftest")
    if outcome.skipped == "vanished" or not target.exists() and not outcome.quarantined:
        result.inconclusive = (
            "the EICAR file disappeared before myav could scan it. Windows Defender "
            "real-time protection does this to files inside WSL. This is Defender doing "
            "its job, not a myav failure — do NOT disable Defender to make this test pass."
        )
        _cleanup(sandbox, None, paths, state)
        return result

    verdict = outcome.verdict
    check("verdict is MALICIOUS", outcome.level == "MALICIOUS", outcome.level)
    signatures = " ".join(r.signature or "" for r in (verdict.results if verdict else []))
    check(
        "ClamAV named the Eicar signature",
        "eicar" in signatures.lower(),
        signatures or "no signature reported",
    )
    check("source file was removed", not target.exists(), str(target))
    record = outcome.quarantined
    check("quarantine record created", record is not None, record.id[:8] if record else "none")

    if record is None:
        # Only call it inconclusive when something *did* fire. A clean result is a real
        # failure of the chain and must exit 1, not hide behind INCONCLUSIVE.
        if outcome.level in {"MALICIOUS", "SUSPICIOUS"}:
            result.inconclusive = (
                "the test file was detected but not quarantined; see the assertions above."
            )
        _cleanup(sandbox, None, paths, state)
        return result

    quarantine = Quarantine(paths, state, config)
    stored = quarantine.payload_path(record)
    check("payload exists", stored.exists(), str(stored))
    if stored.exists():
        # Quarantined payloads live at mode 0000 so nothing can execute them. Reading
        # them for verification is an explicit, temporary permission grant.
        os.chmod(stored, 0o600)
    check(
        "payload hash matches the original",
        stored.exists() and sha256_file(stored) == original_hash,
    )
    check(
        "payload is not executable",
        stored.exists() and (stored.stat().st_mode & 0o777) == 0o600,
        oct(stored.stat().st_mode & 0o777) if stored.exists() else "missing",
    )

    restored: Path | None = None
    try:
        restored = quarantine.restore(record.id)
        check("restore returned a path", restored.exists(), str(restored))
        check("restored file hash matches", sha256_file(restored) == original_hash)
    except QuarantineError as exc:
        check("restore succeeded", False, str(exc))

    _cleanup(sandbox, restored, paths, state, record.id)
    check("no test artefacts left in the sandbox", not sandbox.exists(), str(sandbox))
    return result


def _cleanup(
    sandbox: Path,
    restored: Path | None,
    paths: Paths,
    state: State,
    quarantine_id: str | None = None,
) -> None:
    if restored and restored.exists():
        restored.unlink(missing_ok=True)
    if quarantine_id:
        quarantine = Quarantine(paths, state)
        record = state.get_quarantine(quarantine_id)
        if record:
            payload = quarantine.payload_path(record)
            if payload.exists():
                os.chmod(payload, 0o600)
                payload.unlink(missing_ok=True)
            state.delete_quarantine(quarantine_id)
    for path in sorted(sandbox.rglob("*"), reverse=True) if sandbox.exists() else []:
        if path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            path.rmdir()
    if sandbox.exists():
        sandbox.rmdir()
