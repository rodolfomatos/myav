---
ticket: T011
title: EICAR self-test + live verification (proof of FR-9)
sprint: sprint-01
priority: high
status: pending
created: 2026-11-01
---

# T011 — Proof of life

## Context

"Prove it works with the EICAR test file." The test must prove the **whole chain**, not just that
ClamAV knows the string: detect → verdict → quarantine → source gone → restore → byte-identical.

## Acceptance Criteria

- [ ] `myav selftest --eicar` builds the EICAR string **from concatenated parts** so this repo's own
  files are never flagged (and a test asserts the literal does not appear in `src/` or `tests/`)
- [ ] Writes to an ext4 temp dir (`$XDG_RUNTIME_DIR` or `/tmp`), never `/mnt/c`
- [ ] Asserts, in order: `MALICIOUS`, signature named `Eicar-Test-Signature`, quarantine record
  created, source path gone, quarantined sha256 == original sha256, payload mode `0000`
- [ ] `restore` → file back at original path, sha256 identical, mode/mtime restored
- [ ] Cleanup removes the restored file and the quarantine record, leaving no trace
- [ ] If Defender removes the file first → result `INCONCLUSIVE` with the reason, exit 5,
  and an instruction that does **not** involve disabling Defender
- [ ] `make verify-live` = doctor + selftest + watcher drop-test + report assertion, exit 0
- [ ] Output is a copy-pasteable assertion table (this becomes the sprint evidence)

## Scope
**In:** `src/myav/selftest.py`, `Makefile` target, `scripts/verify-live.sh`.
**Out:** real malware samples (never), AMTSO cloud-lookup test (Sprint 03).

## Rollback
Self-cleaning. On failure, prints exact paths left behind.

## Known Risks
- Defender real-time protection is ON and may intercept the file inside WSL → INCONCLUSIVE.
  Documented in THREAT_MODEL B11; the operator may choose a Defender exclusion for
  `\\wsl$\Ubuntu\opt\myav\.testtmp` (their decision, requires admin).
- Antivirus testing on the operator's own machine is noisy by nature; the test writes one known
  harmless file for < 30 s.
