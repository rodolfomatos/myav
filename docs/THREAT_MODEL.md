# Threat Model

Two threat surfaces: (A) malware that `myav` is meant to catch, and (B) `myav` itself as an
attack surface. B is the one that gets projects like this compromised.

## A. What we defend against

| Threat | Covered by | Explicitly *not* covered |
|--------|-----------|--------------------------|
| Known malware families | ClamAV signatures | Zero-days, targeted implants |
| Known-bad file reputation | VT hash lookup (files VT already has) | New samples never seen by VT |
| Script/malware patterns, webshells, crypto-miners | YARA `signature-base` | Packed/obfuscated samples, kernel malware |
| Re-infection via startup persistence | bootwatch inventory diff (detection only) | Blocking execution (out of scope) |
| Files arriving via browser/USB copy | write watcher | Network traffic, browser memory, Windows host |

Stated honestly in every report: `myav` is a detection tool, not a prevention tool. A file can run
before the watcher finishes scanning it. That is a deliberate v1 limitation.

## B. myav as an attack surface

| # | Threat | Mechanism | Mitigation |
|---|--------|-----------|------------|
| B1 | **Rule supply-chain compromise** — a malicious or broken YARA pack executes arbitrary logic or floods with false positives | pinned commit + archive SHA-256 in `rules/PROVENANCE.json`; compile check; no auto-update of rules without an explicit `--accept-rules` | operator reviews the diff of rule count and provenance on refresh |
| B2 | **Quarantine as a malware stash** — quarantined files remain executable | quarantine dir `0700`, files stored as `<id>.bin` with **mode 0000** and no extension; restore re-applies original mode | a file must never be re-executed from quarantine by accident |
| B3 | **Symlink / path traversal into quarantine** — a crafted path writes outside the quarantine dir | quarantine paths are generated (`uuid4`), never derived from the source filename; `os.open` with `O_NOFOLLOW` on the destination; restore path validated to stay within the allowed root | never join user-controlled names into the destination |
| B4 | **TOCTOU between scan and quarantine** — file swapped after scan | hash-before / hash-after verification; mismatch → keep both, do not unlink, verdict `UNKNOWN` | attacker gains nothing but a false "quarantined" claim is prevented |
| B5 | **Decompression/size DoS** — scanning a huge or recursive file | `max_scan_bytes` (100 MiB), per-file timeout 60 s, YARA `timeout`, skip non-regular files, skip symlinks | bounded queue, no recursion into archives in v1 |
| B6 | **Credential leak** — VT API key in logs, reports, or git | key only in `~/.config/myav/config.toml` (0600); redaction filter on the logger; a unit test asserts the key never appears in output | `grep`-based CI check for `api_key` values |
| B7 | **Privacy leak to VirusTotal** — hash lookup reveals the existence of a file | hash-only, opt-in, documented; no filename or path ever sent; `myav scan --no-vt` | offline mode disables the engine entirely |
| B8 | **Privilege abuse** — the tool requests root (clamd, freshclam) | root is used **only** by `scripts/install-system.sh` and the two root scheduled tasks; the watcher and CLI run unprivileged | systemd unit files and sudoers entries are forbidden; no `sudo` inside Python |
| B9 | **False positive destroys workflow** — a legitimate file is quarantined | reversible by design; `myav allow <sha256>` allowlist checked before quarantine; report states exactly which engine fired | allowlist is explicit and audited in `state.db` |
| B10 | **Watcher watches a world-writable dir** — any local process drops files to trigger scans | scanning is read-only on the file; DoS cost bounded by queue + size caps | acceptable for a single-user WSL machine; documented |
| B11 | **Windows Defender race on EICAR** — Defender deletes the test file before `myav` sees it | test writes to an ext4 temp dir and scans immediately; if Defender interferes the test reports `INCONCLUSIVE` with the reason instead of failing misleadingly | never disable Defender to make the test pass |
| B12 | **Signature staleness masquerading as protection** — old DB, "CLEAN" reports | every report includes signature age; `doctor` fails at > 48 h; verdict includes `engines.stale` flag | stale DB downgrades `CLEAN` to `CLEAN(degraded)` |

## C. Trust boundaries

- **Operator** — trusted. Grants the only root escalation.
- **Network** (freshclam mirrors, GitHub archive host, VirusTotal) — untrusted. TLS required;
  archive integrity verified against the pinned hash; VT responses validated (type, range) before use.
- **Watched directories** — untrusted content by definition. All input paths are treated as hostile strings.
- **Quarantine directory** — trusted only after hash verification.
- **Windows interop** (`reg.exe`, `powershell.exe`) — trusted for read-only enumeration; output is parsed,
  never executed, never used to build a shell command string.
