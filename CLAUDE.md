# myav — Operational Contract

This file is the operational contract for AI agents working on this project.
It is the first file an agent must read. It defines scope, boundaries, and evidence rules.

---

## Intent

`myav` is a local, open-source-only antivirus for this machine: it scans files on write,
quarantines (never deletes) what it flags, watches startup entries, and reports in plain English.

---

## Environment Facts (verified 2026-11-01 — do not assume otherwise)

| Fact | Value | Consequence |
|------|-------|-------------|
| Platform | WSL2, Ubuntu 22.04, kernel `6.6.87.1-microsoft-standard-WSL2` | Not a security boundary for Windows |
| Init | systemd **offline**, `cron` **not running** | No `systemctl`/`systemd.timer`; scheduling goes through Windows Task Scheduler |
| Privileges | `sudo` requires a password; agent cannot type it | Privileged steps are operator-run via `scripts/install-system.sh` |
| RAM | 7.6 GiB total | `clamd` (~0.4 GiB steady, ~1.2 GiB peak load) is affordable |
| Disk | `/` ext4 737 GiB free · `C:` **3.8 GiB free (100 % used)** | Never write signatures, quarantine, logs, or caches to `/mnt/c` |
| Defender | Real-time protection **ON** | EICAR may be intercepted by Defender before `myav` sees it; document, don't "fix" by disabling Defender |
| Interop | `powershell.exe`, `reg.exe`, `wslpath` available | Startup inventory + scheduling are possible without admin |

---

## Non-Goals

- **Not** a replacement for Windows Defender. `myav` sees the WSL filesystem and mounted Windows volumes; it cannot protect the Windows desktop, kernel, or network stack.
- **No file upload.** VirusTotal integration is hash-lookup only (`GET /files/{hash}`). No sample leaves the machine.
- **No automatic deletion.** Quarantine is always reversible. `myav` must never `rm` a user file, and never `rm` a quarantined file without an explicit `myav purge --yes`.
- **No kernel modules, eBPF, fanotify, or FUSE interception.** On-write detection only; blocking is out of scope for v1.
- **No Windows registry writes, no Defender configuration changes, no host firewall changes.**
- **No signature authoring.** v1 consumes ClamAV CVDs and a pinned public YARA pack; it does not write detections.

---

## Critical Files

Any change here must be flagged to the operator **before** it happens, never silently:

- `scripts/install-system.sh` — the only file allowed to request root; run by a human
- `scripts/schedule-install.sh` — creates Windows Scheduled Tasks
- `src/myav/quarantine.py` — the "never delete" guarantee lives here
- `src/myav/engines/virustotal.py` — the "no upload" guarantee lives here
- `~/.config/myav/config.toml` (0600) — holds the VirusTotal key
- `.aes/hooks/*` — quality gates

---

## Never Do

- Never alter test vectors or expected outputs to make tests pass.
- Never disable or weaken security checks — including Defender, to make EICAR pass.
- Never commit secrets, API keys, or credentials. The VT key lives in `~/.config/myav/config.toml`, never in the repo.
- Never modify CI configuration to skip quality gates.
- Never write to `/mnt/c` (3.8 GiB free).
- Never run `sudo`, `apt`, `schtasks.exe`, or edit `/etc/**` without an explicit operator "yes" in the current session.
- Never implement a code path that uploads a file or its contents to any network service.
- Never implement a delete path for quarantine without a confirmation prompt and a dry-run mode.
- Never `chmod 000` or otherwise "neutralise" an original file instead of quarantining it.

---

## Evidence Required

Every non-trivial change must include:
- [ ] Output of `make test`
- [ ] Output of `make lint`
- [ ] Diffstory (what changed, why, what was untouched, remaining risks)
- [ ] Updated docs if behaviour changed
- [ ] For anything touching quarantine/VT/scheduling: the specific test that proves the guarantee

---

## Review Rule

- AI may implement and suggest.
- Human approves all merges to main.
- Human runs all privileged commands.
- No auto-merge without passing all quality gates.

---

## Stable Context (reload each session)

The **Debate Partner Protocol** is inherent to this project (see `prompts/debate-partner.md`). No yes-men.

Load at the start of every session:
- This file
- `docs/VISION.md`, `docs/REQUIREMENTS.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`
- `aes/kanban.md`

---

## Final Response

At the end of every non-trivial task, always summarise:

1. **What changed** — files touched and intent.
2. **Why it changed** — requirement or ticket addressed.
3. **Validation performed** — exact command and result. If not run, say so.
4. **Remaining risk or follow-up** — what was not tested, what to watch.
