# Personas

## P1 — The operator (primary, and only user in v1)

Owns the machine, runs the AI agent, is technical but not an antivirus specialist.
Wants: *"tell me plainly whether something bad landed here, and never lose my files."*

Needs:
- A verdict in plain English, with the evidence behind it.
- A guaranteed undo path for any quarantine action.
- To know when the tool is degraded (stale signatures, engine down, VT unconfigured).
- To be asked before anything privileged or irreversible happens.

Frustrations to avoid:
- Silent failures ("scanned 0 files" reported as success).
- Jargon-only output (`Heuristics.Trojan.Script.Generic` with no explanation).
- Being told to "just disable Defender" to make a test pass.

## P2 — The AI agent (secondary)

Operates the repo, writes code, runs non-privileged commands.
Wants: deterministic commands, machine-readable output, and hard boundaries so it
cannot destroy user data or change system settings by accident.

Needs:
- `--json` on every read command.
- Exit codes that distinguish clean / suspicious / malicious / error.
- Explicit prohibition (enforced by tests, not prose) on delete paths and network uploads.

## P3 — Future collaborator (deferred)

Would contribute YARA rules or engine adapters. Not a v1 target; no plugin API yet.
