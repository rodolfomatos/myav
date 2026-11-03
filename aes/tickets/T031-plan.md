---
ticket: T031
title: Lightweight sandbox — sufficient observation time
sprint: research-01
priority: medium
status: done
created: 2026-11-03
---

# T031 — Lightweight sandbox

## Context

Küchler et al. 2021 show short sandbox runs miss behaviour. T031 builds a lightweight sandbox that executes a file in isolation for a configurable observation window, monitoring syscalls, file modifications, and network connections. It detects behaviour that only appears after sustained execution, and flags sandbox-evasion techniques (malware behaving differently in a VM).

## Acceptance Criteria

- [ ] `src/myav/research/sandbox.py` created: executes a file isolated, observes behaviour
- [ ] `myav research sandbox <file> [--duration N seconds]` CLI command
- [ ] Monitors: process spawns, file modifications, outbound connections, registry/autostart changes
- [ ] Detects sandbox evasion: timing checks, VM artifacts, user interaction requirements
- [ ] Reports behavioural timeline, not a verdict
- [ ] `--json` output supported
- [ ] Tests cover: sandbox executes harmless file and reports timeline, sandbox-evasion heuristics run without crashing, JSON output
- [ ] Nothing ships as protection: observation only, never blocking
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/research/sandbox.py`, CLI `research sandbox`, tests.

**Out:** full system call interception, kernel integration, production sandbox.

## Rollback

Git revert.

## Known Risks

- Running unknown files in a sandbox is inherently risky; the sandbox must be isolated (separate user, no network, resource limits).
- Observation window must be long enough to matter but short enough to be practical.
