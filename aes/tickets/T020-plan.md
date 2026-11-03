---
ticket: T020
title: usbipd-aware device enumeration
sprint: sprint-03
priority: medium
status: done
created: 2026-11-03
---

# T020 — usbipd-aware device enumeration

## Context

On WSL with usbipd-win, USB devices attached from Windows appear as mounts inside WSL.
The existing `discover_removable_mounts()` reads `/proc/mounts` and finds them generically.
T020 adds explicit usbipd awareness: detecting the `usbipd` binary, listing attached
devices, and reporting them so the operator knows which removable media are usbipd-backed.

## Acceptance Criteria

- [ ] `discover_usbipd_devices()` added to `paths.py`
- [ ] Returns a list of mount points for usbipd-attached devices
- [ ] Returns an empty list when `usbipd` is not installed (graceful degradation)
- [ ] `discover_removable_mounts()` integrates usbipd devices
- [ ] Tests cover: usbipd available (parses output), usbipd not available (empty list)
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/paths.py` (usbipd discovery), tests.

**Out:** binding/unbinding usbipd devices, automatic mounting.

## Rollback

Git revert.
