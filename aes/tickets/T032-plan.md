---
ticket: T032
title: Campaign correlation graphs — beyond isolated files
sprint: research-01
priority: medium
status: done
created: 2026-11-03
---

# T032 — Campaign correlation graphs

## Context

Today myav evaluates each file in isolation. T032 builds a correlation graph linking: file → process → outbound connection → another file → startup entry. This enables detecting *campaigns* (e.g. a downloader that fetches a second stage which modifies boot), rather than isolated findings.

## Acceptance Criteria

- [ ] `src/myav/research/campaign_graph.py` created: builds and queries a correlation graph
- [ ] `myav research campaign-graph [--days N]` CLI command shows active campaigns
- [ ] Nodes: files, processes, network connections, startup entries
- [ ] Edges: "spawned", "connected to", "modified", "dropped"
- [ ] Reports campaign clusters with risk score (not a verdict)
- [ ] `--json` output supported
- [ ] Tests cover: graph builds from synthetic events, clusters detected, JSON output, empty graph handled
- [ ] Nothing ships as protection: correlation display only
- [ ] Coverage ≥ 80%, lint clean

## Scope

**In:** `src/myav/research/campaign_graph.py`, CLI `research campaign-graph`, tests.

**Out:** automatic blocking, real-time correlation engine.

## Rollback

Git revert.

## Known Risks

- Correlation graphs can grow large; pruning/retention policy needed.
- Risk scores are heuristic; they must not be presented as detection verdicts.
