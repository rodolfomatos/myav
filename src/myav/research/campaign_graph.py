"""Campaign correlation graphs (research track).

Read-only: builds a graph linking file → process → outbound connection →
another file → startup entry, to detect *campaigns* rather than isolated
findings. Reports clusters with heuristic risk scores — never a detection
verdict.

This is a **measurement**, not a detector. It does not ship as MYAV Core
protection and never will be, unless it graduates per
docs/RESEARCH_TRACK.md (deterministic, explainable, measurable, offline).
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------- data types


@dataclass(frozen=True)
class GraphNode:
    """A node in the campaign graph."""

    id: str
    type: str  # file, process, connection, startup
    label: str
    first_seen: str
    last_seen: str
    attributes: dict = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    """A directed edge between two nodes."""

    source: str
    target: str
    type: str  # spawned, connected_to, modified, dropped
    timestamp: str
    attributes: dict = field(default_factory=dict)


@dataclass
class GraphCluster:
    """A connected component (campaign candidate)."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    risk_score: float  # 0.0 = benign, 1.0 = high risk

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)


@dataclass
class CampaignGraphResult:
    """Result of building and querying the campaign graph."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]
    clusters: list[GraphCluster]
    generated_at: str
    window_days: int

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    @property
    def cluster_count(self) -> int:
        return len(self.clusters)


# --------------------------------------------------------------------------- graph building


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _is_within_window(ts: str, days: int, now: str) -> bool:
    """Check if timestamp is within the last N days."""
    try:
        ts_dt = datetime.fromisoformat(ts)
        now_dt = datetime.fromisoformat(now)
        return (now_dt - ts_dt).total_seconds() <= days * 86400
    except ValueError:
        return True  # keep if we can't parse


def build_campaign_graph(
    events: list[dict],
    window_days: int = 7,
) -> CampaignGraphResult:
    """Build a correlation graph from raw events.

    Each event dict should have:
      - type: process | file | connection | startup
      - id: unique identifier
      - label: human-readable label
      - timestamp: ISO-8601
      - edges: list of {target_id, type} relationships
      - attributes: optional extra metadata

    Returns a CampaignGraphResult with nodes, edges and clusters.
    """
    now = _now_iso()

    # Filter events within the time window
    filtered = [
        e for e in events
        if _is_within_window(e.get("timestamp", now), window_days, now)
    ]

    # Build nodes
    nodes: dict[str, GraphNode] = {}
    for ev in filtered:
        node_id = ev.get("id", "")
        if not node_id:
            continue
        nodes[node_id] = GraphNode(
            id=node_id,
            type=ev.get("type", "unknown"),
            label=ev.get("label", node_id),
            first_seen=ev.get("timestamp", now),
            last_seen=ev.get("timestamp", now),
            attributes=ev.get("attributes", {}),
        )

    # Build edges
    edges: list[GraphEdge] = []
    for ev in filtered:
        source_id = ev.get("id", "")
        for edge_info in ev.get("edges", []):
            target_id = edge_info.get("target", "")
            if not target_id or target_id not in nodes:
                continue
            edges.append(GraphEdge(
                source=source_id,
                target=target_id,
                type=edge_info.get("type", "related_to"),
                timestamp=ev.get("timestamp", now),
                attributes=edge_info.get("attributes", {}),
            ))

    # Build clusters (connected components via undirected BFS)
    clusters = _find_clusters(nodes, edges)

    return CampaignGraphResult(
        nodes=list(nodes.values()),
        edges=edges,
        clusters=clusters,
        generated_at=now,
        window_days=window_days,
    )


def _find_clusters(
    nodes: dict[str, GraphNode],
    edges: list[GraphEdge],
) -> list[GraphCluster]:
    """Find connected components in the graph (undirected)."""
    # Build adjacency list (undirected)
    adj: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        adj[edge.source].add(edge.target)
        adj[edge.target].add(edge.source)

    visited: set[str] = set()
    clusters: list[GraphCluster] = []

    for node_id in nodes:
        if node_id in visited:
            continue
        # BFS to find all nodes in this component
        component_nodes: set[str] = set()
        queue = deque([node_id])
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            component_nodes.add(current)
            for neighbor in adj.get(current, set()):
                if neighbor not in visited:
                    queue.append(neighbor)

        # Collect edges within this component
        component_edges = [
            e for e in edges
            if e.source in component_nodes and e.target in component_nodes
        ]

        # Calculate heuristic risk score
        risk_score = _calculate_risk_score(component_nodes, component_edges, nodes)

        clusters.append(GraphCluster(
            nodes=[nodes[nid] for nid in sorted(component_nodes)],
            edges=component_edges,
            risk_score=risk_score,
        ))

    # Sort clusters by risk score descending
    clusters.sort(key=lambda c: c.risk_score, reverse=True)
    return clusters


def _calculate_risk_score(
    node_ids: set[str],
    edges: list[GraphEdge],
    nodes: dict[str, GraphNode],
) -> float:
    """Heuristic risk score for a cluster.

    Factors:
    - Number of nodes (larger = more complex campaign)
    - Number of edges (more connections = more coordination)
    - Presence of startup entries (persistence mechanism)
    - Presence of network connections (C2 communication)
    - Multiple file types involved
    """
    score = 0.0

    # Base score from size
    node_count = len(node_ids)
    edge_count = len(edges)
    score += min(node_count * 0.1, 0.3)  # up to 0.3
    score += min(edge_count * 0.05, 0.2)  # up to 0.2

    # Persistence mechanism (startup entries)
    has_startup = any(nodes[nid].type == "startup" for nid in node_ids)
    if has_startup:
        score += 0.2

    # Network communication (C2)
    has_connection = any(nodes[nid].type == "connection" for nid in node_ids)
    if has_connection:
        score += 0.15

    # Multiple file types
    file_types = {
        nodes[nid].attributes.get("file_type", "unknown")
        for nid in node_ids
        if nodes[nid].type == "file"
    }
    if len(file_types) > 1:
        score += 0.1

    # Cap at 1.0
    return min(score, 1.0)


# --------------------------------------------------------------------------- CLI output


def result_to_dict(result: CampaignGraphResult) -> dict:
    """Serialise CampaignGraphResult to a JSON-serialisable dict."""
    return {
        "command": "research-campaign-graph",
        "generated_at": result.generated_at,
        "window_days": result.window_days,
        "node_count": result.node_count,
        "edge_count": result.edge_count,
        "cluster_count": result.cluster_count,
        "nodes": [
            {
                "id": n.id,
                "type": n.type,
                "label": n.label,
                "first_seen": n.first_seen,
                "last_seen": n.last_seen,
                "attributes": n.attributes,
            }
            for n in result.nodes
        ],
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "type": e.type,
                "timestamp": e.timestamp,
                "attributes": e.attributes,
            }
            for e in result.edges
        ],
        "clusters": [
            {
                "node_count": c.node_count,
                "edge_count": c.edge_count,
                "risk_score": round(c.risk_score, 3),
                "node_ids": [n.id for n in c.nodes],
                "edge_types": list({e.type for e in c.edges}),
            }
            for c in result.clusters
        ],
    }


# ------------------------------------------------------------------ example data


def example_events() -> list[dict]:
    """Return example events demonstrating a download → execute → persist campaign.

    Timestamps are relative to "now" (anchored one hour ago) so the demo stays
    inside the rolling window used by ``build_campaign_graph``. Fixed dates made
    the campaign silently disappear once the 7-day window moved past them.
    """
    base = datetime.now(tz=timezone.utc).replace(microsecond=0) - timedelta(hours=1)

    def at(offset_seconds: int) -> str:
        return (base + timedelta(seconds=offset_seconds)).isoformat()

    return [
        {
            "id": "file1",
            "type": "file",
            "label": "downloader.exe",
            "timestamp": at(0),
            "attributes": {"file_type": "exe", "size": 45000},
            "edges": [
                {"target": "proc1", "type": "spawned"},
            ],
        },
        {
            "id": "proc1",
            "type": "process",
            "label": "downloader.exe (PID 1234)",
            "timestamp": at(5),
            "attributes": {"pid": 1234, "parent": "explorer.exe"},
            "edges": [
                {"target": "conn1", "type": "connected_to"},
                {"target": "file2", "type": "dropped"},
            ],
        },
        {
            "id": "conn1",
            "type": "connection",
            "label": "185.220.101.44:443",
            "timestamp": at(6),
            "attributes": {"ip": "185.220.101.44", "port": 443},
            "edges": [],
        },
        {
            "id": "file2",
            "type": "file",
            "label": "stage2.dll",
            "timestamp": at(7),
            "attributes": {"file_type": "dll", "size": 120000},
            "edges": [
                {"target": "proc2", "type": "spawned"},
            ],
        },
        {
            "id": "proc2",
            "type": "process",
            "label": "rundll32.exe stage2.dll (PID 5678)",
            "timestamp": at(8),
            "attributes": {"pid": 5678, "parent": "explorer.exe"},
            "edges": [
                {"target": "startup1", "type": "modified"},
            ],
        },
        {
            "id": "startup1",
            "type": "startup",
            "label": "HKCU\\Run\\stage2",
            "timestamp": at(9),
            "attributes": {"location": "registry", "key": "HKCU\\Run"},
            "edges": [],
        },
    ]
