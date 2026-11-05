"""Campaign correlation graph tests (research track).

These tests verify the measurement tooling only — no detection feature ships
as part of MYAV Core from this ticket.
"""

from __future__ import annotations

from myav.research.campaign_graph import (
    GraphCluster,
    GraphEdge,
    GraphNode,
    build_campaign_graph,
    example_events,
    result_to_dict,
)


def test_example_events_structure() -> None:
    events = example_events()
    assert len(events) == 6
    ids = {e["id"] for e in events}
    assert "file1" in ids  # downloader.exe
    assert "proc1" in ids  # downloader.exe process
    assert "conn1" in ids  # network connection
    assert "file2" in ids  # stage2.dll
    assert "proc2" in ids  # rundll32 process
    assert "startup1" in ids  # registry run key


def test_build_campaign_graph_basic() -> None:
    events = example_events()
    result = build_campaign_graph(events, window_days=7)

    assert result.node_count == 6
    assert result.edge_count >= 4  # edges: file1->proc1, proc1->conn1, etc.
    assert result.cluster_count == 1  # all connected
    assert result.window_days == 7

    # Check we have all expected node types
    types = {n.type for n in result.nodes}
    assert "file" in types
    assert "process" in types
    assert "connection" in types
    assert "startup" in types


def test_build_campaign_graph_risk_score() -> None:
    events = example_events()
    result = build_campaign_graph(events, window_days=7)

    assert len(result.clusters) == 1
    cluster = result.clusters[0]
    assert 0.0 <= cluster.risk_score <= 1.0
    # This campaign has startup + connection + multiple files, so should be elevated
    assert cluster.risk_score > 0.2


def test_build_campaign_graph_empty() -> None:
    result = build_campaign_graph([], window_days=7)

    assert result.node_count == 0
    assert result.edge_count == 0
    assert result.cluster_count == 0


def test_result_to_dict() -> None:
    events = example_events()
    result = build_campaign_graph(events, window_days=7)
    d = result_to_dict(result)

    assert d["command"] == "research-campaign-graph"
    assert d["window_days"] == 7
    assert d["node_count"] == 6
    assert d["edge_count"] >= 4
    assert d["cluster_count"] == 1
    assert len(d["nodes"]) == 6
    assert len(d["clusters"]) == 1
    assert "risk_score" in d["clusters"][0]


def test_graph_node_dataclass() -> None:
    n = GraphNode(
        id="n1",
        type="file",
        label="test.exe",
        first_seen="2026-11-01T10:00:00+00:00",
        last_seen="2026-11-01T10:00:00+00:00",
    )
    assert n.id == "n1"
    assert n.type == "file"
    assert n.label == "test.exe"


def test_graph_edge_dataclass() -> None:
    e = GraphEdge(
        source="n1",
        target="n2",
        type="spawned",
        timestamp="2026-11-01T10:00:00+00:00",
    )
    assert e.source == "n1"
    assert e.target == "n2"
    assert e.type == "spawned"


def test_graph_cluster_dataclass() -> None:
    n1 = GraphNode(id="n1", type="file", label="a.exe", first_seen="t", last_seen="t")
    n2 = GraphNode(id="n2", type="process", label="proc", first_seen="t", last_seen="t")
    e1 = GraphEdge(source="n1", target="n2", type="spawned", timestamp="t")
    c = GraphCluster(nodes=[n1, n2], edges=[e1], risk_score=0.5)
    assert c.node_count == 2
    assert c.edge_count == 1
    assert c.risk_score == 0.5


def test_window_days_filter() -> None:
    """Events outside the window should be excluded."""
    old_event = {
        "id": "old_file",
        "type": "file",
        "label": "old.exe",
        "timestamp": "2026-01-01T10:00:00+00:00",
        "attributes": {},
        "edges": [],
    }
    recent_event = {
        "id": "recent_file",
        "type": "file",
        "label": "recent.exe",
        "timestamp": "2026-11-04T10:00:00+00:00",
        "attributes": {},
        "edges": [],
    }
    result = build_campaign_graph([old_event, recent_event], window_days=7)
    # Only the recent event should be in the graph (old is >7 days from now)
    assert result.node_count == 1
    assert result.nodes[0].id == "recent_file"
