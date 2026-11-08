"""Tests for the read-only local web dashboard (T038).

The dashboard is an observation tool: it must never mutate state and it must
never expose a file outside the reports directory. These tests exercise the
snapshot builder, the HTTP API and the CLI wiring without touching the real
user configuration or state database.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from myav import cli
from myav.paths import ensure_dirs
from myav.research import web_dashboard
from myav.state import QuarantineRecord


class FakeContext:
    def __init__(self, config, paths, state, platform, engines) -> None:
        self.config = config
        self.paths = paths
        self.state = state
        self.platform = platform
        self._engines = engines

    def engines(self):
        return self._engines


@pytest.fixture
def ctx(home, paths, state, config, platform, engines):
    ensure_dirs(paths)
    for index, verdict in enumerate(("CLEAN", "SUSPICIOUS", "MALICIOUS")):
        state.record_scan(
            path=str(home / f"file{index}.bin"),
            size=10 + index,
            sha256=str(index) * 64,
            verdict=verdict,
            engines=[{"engine": "clamav", "status": verdict}],
        )
    state.add_quarantine(
        QuarantineRecord(
            id="deadbeef",
            original_path=str(home / "bad.bin"),
            sha256="a" * 64,
            size=123,
            mode=0o644,
            mtime=0.0,
            tag="malicious",
            reason="test",
            payload=str(paths.quarantine_dir / "payload"),
        )
    )
    (paths.reports_dir / "2026-01-01-1200-full.md").write_text("# Report\nhello")
    (paths.reports_dir / "2026-01-02-1200-manual.md").write_text("# Report 2\nworld")
    return FakeContext(config, paths, state, platform, engines)


# --------------------------------------------------------------------- snapshot


def test_build_snapshot_shape_and_limit(ctx) -> None:
    snapshot = web_dashboard.build_snapshot(
        ctx.state, ctx.paths, ctx.config, limit=2
    )

    assert set(snapshot) >= {
        "version",
        "config",
        "scans",
        "quarantine",
        "reports",
        "yara",
        "intel",
    }
    assert isinstance(snapshot["version"], str)
    assert isinstance(snapshot["config"], dict)
    assert len(snapshot["scans"]) == 2
    assert snapshot["scans"][0]["path"].endswith("file2.bin")
    assert snapshot["quarantine"][0]["id"] == "deadbeef"
    assert snapshot["reports"] == [
        "2026-01-02-1200-manual.md",
        "2026-01-01-1200-full.md",
    ]
    assert isinstance(snapshot["yara"], dict)
    assert isinstance(snapshot["intel"], dict)


def test_build_snapshot_is_json_serialisable(ctx) -> None:
    snapshot = web_dashboard.build_snapshot(ctx.state, ctx.paths, ctx.config)
    assert json.loads(json.dumps(snapshot, default=str))


# ------------------------------------------------------------------------- CLI


def test_cli_snapshot_forwards_options(monkeypatch, ctx, capsys) -> None:
    monkeypatch.setattr(cli, "make_context", lambda create_dirs=True: ctx)
    calls: dict = {}

    def fake_run_server(context, **kwargs):
        calls["context"] = context
        calls.update(kwargs)
        return 0

    monkeypatch.setattr(web_dashboard, "run_server", fake_run_server)

    code = cli.main(
        [
            "research",
            "web",
            "--host",
            "127.0.0.1",
            "--port",
            "9123",
            "--snapshot",
            "--open",
            "--allow-remote",
        ]
    )

    assert code == 0
    assert calls["context"] is ctx
    assert calls["host"] == "127.0.0.1"
    assert calls["port"] == 9123
    assert calls["snapshot"] is True
    assert calls["open_browser"] is True
    assert calls["allow_remote"] is True


def test_run_server_snapshot_writes_json(ctx, capsys) -> None:
    code = web_dashboard.run_server(ctx, snapshot=True)
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"]
    assert len(payload["scans"]) == 3


def test_run_server_refuses_non_loopback_without_allow_remote(ctx, capsys) -> None:
    code = web_dashboard.run_server(ctx, host="0.0.0.0", snapshot=False)
    assert code == 2
    assert "allow-remote" in capsys.readouterr().err


def test_run_server_allows_remote_bind_with_flag(monkeypatch, ctx) -> None:
    bound: dict = {}

    class FakeServer:
        def __init__(self, address, handler):
            bound["address"] = address
            bound["handler"] = handler

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            bound["closed"] = True

    monkeypatch.setattr(web_dashboard, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(web_dashboard.webbrowser, "open", lambda url: bound.update(url=url))

    code = web_dashboard.run_server(
        ctx, host="0.0.0.0", port=8765, open_browser=True, allow_remote=True
    )

    assert code == 0
    assert bound["address"] == ("0.0.0.0", 8765)
    assert bound["url"] == "http://0.0.0.0:8765/"
    assert bound["closed"] is True


# ---------------------------------------------------------------------- server


class QuietHandler(web_dashboard._DashboardHandler):
    def log_message(self, *args, **kwargs):  # pragma: no cover - silence tests
        pass


@pytest.fixture
def live_server(ctx):
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        lambda *args, **kwargs: QuietHandler(*args, ctx=ctx, **kwargs),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    base = f"http://{host}:{port}"
    try:
        yield base
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(url: str, method: str = "GET"):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, response.headers, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


def test_server_serves_summary(live_server) -> None:
    status, headers, body = request(live_server + "/api/summary")
    assert status == 200
    assert headers["Content-Type"].startswith("application/json")
    payload = json.loads(body)
    assert "version" in payload
    assert len(payload["scans"]) == 3


def test_server_serves_scans_with_limit(live_server) -> None:
    status, _, body = request(live_server + "/api/scans?limit=1")
    assert status == 200
    scans = json.loads(body)
    assert len(scans) == 1
    assert scans[0]["path"].endswith("file2.bin")


def test_server_serves_quarantine(live_server) -> None:
    status, _, body = request(live_server + "/api/quarantine")
    assert status == 200
    quarantines = json.loads(body)
    assert quarantines[0]["id"] == "deadbeef"


def test_server_serves_reports_and_report(live_server) -> None:
    status, _, body = request(live_server + "/api/reports")
    assert status == 200
    assert json.loads(body) == [
        "2026-01-02-1200-manual.md",
        "2026-01-01-1200-full.md",
    ]

    status, headers, body = request(
        live_server + "/api/report?name=2026-01-01-1200-full.md"
    )
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert b"# Report" in body


def test_server_serves_intel_and_health(live_server) -> None:
    status, _, body = request(live_server + "/api/intel")
    assert status == 200
    assert isinstance(json.loads(body), dict)

    status, _, body = request(live_server + "/healthz")
    assert status == 200
    assert json.loads(body) == {"status": "ok"}


def test_server_serves_index(live_server) -> None:
    status, headers, body = request(live_server + "/")
    assert status == 200
    assert headers["Content-Type"].startswith("text/html")
    assert b"myav dashboard" in body

    status, _, body = request(live_server + "/index.html")
    assert status == 200
    assert b"myav dashboard" in body


@pytest.mark.parametrize(
    "name",
    ["../secret.md", "/etc/passwd", "not-markdown.txt", "..", "sub/report.md"],
)
def test_server_rejects_report_traversal(live_server, name) -> None:
    quoted = urllib.parse.quote(name, safe="")
    status, _, body = request(live_server + f"/api/report?name={quoted}")
    assert status == 400
    assert json.loads(body)["error"] == "invalid report name"


def test_server_rejects_report_symlink_escape(live_server, ctx, tmp_path) -> None:
    secret = tmp_path / "secret.md"
    secret.write_text("# secret")
    link = ctx.paths.reports_dir / "link.md"
    link.symlink_to(secret)

    status, _, body = request(live_server + "/api/report?name=link.md")
    assert status == 404
    assert json.loads(body)["error"] == "not found"


def test_server_rejects_invalid_scan_limit(live_server) -> None:
    status, _, body = request(live_server + "/api/scans?limit=abc")
    assert status == 400
    assert json.loads(body)["error"] == "limit must be an integer"


def test_server_rejects_missing_report(live_server) -> None:
    status, _, body = request(live_server + "/api/report")
    assert status == 400

    status, _, body = request(live_server + "/api/report?name=absent.md")
    assert status == 404


def test_server_rejects_unknown_path(live_server) -> None:
    status, _, _ = request(live_server + "/api/unknown")
    assert status == 404


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE"])
def test_server_rejects_mutating_methods(live_server, method) -> None:
    status, headers, _ = request(live_server + "/api/summary", method=method)
    assert status == 405
    assert headers["Allow"] == "GET, HEAD"


def test_server_head_requests(live_server) -> None:
    status, _, body = request(live_server + "/", method="HEAD")
    assert status == 200
    assert body == b""

    status, _, _ = request(live_server + "/nope", method="HEAD")
    assert status == 404


def test_render_html_is_self_contained() -> None:
    html = web_dashboard.render_html()
    assert html.startswith("<!doctype html>")
    assert "http://" not in html
    assert "https://" not in html
