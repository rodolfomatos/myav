"""Local web dashboard (stdlib) for read‑only inspection of state.

The dashboard runs as a separate process, never writes any state and never
executes commands. It only reads the SQLite DB, the config file and the reports
directory and presents the information via a tiny HTTP server built on the
standard library `http.server`. All endpoints are ``GET`` (or ``HEAD``) and the
HTML page embeds its own CSS/JS – no external resources are loaded.

The design mirrors the Tkinter GUI from T034 but targets a browser. The server is
intended for local use only; binding to a non‑loopback address requires the
explicit ``--allow-remote`` flag because there is no authentication.
"""

from __future__ import annotations

import json
import sys
import webbrowser
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import __version__
from ..config import Config
from ..paths import Paths
from ..rules import status as rules_status
from ..state import State

# --------------------------------------------------------------------------- snapshot

def build_snapshot(
    state: State,
    paths: Paths,
    config: Config,
    limit: int = 50,
) -> dict[str, Any]:
    """Collect a read‑only view of the system.

    The snapshot is JSON‑serialisable and is used both for the ``/api/summary``
    endpoint and for the ``myav research web --snapshot`` CLI shortcut.
    """
    # recent scans (ordered newest first)
    scans = state.recent_scans(limit)
    # quarantine entries (excluding already restored ones)
    quarantine = state.list_quarantines(include_restored=False)
    # reports (just filenames, newest first)
    reports = sorted([p.name for p in paths.reports_dir.glob("*.md")], reverse=True)
    # YARA pack status – useful for the UI
    yara = rules_status(paths)
    # intel cache summary
    intel = state.intel_summary()
    return {
        "version": __version__,
        "config": config.public_dict(redact=True),
        "scans": scans,
        "quarantine": [asdict(q) for q in quarantine],
        "reports": reports,
        "yara": yara,
        "intel": intel,
    }

# --------------------------------------------------------------------------- HTTP handler

def _safe_report_name(name: str | None) -> bool:
    """Return ``True`` only for a bare ``.md`` filename.

    Reports are always flat files inside ``reports_dir``; anything with a
    directory component, an absolute path or traversal is refused before the
    filesystem is touched.
    """
    if not name or not name.endswith(".md"):
        return False
    candidate = Path(name)
    return candidate.name == name and not candidate.is_absolute()


class _DashboardHandler(BaseHTTPRequestHandler):
    """Serve the dashboard API and the static HTML page.

    The handler receives a ``ctx`` attribute set by the server factory – it
    contains ``state``, ``paths`` and ``config``. All data is read‑only.
    """

    def __init__(self, *args, ctx: Any = None, **kwargs):
        self.ctx = ctx
        super().__init__(*args, **kwargs)

    # ----- helpers -----
    def _json_response(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _html_response(self, html: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _method_not_allowed(self) -> None:
        self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
        self.send_header("Allow", "GET, HEAD")
        self.end_headers()

    # ----- HTTP verbs -----
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self._html_response(render_html())
            return
        if path == "/healthz":
            self._json_response({"status": "ok"})
            return
        if path == "/api/summary":
            snap = build_snapshot(self.ctx.state, self.ctx.paths, self.ctx.config)
            self._json_response(snap)
            return
        if path == "/api/scans":
            try:
                limit = int(query.get("limit", [50])[0])
            except ValueError:
                self._json_response(
                    {"error": "limit must be an integer"}, status=HTTPStatus.BAD_REQUEST
                )
                return
            self._json_response(self.ctx.state.recent_scans(limit))
            return
        if path == "/api/quarantine":
            records = self.ctx.state.list_quarantines(include_restored=False)
            self._json_response([asdict(record) for record in records])
            return
        if path == "/api/reports":
            reports = sorted(
                [p.name for p in self.ctx.paths.reports_dir.glob("*.md")], reverse=True
            )
            self._json_response(reports)
            return
        if path == "/api/report":
            name = query.get("name", [None])[0]
            if not _safe_report_name(name):
                self._json_response(
                    {"error": "invalid report name"}, status=HTTPStatus.BAD_REQUEST
                )
                return
            reports_dir = self.ctx.paths.reports_dir.resolve()
            report_path_obj = (reports_dir / name).resolve()
            if report_path_obj.parent != reports_dir or not report_path_obj.is_file():
                self._json_response({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            content = report_path_obj.read_text(encoding="utf-8")
            self._html_response(content)
            return
        if path == "/api/intel":
            self._json_response(self.ctx.state.intel_summary())
            return
        # unknown endpoint
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_HEAD(self):
        # Respond like GET but without body – reuse GET logic for status codes.
        parsed = urlparse(self.path)
        path = parsed.path
        known = {
            "/",
            "/healthz",
            "/api/summary",
            "/api/scans",
            "/api/quarantine",
            "/api/reports",
            "/api/intel",
            "/api/report",
        }
        if path in known:
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    # reject everything else
    def do_POST(self):
        self._method_not_allowed()

    def do_PUT(self):
        self._method_not_allowed()

    def do_DELETE(self):
        self._method_not_allowed()

# --------------------------------------------------------------------------- HTML rendering

def render_html() -> str:
    """Return a minimal static HTML page for the dashboard.

    The page uses a tiny amount of inline CSS and JavaScript to fetch data from
    the ``/api`` endpoints and render tables. Keeping everything in a single
    string avoids external file handling and works in the sandboxed test
    environment.
    """
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>myav dashboard</title>
<style>
body{font-family:Arial,sans-serif;margin:0;padding:0;background:#f5f5f5}
header{background:#222;color:#fff;padding:1rem;text-align:center}
section{max-width:960px;margin:auto;padding:1rem}
h2{border-bottom:1px solid #ccc;padding-bottom:.5rem}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:.5rem;text-align:left}
th{background:#eee}
</style></head>
<body><header><h1>myav dashboard</h1></header>
<section><h2>Recent scans</h2>
<table id="scans"><thead><tr>
<th>ID</th><th>Time</th><th>Path</th><th>Verdict</th><th>Kind</th>
</tr></thead><tbody></tbody></table></section>
<section><h2>Quarantine</h2>
<table id="quarantine"><thead><tr>
<th>ID</th><th>Path</th><th>Reason</th>
</tr></thead><tbody></tbody></table></section>
<section><h2>Reports</h2><ul id="reports"></ul></section>
<script>
function loadJSON(url){return fetch(url).then(r=>r.json());}
function addRow(tbody,values){
  let tr=document.createElement('tr');
  values.forEach(value=>{
    let td=document.createElement('td');
    td.textContent=value===null||value===undefined?'':String(value);
    tr.appendChild(td);
  });
  tbody.appendChild(tr);
}
function populateScans(){
  loadJSON('/api/scans').then(data=>{
    let t=document.querySelector('#scans tbody');
    t.innerHTML='';
    data.forEach(r=>addRow(t,[r.id,r.ts,r.path,r.verdict,r.kind]));
  });
}
function populateQuarantine(){
  loadJSON('/api/quarantine').then(data=>{
    let t=document.querySelector('#quarantine tbody');
    t.innerHTML='';
    data.forEach(r=>addRow(t,[r.id,r.original_path,r.reason]));
  });
}
function populateReports(){
  loadJSON('/api/reports').then(data=>{
    let ul=document.getElementById('reports');
    ul.innerHTML='';
    data.forEach(name=>{
      let li=document.createElement('li');
      let a=document.createElement('a');
      a.href=`/api/report?name=${encodeURIComponent(name)}`;
      a.textContent=name;
      li.appendChild(a);
      ul.appendChild(li);
    });
  });
}
document.addEventListener('DOMContentLoaded',()=>{
  populateScans();
  populateQuarantine();
  populateReports();
});
</script></body></html>"""

# --------------------------------------------------------------------------- server entry point

def run_server(
    ctx: Any,
    host: str = "127.0.0.1",
    port: int = 8787,
    snapshot: bool = False,
    open_browser: bool = False,
    allow_remote: bool = False,
) -> int:
    """Start the dashboard server or print a snapshot.

    Returns an exit code compatible with the CLI contract.
    """
    # Safety: disallow non‑loopback binds unless explicitly allowed.
    if not allow_remote and host not in ("127.0.0.1", "::1", "localhost"):
        print(
            "myav: refusing to bind to a non‑loopback address without --allow-remote",
            file=sys.stderr,
        )
        return 2  # EXIT_USAGE

    if snapshot:
        snap = build_snapshot(ctx.state, ctx.paths, ctx.config)
        json.dump(snap, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return 0

    def handler(*args: Any, **kwargs: Any) -> _DashboardHandler:
        return _DashboardHandler(*args, ctx=ctx, **kwargs)

    server = ThreadingHTTPServer((host, port), handler)
    url = f"http://{host}:{port}/"
    print(f"myav: dashboard listening at {url}")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
