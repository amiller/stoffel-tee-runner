#!/usr/bin/env python3
"""Mock of the stoffel-lobby API (issue #4).

Serves the webapp (../index.html and friends) and the three GET routes the
page consumes, so page and API are same-origin and the mock needs no CORS.

    GET /nodes               -> NodeRecord[] of the mounted bundle fixture
    GET /jobs                -> the synthetic mock jobs + the mounted job
    GET /jobs/{id}/bundle    -> the mounted EvidenceBundle, 404 otherwise

The bundle fixtures are the real evidence-grade ones from issue #1
(evidence/bundles/*.json, each carrying a real TDX quote and DCAP collateral).
All four fixtures share one job_id, so exactly one is mounted per run:

    python3 web/mock/serve.py tampered-measurement.json

The service's POST routes and its 409 "lifecycle incomplete" case are not
mocked: the page is read-only and only consumes these three GETs.
"""

import json
import sys
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

WEB = Path(__file__).resolve().parent.parent          # web/
BUNDLES = WEB.parent / "evidence" / "bundles"
MOCK_JOBS = WEB / "mock" / "data" / "mock-jobs.json"


def load_bundle(name):
    path = BUNDLES / name
    if not name.endswith(".json") or not path.is_file():
        sys.exit(f"unknown fixture {name!r}; expected one of "
                 f"{sorted(p.name for p in BUNDLES.glob('*.json'))}")
    bundle = json.loads(path.read_text())
    for field in ("version", "job", "nodes", "joins", "results"):
        if field not in bundle:
            sys.exit(f"fixture {name} is not an EvidenceBundle: no {field!r}")
    return bundle


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB), **kwargs)

    def send_json(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/nodes":
            return self.send_json(200, BUNDLE["nodes"])
        if path == "/jobs":
            return self.send_json(200, MOCK_JOBS_DATA + [BUNDLE["job"]])
        prefix = "/jobs/"
        suffix = "/bundle"
        if path.startswith(prefix) and path.endswith(suffix):
            job_id = path[len(prefix):-len(suffix)]
            if job_id == BUNDLE["job"]["job_id"]:
                return self.send_json(200, BUNDLE)
            return self.send_json(404, {"error": "unknown job"})
        super().do_GET()  # the page itself: /, /app.js, /style.css

    def log_message(self, fmt, *args):
        pass  # keep the one-command demo quiet; errors still raise


if __name__ == "__main__":
    fixture = sys.argv[1] if len(sys.argv) > 1 else "tampered-measurement.json"
    BUNDLE = load_bundle(fixture)
    MOCK_JOBS_DATA = json.loads(MOCK_JOBS.read_text())
    host, port = "127.0.0.1", 8081
    url = f"http://{host}:{port}/"
    print(f"mock lobby + page on {url} (fixture {fixture}, "
          f"job {BUNDLE['job']['job_id'][:16]}…, Ctrl-C to stop)", flush=True)
    # Threading, not the single-threaded HTTPServer: browsers open speculative
    # preconnects that send no request, and a single-threaded server blocks on
    # the first one while every real request waits behind it.
    ThreadingHTTPServer((host, port), Handler).serve_forever()
