"""Local web front end for CTRE (standard library only).

Serves a single-page UI on 127.0.0.1. Artifacts are uploaded into a private
temporary directory, analyzed with the same pipeline as the CLI, and deleted
when the server stops.

Because any web page open in the user's browser can try to send requests to a
localhost port, the API is hardened:

  * the server binds to loopback only;
  * the Host header must name the loopback address (blocks DNS rebinding);
  * every API call needs a custom `X-CTRE` header. Browsers will not attach a
    custom header cross-origin without a CORS preflight, and this server never
    answers preflights, so other sites cannot drive it;
  * a strict Content-Security-Policy is sent with every page.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from urllib.parse import parse_qs, urlsplit

from .gen_testdata import generate
from .service import Analysis, Options, run_analysis

KINDS = ("mft", "usnjrnl", "pcap")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
CHUNK = 1024 * 1024
DEFAULT_MAX_UPLOAD = 16 * 1024 ** 3  # 16 GiB per artifact
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


class Workspace:
    """Uploaded artifacts and the latest analysis for this server process."""

    def __init__(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="ctre-")
        self.files: dict[str, dict] = {}   # kind -> {path, name, size}
        self.analysis: Analysis | None = None
        self.lock = threading.Lock()

    def path_for(self, kind: str) -> str:
        return os.path.join(self.dir, f"{kind}.bin")

    def state(self) -> dict:
        return {
            "files": {k: {"name": v["name"], "size": v["size"]}
                      for k, v in self.files.items()},
            "has_analysis": self.analysis is not None,
        }

    def cleanup(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def _clean_name(raw: str | None, kind: str) -> str:
    # Display-only: never used to build a filesystem path.
    name = (raw or kind).replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if ch.isprintable())
    return name[:200] or kind


class Handler(BaseHTTPRequestHandler):
    server_version = "CTRE"
    sys_version = ""

    @property
    def ws(self) -> Workspace:
        return self.server.workspace  # type: ignore[attr-defined]

    # ----------------------------------------------------------------- utils
    def log_message(self, fmt, *args):  # keep the console quiet
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    def _send(self, status: int, body: bytes, ctype: str,
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in {**SECURITY_HEADERS, **(extra or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload, extra: dict | None = None) -> None:
        self._send(status, json.dumps(payload).encode(),
                   "application/json; charset=utf-8", extra)

    def _error(self, status: int, message: str) -> None:
        self._json(status, {"error": message})

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        port = self.server.server_address[1]
        return host in {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _api_ok(self) -> bool:
        if self.headers.get("X-CTRE") != "1":
            self._error(HTTPStatus.FORBIDDEN, "missing X-CTRE header")
            return False
        return True

    def _drain(self) -> None:
        # Read and discard a request body we are rejecting, so the client
        # sees our response instead of a reset connection.
        remaining = int(self.headers.get("Content-Length") or 0)
        while remaining > 0:
            got = self.rfile.read(min(CHUNK, remaining))
            if not got:
                break
            remaining -= len(got)

    # --------------------------------------------------------------- routing
    def do_GET(self):
        if not self._host_ok():
            return self._error(HTTPStatus.FORBIDDEN, "bad Host header")
        path = urlsplit(self.path).path
        if path in STATIC:
            fname, ctype = STATIC[path]
            body = resources.files("ctre").joinpath("web", fname).read_bytes()
            return self._send(HTTPStatus.OK, body, ctype)
        if path == "/api/state":
            if not self._api_ok():
                return
            with self.ws.lock:
                return self._json(HTTPStatus.OK, self.ws.state())
        if path in ("/api/report", "/api/export"):
            if not self._api_ok():
                return
            with self.ws.lock:
                analysis = self.ws.analysis
            if analysis is None:
                return self._error(HTTPStatus.CONFLICT, "run an analysis first")
            if path == "/api/report":
                return self._send(
                    HTTPStatus.OK, analysis.report_html().encode("utf-8"),
                    "text/html; charset=utf-8",
                    {"Content-Disposition":
                     'attachment; filename="ctre-report.html"'})
            return self._send(
                HTTPStatus.OK,
                json.dumps(analysis.to_json(), indent=2).encode(),
                "application/json; charset=utf-8",
                {"Content-Disposition":
                 'attachment; filename="ctre-results.json"'})
        return self._error(HTTPStatus.NOT_FOUND, "not found")

    do_HEAD = do_GET

    def do_POST(self):
        if not self._host_ok():
            self._drain()
            return self._error(HTTPStatus.FORBIDDEN, "bad Host header")
        if not self._api_ok():
            self._drain()
            return
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        route = {
            "/api/upload": self._upload,
            "/api/remove": self._remove,
            "/api/sample": self._sample,
            "/api/analyze": self._analyze,
        }.get(url.path)
        if route is None:
            self._drain()
            return self._error(HTTPStatus.NOT_FOUND, "not found")
        route(query)

    # ------------------------------------------------------------- handlers
    def _upload(self, query) -> None:
        kind = (query.get("kind") or [""])[0]
        if kind not in KINDS:
            self._drain()
            return self._error(HTTPStatus.BAD_REQUEST, "unknown artifact kind")
        try:
            length = int(self.headers.get("Content-Length") or -1)
        except ValueError:
            length = -1
        if length < 0:
            return self._error(HTTPStatus.LENGTH_REQUIRED,
                               "Content-Length required")
        if length > self.server.max_upload:  # type: ignore[attr-defined]
            self._drain()
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                               "artifact too large")
        name = _clean_name((query.get("name") or [None])[0], kind)
        dest = self.ws.path_for(kind)
        tmp = dest + ".part"
        remaining = length
        with open(tmp, "wb") as fh:
            while remaining > 0:
                chunk = self.rfile.read(min(CHUNK, remaining))
                if not chunk:
                    break
                fh.write(chunk)
                remaining -= len(chunk)
        if remaining:
            os.remove(tmp)
            return self._error(HTTPStatus.BAD_REQUEST, "upload incomplete")
        with self.ws.lock:
            os.replace(tmp, dest)
            self.ws.files[kind] = {"path": dest, "name": name, "size": length}
            self.ws.analysis = None
            return self._json(HTTPStatus.OK, self.ws.state())

    def _remove(self, query) -> None:
        self._drain()
        kind = (query.get("kind") or [""])[0]
        with self.ws.lock:
            if kind == "all":
                kinds = list(self.ws.files)
            elif kind in KINDS:
                kinds = [kind]
            else:
                return self._error(HTTPStatus.BAD_REQUEST, "unknown kind")
            for k in kinds:
                info = self.ws.files.pop(k, None)
                if info and os.path.exists(info["path"]):
                    os.remove(info["path"])
            self.ws.analysis = None
            return self._json(HTTPStatus.OK, self.ws.state())

    def _sample(self, query) -> None:
        self._drain()
        with self.ws.lock:
            sample_dir = os.path.join(self.ws.dir, "sample")
            generated = generate(sample_dir)
            for kind in KINDS:
                dest = self.ws.path_for(kind)
                os.replace(generated[kind], dest)
                self.ws.files[kind] = {
                    "path": dest,
                    "name": "sample " + os.path.basename(generated[kind]),
                    "size": os.path.getsize(dest),
                }
            self.ws.analysis = None
            return self._json(HTTPStatus.OK, self.ws.state())

    def _analyze(self, query) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 64 * 1024:
            self._drain()
            return self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                               "options too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
            opts = Options(
                min_exfil_bytes=int(body.get("min_exfil_bytes", 100_000)),
                window_minutes=float(body.get("window_minutes", 5)),
                mft_record_size=int(body.get("mft_record_size", 1024)),
            )
        except (ValueError, TypeError, AttributeError):
            return self._error(HTTPStatus.BAD_REQUEST, "invalid options")
        if not (opts.min_exfil_bytes >= 0 and 0 < opts.window_minutes <= 1440
                and opts.mft_record_size in (1024, 4096)):
            return self._error(HTTPStatus.BAD_REQUEST, "option out of range")

        with self.ws.lock:
            paths = {k: v["path"] for k, v in self.ws.files.items()}
            names = {k: v["name"] for k, v in self.ws.files.items()}
            try:
                analysis = run_analysis(paths, opts, names)
            except (OSError, ValueError) as exc:
                return self._error(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc))
            self.ws.analysis = analysis
            return self._json(HTTPStatus.OK, analysis.to_json())


def make_server(port: int = 8765, max_upload: int = DEFAULT_MAX_UPLOAD,
                verbose: bool = False) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.daemon_threads = True
    httpd.workspace = Workspace()  # type: ignore[attr-defined]
    httpd.max_upload = max_upload  # type: ignore[attr-defined]
    httpd.verbose = verbose        # type: ignore[attr-defined]
    return httpd


def serve(port: int = 8765, open_browser: bool = True,
          verbose: bool = False) -> int:
    httpd = make_server(port, verbose=verbose)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"CTRE web UI running at {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.5, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        httpd.server_close()
        httpd.workspace.cleanup()  # type: ignore[attr-defined]
    return 0
