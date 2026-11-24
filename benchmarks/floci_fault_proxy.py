"""Local HTTP fault proxy that forwards normal requests to real Floci."""

import http.client
import re
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlencode


@contextmanager
def fault_proxy(mode: str, upstream_port: int = 4566):
    if mode not in {"throttle", "timeout", "malformed_xml", "missing_marker"}:
        raise ValueError("Unsupported Floci fault mode")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self._forward(None)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            action = dict(parse_qsl(body.decode("utf-8", "replace"))).get("Action")
            if action == "ListUsers":
                if mode == "throttle":
                    payload = ("<ErrorResponse><Error><Code>Throttling</Code>"
                               "<Message>Injected local fault</Message></Error></ErrorResponse>").encode()
                    self._reply(400, payload, "text/xml")
                    return
                if mode == "timeout":
                    time.sleep(0.5)
                if mode == "malformed_xml":
                    self._reply(200, b"<ListUsersResponse><broken", "text/xml")
                    return
                if mode == "missing_marker":
                    pairs = [(key, value) for key, value in parse_qsl(body.decode()) if key != "MaxItems"]
                    pairs.append(("MaxItems", "10"))
                    body = urlencode(pairs).encode()
            self._forward(body, missing_marker=action == "ListUsers" and mode == "missing_marker")

        def _forward(self, body, *, missing_marker=False):
            upstream = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=5)
            headers = {"Content-Type": self.headers.get("Content-Type", "application/x-www-form-urlencoded")}
            try:
                upstream.request(self.command, self.path, body=body, headers=headers)
                response = upstream.getresponse()
                payload = response.read()
                if missing_marker:
                    payload = re.sub(rb"<Marker>[^<]*</Marker>", b"", payload, count=1)
                self._reply(response.status, payload, response.getheader("Content-Type", "text/xml"))
            finally:
                upstream.close()

        def _reply(self, status, payload, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
