"""A deliberately weak local web site used as a scan target in tests. Never expose it to a network."""
import http.server
import sys
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/ssai-not-found"):
            return self._send(404, "<pre>Traceback (most recent call last):\n  File app.py, line 3</pre>")
        if self.path.startswith("/."):
            return self._send(404, "nope")
        page = '<html><body><form method="post" action="/login"><input type="password" name="p"></form></body></html>'
        self._send(200, page, extra={"Set-Cookie": "PHPSESSID=abc123; Path=/"})


def serve(port: int = 0):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


if __name__ == "__main__":
    s = serve(int(sys.argv[1]) if len(sys.argv) > 1 else 0)
    print(s.server_address[1], flush=True)
    threading.Event().wait()
