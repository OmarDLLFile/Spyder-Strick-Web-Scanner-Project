"""Intentionally vulnerable local test app (stdlib only) for the test suite.
Serves: reflected XSS, SQL error, traversal, redirect, missing headers,
OpenAPI spec, GraphQL stub, BOLA endpoints, login form. For tests only.
"""
from __future__ import annotations
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

OPENAPI = {"openapi": "3.0.0", "info": {"title": "Test API", "version": "1.0"},
           "paths": {"/api/users/{id}": {"get": {"responses": {"200": {"description": "ok"}}}},
                      "/api/users": {"get": {"responses": {"200": {"description": "ok"}}}}}}

USERS = {"1": {"id": 1, "name": "Alice", "email": "alice@example.com", "password": "secret1"},
         "2": {"id": 2, "name": "Bob", "email": "bob@example.com", "password": "secret2"}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, code=200, ctype="text/html"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = urlparse(self.path)
        q = parse_qs(p.query)
        if p.path == "/":
            self._send('<html><body><a href="/search?q=test">search</a> '
                       '<a href="/page">page</a> <a href="/api/users/1">user</a>'
                       '<form action="/search" method="get"><input name="q" type="text">'
                       '<input name="comment" type="text"></form>'
                       '<form action="/login" method="post"><input name="username"><input name="password" type="password">'
                       '<input name="csrf_token" type="hidden" value="abc"></form>'
                       '<script src="/app.js"></script></body></html>')
        elif p.path == "/app.js":
            self._send('fetch("/api/users/1").then(r=>r.json());', ctype="application/javascript")
        elif p.path == "/search":
            val = q.get("q", [""])[0]
            if "'" in val:
                self._send(f"<html>you have an error in your sql syntax near '{val}'</html>")
            else:
                self._send(f"<html>Results for {val}</html>")
        elif p.path == "/page":
            self._send("<html><body>plain page</body></html>")
        elif p.path == "/file":
            f = q.get("file", [""])[0]
            if "passwd" in f:
                self._send("root:x:0:0:root:/root:/bin/bash\n")
            else:
                self._send("file not found", 404)
        elif p.path == "/go":
            nxt = q.get("next", [""])[0]
            if nxt:
                self.send_response(302)
                self.send_header("Location", nxt)
                self.end_headers()
            else:
                self._send("go")
        elif p.path == "/openapi.json":
            self._send(json.dumps(OPENAPI), ctype="application/json")
        elif p.path.startswith("/api/users/"):
            uid = p.path.rsplit("/", 1)[-1]
            u = USERS.get(uid)
            if u:
                self._send(json.dumps(u), ctype="application/json")
            else:
                self._send("not found", 404)
        elif p.path == "/api/users":
            self._send(json.dumps(list(USERS.values())), ctype="application/json")
        elif p.path == "/graphql":
            self._send(json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}}), ctype="application/json")
        elif p.path == "/admin":
            self._send("<html><body>Admin dashboard - users management</body></html>")
        elif p.path == "/.well-known/openid-configuration":
            self._send(json.dumps({"issuer": "http://test/"}), ctype="application/json")
        else:
            self._send("not found", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        if urlparse(self.path).path == "/graphql":
            self._send(json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}}), ctype="application/json")
        else:
            self._send("ok")


def start(port=0):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    import threading
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
