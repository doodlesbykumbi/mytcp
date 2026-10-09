#!/usr/bin/env python3
"""Serve the deck, plus read-only repo source for the in-deck code viewer.

    python3 serve.py [port]

/            → docs/talk (the Reveal deck)
/src/index.json → {"root": "/abs/path/to/mytcp", "files": ["cmd/mytcp/main.go", ...]}
/src/<path>  → a source file from the repo (only the extensions below)
"""

import http.server
import json
import pathlib
import sys
import urllib.parse

TALK = pathlib.Path(__file__).resolve().parent
REPO = TALK.parent.parent
SOURCE_DIRS = ("cmd", "internal", "scripts")
# Only the stack itself — no markdown, Makefile, or other top-level docs.
SOURCE_EXTS = {".go", ".sh"}


def source_files():
    files = []
    for d in SOURCE_DIRS:
        for p in sorted((REPO / d).rglob("*")):
            if p.is_file() and p.suffix in SOURCE_EXTS:
                files.append(p.relative_to(REPO).as_posix())
    return files


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(TALK), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if not path.startswith("/src/"):
            return super().do_GET()
        rel = urllib.parse.unquote(path[len("/src/"):])
        if rel == "index.json":
            return self.send_bytes(
                json.dumps({"root": str(REPO), "files": source_files()}).encode(),
                "application/json",
            )
        if rel not in source_files():
            return self.send_error(404, "not a source file")
        self.send_bytes((REPO / rel).read_bytes(), "text/plain; charset=utf-8")

    def send_bytes(self, body, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8766
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler) as httpd:
        print(f"Serving deck on http://127.0.0.1:{port}/")
        httpd.serve_forever()
