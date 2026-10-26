"""Serve web/ on http://localhost:PORT (default 8000) cross-origin isolated, so the browser worker
loads the multi-threaded bundle. Any static host works if it sends the same two headers:
`Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp`."""
import functools
import http.server
import sys

from browser_test import ROOT, QuietHandler

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
handler = functools.partial(QuietHandler, directory=str(ROOT / "web"))
print(f"serving http://localhost:{port} (cross-origin isolated)")
http.server.ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever()
