"""Real-browser test: serve web/ and read a page's #result (default selftest.html; perftest.html for
timings; optional second argument: timeout in seconds) from headless Edge or Chrome over CDP."""
import functools
import http.server
import shutil
import subprocess
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANDIDATES = [
    "chrome", "google-chrome", "chromium", "chromium-browser", "msedge",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def find_browser():
    for name in CANDIDATES:
        found = shutil.which(name) or (name if Path(name).is_file() else None)
        if found:
            return found
    return None


def main(page: str, timeout: str) -> int:
    browser = find_browser()
    if browser is None:
        print("NOT VALIDATED: no Chrome/Edge/Chromium found for the browser test")
        return 1
    handler = functools.partial(QuietHandler, directory=str(ROOT / "web"))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_port}/{page}"
    profile = ROOT / "target" / "browser-profile"
    port = 9333
    process = subprocess.Popen([browser, "--headless=new", "--disable-gpu", f"--user-data-dir={profile}",
                                f"--remote-debugging-port={port}", "about:blank"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        done = subprocess.run(["node", str(ROOT / "scripts" / "cdp_result.cjs"), str(port), url, timeout])
    finally:
        process.kill()
        server.shutdown()
    return done.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "selftest.html", sys.argv[2] if len(sys.argv) > 2 else "600"))
