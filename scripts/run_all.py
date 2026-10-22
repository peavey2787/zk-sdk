#!/usr/bin/env python3
"""Validation driver behind run-all-windows.cmd and run-all-linux.sh.

fast: layout, pinned revisions, fmt, clippy -D warnings, tests (real prove/verify, no mocks).
full: fast plus the wasm bundle, real-browser test, native/wasm interop matrix and cargo audit
      (security and correctness gates).
perf: separate performance regression gates (native and real-browser p50/p95/p99 against the
      500 ms target / 1000 ms ceiling). A miss is reported as such; it is never a reason to lower
      security parameters or raise the threshold.
Logs and a timing report land in target/validation/.
"""
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "target" / "validation"
PY = sys.executable
CARGO = ["cargo"]

FAST = [
    ("layout", [PY, "scripts/check-layout.py"]),
    ("pins", None),
    ("fmt", CARGO + ["fmt", "--all", "--", "--check"]),
    ("clippy", CARGO + ["clippy", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"]),
    ("test", CARGO + ["test", "--workspace", "--all-targets", "--all-features", "--release"]),
]
FULL = [
    ("wasm-build", [PY, "scripts/build_wasm.py"]),
    ("browser", [PY, "scripts/browser_test.py"]),
    ("interop", [PY, "scripts/interop.py"]),
    ("audit", CARGO + ["audit", "--deny", "warnings"]),
]
PERF = [
    ("wasm-build", [PY, "scripts/build_wasm.py"]),
    ("perf-native", [PY, "scripts/perf_gate.py"]),
    ("perf-browser", [PY, "scripts/browser_test.py", "perftest.html"]),
]


def check_pins() -> bool:
    """Every git dependency must name an exact revision, and the lockfile must agree."""
    manifests = [ROOT / "Cargo.toml", *ROOT.glob("crates/*/Cargo.toml")]
    for manifest in manifests:
        for line in manifest.read_text().splitlines():
            if "git =" in line and not re.search(r'rev = "[0-9a-f]{40}"', line):
                print(f"unpinned git dependency in {manifest}: {line.strip()}")
                return False
    lock = (ROOT / "Cargo.lock").read_text()
    unpinned = re.findall(r'source = "git\+[^"#]*"(?!#)', lock)
    if unpinned:
        print(f"lockfile git sources without commit: {unpinned}")
    return not unpinned


def run(name, command) -> bool:
    log = OUT / f"{name}.log"
    with log.open("w", encoding="utf-8") as handle:
        if command is None:
            ok = check_pins()
        else:
            command = [shutil.which(command[0]) or command[0], *command[1:]]
            ok = subprocess.run(command, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT).returncode == 0
    return ok


def main(mode: str) -> int:
    if mode not in ("fast", "full", "perf"):
        print("usage: run_all.py [fast|full|perf]")
        return 2
    OUT.mkdir(parents=True, exist_ok=True)
    steps = {"fast": FAST, "full": FAST + FULL, "perf": PERF}[mode]
    report = []
    for name, command in steps:
        start = time.monotonic()
        ok = run(name, command)
        seconds = time.monotonic() - start
        report.append(f"{'PASS' if ok else 'FAIL'}  {name:<11} {seconds:8.1f}s  log: {OUT / (name + '.log')}")
        print(report[-1], flush=True)
        if not ok:
            print((OUT / f"{name}.log").read_text(encoding="utf-8", errors="replace")[-3000:])
            break
    else:
        report.append(f"PASS: {mode} validation complete (platforms other than this host are NOT VALIDATED)")
        print(report[-1])
    (OUT / "report.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
    return 0 if report[-1].startswith("PASS:") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "fast"))
