#!/usr/bin/env bash
# usage: ./run-all-linux.sh [fast|full|groth16-all|perf]   (default: fast)
set -euo pipefail
cd "$(dirname "$0")"
command -v cargo >/dev/null || { echo "FAIL: Cargo toolchain not installed"; exit 1; }
command -v python3 >/dev/null || { echo "FAIL: Python 3 not installed"; exit 1; }
exec python3 scripts/run_all.py "${1:-fast}"
