"""Optimized native build: targets x86-64-v3 (AVX2, BMI2) and installs it as `zk-avx2` next to
the portable `target/release/zk`.

The portable `zk` stays the entry point and runs on any x86-64 CPU; when the CPU has AVX2 and BMI2
and `zk-avx2` sits beside it, it hands the invocation over (see `crates/zk-cli/src/dispatch.rs`).
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
flags = os.environ.get("RUSTFLAGS", "") + " -C target-cpu=x86-64-v3"
env = {**os.environ, "RUSTFLAGS": flags.strip()}
command = ["cargo", "build", "--release", "-p", "zk-cli", "--target-dir", str(ROOT / "target" / "optimized")]
code = subprocess.run(command, cwd=ROOT, env=env).returncode
if code == 0:
    exe = ".exe" if os.name == "nt" else ""
    (ROOT / "target" / "release").mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "target" / "optimized" / "release" / f"zk{exe}", ROOT / "target" / "release" / f"zk-avx2{exe}")
sys.exit(code)
