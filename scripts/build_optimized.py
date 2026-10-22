"""Optional optimized native build: targets x86-64-v3 (AVX2, BMI2) into target/optimized.

The default `cargo build --release` stays portable and runs on any x86-64 CPU. This build is
several times faster for proving but will not start on CPUs without AVX2.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
flags = os.environ.get("RUSTFLAGS", "") + " -C target-cpu=x86-64-v3"
env = {**os.environ, "RUSTFLAGS": flags.strip()}
command = ["cargo", "build", "--release", "-p", "zk-cli", "--target-dir", str(ROOT / "target" / "optimized")]
sys.exit(subprocess.run(command, cwd=ROOT, env=env).returncode)
