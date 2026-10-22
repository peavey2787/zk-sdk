"""Native proving-latency regression gate (performance, not a security or correctness gate).

Target 500 ms, hard ceiling 1000 ms, at the default 116-bit full-ZK policy on this host. The
timer covers the whole prove call (key decode, preparation, witness import, the cryptographic
prove, proof encoding); nothing is excluded and no security parameter is lowered. A miss is
reported, never hidden by raising the threshold. Results: target/validation/perf-native.json.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "target" / "release" / ("zk.exe" if sys.platform == "win32" else "zk")
CIRCUITS = ("age_over", "arithmetic", "millionaires")
TARGET_MS, CEILING_MS, RUNS = 500, 1000, 20


def zk(*args):
    done = subprocess.run([str(EXE), *map(str, args)], capture_output=True, text=True, cwd=ROOT)
    if done.returncode != 0:
        raise SystemExit(f"FAIL: zk {' '.join(map(str, args))}\n{done.stdout}{done.stderr}")
    return done.stdout


def main() -> int:
    subprocess.run(["cargo", "build", "--release", "-p", "zk-cli"], cwd=ROOT, check=True)
    work = ROOT / "target" / "bench"
    work.mkdir(parents=True, exist_ok=True)
    worst = 0
    results = {}
    for name in CIRCUITS:
        data = ROOT / "testdata" / name
        r1cs, pk = data / f"{name}.r1cs", work / f"{name}.pk"
        zk("setup", "--r1cs", r1cs, "--pk", pk, "--vk", work / f"{name}.vk")
        out = zk("bench", "--pk", pk, "--r1cs", r1cs, "--sym", data / f"{name}.sym",
                 "--input", data / "input.json", "--runs", RUNS)
        print(out.strip(), flush=True)
        p50, p95, p99 = map(int, re.search(r"p50_ms=(\d+) p95_ms=(\d+) p99_ms=(\d+)", out).groups())
        results[name] = {"p50_ms": p50, "p95_ms": p95, "p99_ms": p99, "runs": RUNS}
        print(f"{name}: p50 {p50} ms, p95 {p95} ms, p99 {p99} ms (target {TARGET_MS}, ceiling {CEILING_MS})")
        worst = max(worst, p50)
    (ROOT / "target" / "validation").mkdir(parents=True, exist_ok=True)
    (ROOT / "target" / "validation" / "perf-native.json").write_text(json.dumps(results, indent=2))
    if worst > CEILING_MS:
        print(f"PERF MISS: worst p50 {worst} ms exceeds the {CEILING_MS} ms ceiling")
        return 1
    print(f"PASS: worst p50 {worst} ms" + ("" if worst <= TARGET_MS else f" (above the {TARGET_MS} ms target)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
