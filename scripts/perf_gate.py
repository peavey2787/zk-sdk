"""Native proving-latency gate: median wall time of the full prove, per circuit.

Target 500 ms, hard ceiling 1000 ms, at the default 116-bit full-ZK policy on this host. The
timer covers the whole prove call (key decode, preparation, witness import, the cryptographic
prove, proof encoding); nothing is excluded and no security parameter is lowered.
"""
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
    for name in CIRCUITS:
        data = ROOT / "testdata" / name
        r1cs, pk = data / f"{name}.r1cs", work / f"{name}.pk"
        zk("setup", "--r1cs", r1cs, "--pk", pk, "--vk", work / f"{name}.vk")
        out = zk("bench", "--pk", pk, "--r1cs", r1cs, "--sym", data / f"{name}.sym",
                 "--input", data / "input.json", "--runs", RUNS)
        print(out.strip(), flush=True)
        median, p95 = map(int, re.search(r"median_ms=(\d+) p95_ms=(\d+)", out).groups())
        print(f"{name}: median {median} ms, p95 {p95} ms (target {TARGET_MS}, ceiling {CEILING_MS})")
        worst = max(worst, median)
    if worst > CEILING_MS:
        print(f"FAIL: median {worst} ms exceeds the {CEILING_MS} ms ceiling")
        return 1
    print(f"PASS: worst median {worst} ms" + ("" if worst <= TARGET_MS else f" (above the {TARGET_MS} ms target)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
