#!/usr/bin/env python3
"""Groth16 trusted-setup tooling around `zk groth16` (docs/GROTH16_SETUP.md). No key is kept in the
repository: setups are made by their users from the published Hermez Powers of Tau.

usage: groth16_setup.py --fetch [--power N]
           download the published phase-1 file powersOfTau28_hez_final_N.ptau (default 14, the
           smallest that fits every circuit) into target/ptau unless a published file is already
           there, and check it with `zk groth16 phase1` (which knows the published hashes)
       groth16_setup.py --reference [--all]
           cross-check the native ceremony against the reference implementation (a pinned snarkjs in
           target/toolchain/snarkjs) on representative circuits, or on every circuit with --all:
           starting keys byte-identical to `snarkjs zkey new`, native contributions accepted by
           `snarkjs zkey verify`, snarkjs contributions accepted by `zk groth16 verify`, and beacon
           contributions byte-identical in both
"""
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "testdata" / "groth16"
PTAU_DIR = ROOT / "target" / "ptau"
PTAU_URL = "https://circom.info/powersOfTau28_hez_final_{power:02}.ptau"  # the host is not trusted: the file must match its published hash
MIN_POWER = 14  # the largest circuit's domain (constraints plus public inputs) needs 2^14

SNARKJS_VERSION = "0.7.6"
SNARKJS_HOME = ROOT / "target" / "toolchain" / "snarkjs"
SNARKJS = SNARKJS_HOME / "node_modules" / "snarkjs" / "build" / "cli.cjs"
# Small and large domains, many public inputs, Merkle paths and the arithmetic circuits.
REPRESENTATIVE = ("open_32", "compare_committed_128", "arith_128", "member8_64", "cred20_128")
BEACON = ("0badc0ffee" * 4, "10")


def run(command, stdin=None):
    result = subprocess.run([str(c) for c in command], cwd=ROOT, input=stdin, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: {' '.join(map(str, command[:4]))} ...\n{result.stdout}{result.stderr}")
    return result.stdout


def zk(*args):
    return run(["cargo", "run", "--quiet", "--release", "-p", "zk-cli", "--", "groth16", *args])


def published_files():
    return sorted(PTAU_DIR.glob("powersOfTau28_hez_final_*.ptau"), key=lambda f: int(f.stem.rsplit("_", 1)[1]))


def fetch(power):
    present = [f for f in published_files() if int(f.stem.rsplit("_", 1)[1]) >= MIN_POWER]
    if present:
        ptau = present[0]
    else:
        url = PTAU_URL.format(power=power)
        ptau = PTAU_DIR / url.rsplit("/", 1)[1]
        PTAU_DIR.mkdir(parents=True, exist_ok=True)
        print(f"downloading {url}")
        partial = ptau.with_suffix(".partial")
        urllib.request.urlretrieve(url, partial)
        partial.replace(ptau)
    print(zk("phase1", "--ptau", ptau).strip())


def ensure_snarkjs():
    if SNARKJS.exists():
        installed = json.loads((SNARKJS.parent.parent / "package.json").read_text())["version"]
        if installed == SNARKJS_VERSION:
            return
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("FAIL: npm is required for the snarkjs reference check (install Node.js)")
    SNARKJS_HOME.mkdir(parents=True, exist_ok=True)
    run([npm, "install", "--prefix", SNARKJS_HOME, f"snarkjs@{SNARKJS_VERSION}",
         "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact"])


def snarkjs(*args, stdin=None):
    return run(["node", SNARKJS, *args], stdin)


def same(a, b, what):
    if a.read_bytes() != b.read_bytes():
        raise SystemExit(f"FAIL: {what}: native and snarkjs outputs differ")


def snarkjs_accepts(name, ptau, zkey):
    if "ZKey Ok!" not in snarkjs("zkey", "verify", DATA / f"{name}.r1cs", ptau, zkey):
        raise SystemExit(f"FAIL: snarkjs zkey verify rejected the native {name} key")


def reference(name, ptau, work):
    """One circuit through every step, alternating implementations."""
    native, ours, theirs = (work / d for d in ("native", "ours", "theirs"))
    for d in (native, ours, theirs):
        d.mkdir()
    zk("initial", "--circuit", name, "--out", native / "initial.zkey", "--ptau", ptau)
    snarkjs("zkey", "new", DATA / f"{name}.r1cs", ptau, work / "initial.zkey")
    same(native / "initial.zkey", work / "initial.zkey", f"{name} starting key")

    pack, extended = work / "native.pack", work / "extended.pack"
    zk("new", "--circuits", name, "--out", pack, "--name", "native", "--ptau", ptau)
    zk("export", "--keys", pack, "--dir", native)
    snarkjs_accepts(name, ptau, native / f"{name}.zkey")
    snarkjs("zkey", "contribute", native / f"{name}.zkey", theirs / f"{name}.zkey", "--name=snarkjs",
            "-e=reference check entropy")
    zk("import", "--dir", theirs, "--circuits", name, "--out", extended)
    zk("verify", "--keys", extended, "--ptau", ptau)

    final = work / "final.pack"
    zk("contribute", "--keys", extended, "--out", final, "--name", "beacon", "--beacon", BEACON[0],
       "--beacon-exponent", BEACON[1], "--ptau", ptau)
    zk("export", "--keys", final, "--dir", ours)
    snarkjs("zkey", "beacon", theirs / f"{name}.zkey", work / "beacon.zkey", *BEACON, "-n=beacon")
    same(ours / f"{name}.zkey", work / "beacon.zkey", f"{name} beacon contribution")
    snarkjs_accepts(name, ptau, ours / f"{name}.zkey")


def check_reference(names):
    ensure_snarkjs()
    files = published_files()
    if not files:
        raise SystemExit("FAIL: no phase-1 file; run groth16_setup.py --fetch")
    for name in names:
        with tempfile.TemporaryDirectory(prefix="zk-groth16-") as work:
            reference(name, files[0], Path(work))
        print(f"PASS: {name} agrees with snarkjs {SNARKJS_VERSION}")
    print(f"PASS: {len(names)} circuits: starting keys, contributions and beacons match the reference")


def main(args):
    if "--fetch" in args:
        power = int(args[args.index("--power") + 1]) if "--power" in args else MIN_POWER
        fetch(power)
    elif "--reference" in args:
        names = sorted(p.stem for p in DATA.glob("*.r1cs")) if "--all" in args else REPRESENTATIVE
        check_reference(names)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
