#!/usr/bin/env python3
"""Groth16 trusted setup for the BN254 predicate circuits in testdata/groth16 (docs/GROTH16_SETUP.md).

Phase 1 is the public Hermez/iden3 Powers of Tau (54 contributions plus a beacon), downloaded once
into target/ptau and checked against the BLAKE2b-512 hash the snarkjs README publishes. Phase 2 runs
per circuit with a pinned snarkjs installed into target/toolchain/snarkjs:

  groth16 setup   -> zkey contribute (one secret contribution: 64 bytes of OS entropy fed on stdin,
                     never written anywhere; snarkjs mixes in its own randomness)
                  -> zkey beacon (public drand randomness fetched after every contribution is made)
                  -> zkey verify (against the r1cs and the ptau) -> export the verification key

Outputs: testdata/groth16/<name>.zkey and <name>.vkey.json, testdata/groth16/setup.json (the
transcript: snarkjs version, ptau hash, beacon, per-circuit hashes) and crates/zk-groth16/src/
approved.rs (the SHA-256 identity of every bundled r1cs and zkey).

usage: groth16_setup.py          new phase 2 for every circuit (new keys; old proofs stop verifying)
       groth16_setup.py --check  re-verify every committed zkey against its r1cs and the ptau
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "testdata" / "groth16"
WORK = ROOT / "target" / "groth16-setup"
APPROVED = ROOT / "crates" / "zk-groth16" / "src" / "approved.rs"

SNARKJS_VERSION = "0.7.6"
SNARKJS_HOME = ROOT / "target" / "toolchain" / "snarkjs"
SNARKJS = SNARKJS_HOME / "node_modules" / "snarkjs" / "build" / "cli.cjs"

PTAU = ROOT / "target" / "ptau" / "powersOfTau28_hez_final_16.ptau"
PTAU_URL = "https://circom.info/powersOfTau28_hez_final_16.ptau"
PTAU_BLAKE2B = (
    "6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf4"
    "3eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125"
)
DRAND = "https://api.drand.sh/public/latest"
BEACON_ITERATIONS_EXP = 10


def run(command, stdin=None):
    result = subprocess.run(command, cwd=ROOT, input=stdin, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: {' '.join(map(str, command[:3]))} ...\n{result.stdout}{result.stderr}")
    return result.stdout


def snarkjs(*args, stdin=None):
    return run(["node", str(SNARKJS), *map(str, args)], stdin)


def ensure_snarkjs():
    if SNARKJS.exists():
        installed = json.loads((SNARKJS.parent.parent / "package.json").read_text())["version"]
        if installed == SNARKJS_VERSION:
            return
    SNARKJS_HOME.mkdir(parents=True, exist_ok=True)
    npm = shutil.which("npm") or raise_missing("npm")
    run([npm, "install", "--prefix", str(SNARKJS_HOME), f"snarkjs@{SNARKJS_VERSION}",
         "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact"])


def raise_missing(tool):
    raise SystemExit(f"FAIL: {tool} is required (install Node.js)")


def blake2b(path):
    digest = hashlib.blake2b()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_ptau():
    if not PTAU.exists():
        PTAU.parent.mkdir(parents=True, exist_ok=True)
        print(f"downloading {PTAU.name} (~76 MB) from {PTAU_URL}")
        partial = PTAU.with_suffix(".partial")
        urllib.request.urlretrieve(PTAU_URL, partial)
        partial.replace(PTAU)
    if blake2b(PTAU) != PTAU_BLAKE2B:
        raise SystemExit(f"FAIL: {PTAU} does not match the published BLAKE2b-512 hash")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def circuits():
    return sorted(p.stem for p in DATA.glob("*.r1cs"))


def contribution_hash(output):
    match = re.search(r"Contribution Hash:\s*((?:\s*[0-9a-f]{8}){16})", output)
    if not match:
        raise SystemExit("FAIL: snarkjs printed no contribution hash")
    return "".join(match.group(1).split())


def contribute(name):
    r1cs = DATA / f"{name}.r1cs"
    initial, contributed, final = (WORK / f"{name}_{i}.zkey" for i in range(3))
    snarkjs("groth16", "setup", r1cs, PTAU, initial)
    entropy = os.urandom(64).hex()
    output = snarkjs("zkey", "contribute", initial, contributed,
                     "--name=zk-sdk phase 2 (single contributor)", stdin=entropy + "\n")
    del entropy
    return contributed, final, contribution_hash(output)


def finish(name, contributed, final, beacon):
    snarkjs("zkey", "beacon", contributed, final, beacon["randomness"], BEACON_ITERATIONS_EXP,
            f"--name=drand round {beacon['round']}")
    verify(name, final)
    zkey = DATA / f"{name}.zkey"
    shutil.copyfile(final, zkey)
    snarkjs("zkey", "export", "verificationkey", zkey, DATA / f"{name}.vkey.json")


def verify(name, zkey):
    output = snarkjs("zkey", "verify", DATA / f"{name}.r1cs", PTAU, zkey)
    if "ZKey Ok!" not in output:
        raise SystemExit(f"FAIL: zkey verify rejected {name}\n{output}")


def fetch_beacon():
    with urllib.request.urlopen(DRAND, timeout=30) as response:
        latest = json.load(response)
    return {"source": DRAND, "round": latest["round"], "randomness": latest["randomness"]}


def approved_rs(names):
    lines = [
        "// GENERATED by scripts/groth16_setup.py; do not edit.",
        "// Approved BN254 predicate circuits: the SHA-256 of each bundled r1cs and zkey is its identity.",
        "",
        "use crate::bundle::Bundled;",
        "",
        "pub(crate) const BUNDLED: &[Bundled] = &[",
    ]
    for name in names:
        base = f"../../../testdata/groth16/{name}"
        lines += [
            "    Bundled {",
            f'        name: "{name}",',
            f'        r1cs: include_bytes!("{base}.r1cs"),',
            f'        sym: include_str!("{base}.sym"),',
            f'        zkey: include_bytes!("{base}.zkey"),',
            f'        r1cs_sha256: "{sha256(DATA / (name + ".r1cs"))}",',
            f'        zkey_sha256: "{sha256(DATA / (name + ".zkey"))}",',
            "    },",
        ]
    return "\n".join(lines + ["];", ""])


def setup():
    WORK.mkdir(parents=True, exist_ok=True)
    names = circuits()
    pending = {}
    for name in names:
        pending[name] = contribute(name)
        print(f"contributed {name}")
    beacon = fetch_beacon()
    transcript = {
        "snarkjs": SNARKJS_VERSION,
        "ptau": {"file": PTAU.name, "url": PTAU_URL, "blake2b512": PTAU_BLAKE2B},
        "contributor": "zk-sdk phase 2 (single contributor)",
        "beacon": {**beacon, "iterations_exp": BEACON_ITERATIONS_EXP},
        "circuits": {},
    }
    for name in names:
        contributed, final, contribution = pending[name]
        finish(name, contributed, final, beacon)
        transcript["circuits"][name] = {
            "r1cs_sha256": sha256(DATA / f"{name}.r1cs"),
            "contribution_hash": contribution,
            "zkey_sha256": sha256(DATA / f"{name}.zkey"),
        }
        print(f"finished {name}")
    shutil.rmtree(WORK)
    (DATA / "setup.json").write_text(json.dumps(transcript, indent=2) + "\n", encoding="utf-8", newline="\n")
    APPROVED.write_text(approved_rs(names), encoding="utf-8", newline="\n")
    print(f"PASS: phase 2 for {len(names)} circuits (beacon: drand round {beacon['round']})")


def check():
    names = circuits()
    transcript = json.loads((DATA / "setup.json").read_text(encoding="utf-8"))
    for name in names:
        recorded = transcript["circuits"][name]
        if (sha256(DATA / f"{name}.r1cs"), sha256(DATA / f"{name}.zkey")) != (
            recorded["r1cs_sha256"], recorded["zkey_sha256"]):
            raise SystemExit(f"FAIL: {name} differs from setup.json; rerun groth16_setup.py")
        verify(name, DATA / f"{name}.zkey")
    if APPROVED.read_text(encoding="utf-8") != approved_rs(names):
        raise SystemExit(f"FAIL: {APPROVED} is stale; rerun groth16_setup.py")
    print(f"PASS: {len(names)} zkeys verify against their r1cs and the Hermez ptau")


def main():
    ensure_snarkjs()
    ensure_ptau()
    if "--check" in sys.argv[1:]:
        check()
    else:
        setup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
