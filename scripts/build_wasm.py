"""Build the browser bundles and the demo circuits in web/circuits.

web/pkg is the single-threaded bundle (any page). web/pkg-threads proves on every core through rayon
over Web Workers; it needs shared-memory atomics, which only a pinned nightly with a rebuilt std
provides today, and a cross-origin-isolated page (web/worker.js picks the bundle at runtime).
web/groth16 holds the approved Groth16 circuits (r1cs and sym) and web/ptau the published phase-1
file, which the worker fetches on demand to create, contribute to and check trusted setups (too
large to embed; the WASM side checks every file against its pinned or published hash). No keys are
shipped: every setup is made by its users.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
THREADS_TOOLCHAIN = "nightly-2026-09-25"
THREADED_ENV = {
    **os.environ,
    "RUSTUP_TOOLCHAIN": THREADS_TOOLCHAIN,
    # Shared, imported memory and the TLS exports wasm-bindgen's thread support needs; atomics is a
    # target modifier, so std is rebuilt with it (-Z build-std) rather than mixed.
    "RUSTFLAGS": " ".join([
        "-Zllvm-target-feature=+atomics",
        "-C target-feature=+bulk-memory,+mutable-globals",
        *(f"-C link-arg={arg}" for arg in (
            "--shared-memory", "--import-memory", "--max-memory=4294967296", "--export=__wasm_init_tls",
            "--export=__tls_size", "--export=__tls_align", "--export=__tls_base",
        )),
        '--cfg getrandom_backend="wasm_js"',
    ]),
}
CIRCUITS = ("age_over", "arithmetic", "millionaires")


def main() -> int:
    pack = shutil.which("wasm-pack")
    if pack is None:
        print("FAIL: wasm-pack is not installed (cargo install wasm-pack)")
        return 1
    for bundle in ("pkg", "pkg-threads"):  # wasm-pack never removes stale snippets
        shutil.rmtree(ROOT / "web" / bundle, ignore_errors=True)
    build = [pack, "build", "crates/zk-wasm", "--target", "web", "--release", "--out-dir"]
    if subprocess.run([*build, "../../web/pkg"], cwd=ROOT).returncode != 0:
        return 1
    threaded = [*build, "../../web/pkg-threads", "--", "--features", "threads", "-Z", "build-std=panic_abort,std"]
    if subprocess.run(threaded, cwd=ROOT, env=THREADED_ENV).returncode != 0:
        return 1
    target = ROOT / "web" / "circuits"
    target.mkdir(exist_ok=True)
    for name in CIRCUITS:
        for suffix in ("r1cs", "sym"):
            shutil.copy(ROOT / "testdata" / name / f"{name}.{suffix}", target)
    groth16, ptau = ROOT / "web" / "groth16", ROOT / "web" / "ptau"
    for directory in (groth16, ptau):
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir()
    for suffix in ("r1cs", "sym"):
        for artifact in (ROOT / "testdata" / "groth16").glob(f"*.{suffix}"):
            shutil.copy(artifact, groth16)
    phase1 = sorted((ROOT / "target" / "ptau").glob("powersOfTau28_hez_final_*.ptau"))
    if not phase1:
        print("FAIL: no phase-1 file in target/ptau (python scripts/groth16_setup.py --fetch)")
        return 1
    shutil.copy(min(phase1, key=lambda f: int(f.stem.rsplit("_", 1)[1])), ptau)
    print("PASS: web bundle built")
    return 0


if __name__ == "__main__":
    sys.exit(main())
