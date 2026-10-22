"""Build the browser bundle: wasm-pack output in web/pkg and the demo circuits in web/circuits."""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CIRCUITS = ("age_over", "arithmetic", "millionaires")


def main() -> int:
    pack = shutil.which("wasm-pack")
    if pack is None:
        print("FAIL: wasm-pack is not installed (cargo install wasm-pack)")
        return 1
    build = [pack, "build", "crates/zk-wasm", "--target", "web", "--release", "--out-dir", "../../web/pkg"]
    if subprocess.run(build, cwd=ROOT).returncode != 0:
        return 1
    target = ROOT / "web" / "circuits"
    target.mkdir(exist_ok=True)
    for name in CIRCUITS:
        for suffix in ("r1cs", "sym"):
            shutil.copy(ROOT / "testdata" / name / f"{name}.{suffix}", target)
    print("PASS: web bundle built")
    return 0


if __name__ == "__main__":
    sys.exit(main())
