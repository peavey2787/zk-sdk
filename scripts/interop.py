"""Cross-backend interop matrix: native (zk CLI) and WebAssembly (Node) produce and verify each other's artifacts."""
import itertools
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = ".exe" if sys.platform == "win32" else ""
CLI = ROOT / "target" / "release" / f"zk{EXE}"
NODE_PKG = ROOT / "target" / "wasm-node" / "zk_wasm.js"
TOOL = ROOT / "scripts" / "wasm_tool.cjs"
STATEMENTS = {"age_over": "1,18", "arithmetic": "1603,5", "millionaires": "1"}
WRONG = {"age_over": "0,18", "arithmetic": "1603,6", "millionaires": "0"}


def run(command, *, expect_ok=True):
    done = subprocess.run([str(c) for c in command], capture_output=True, text=True)
    if (done.returncode == 0) != expect_ok:
        raise SystemExit(f"FAIL: {' '.join(map(str, command))}\n{done.stdout}{done.stderr}")


class Backend:
    def __init__(self, name):
        self.name = name

    def setup(self, r1cs, pk, vk):
        if self.name == "native":
            run([CLI, "setup", "--r1cs", r1cs, "--pk", pk, "--vk", vk])
        else:
            run(["node", TOOL, NODE_PKG, "setup", r1cs, pk, vk])

    def prove(self, pk, circuit, proof):
        data = ROOT / "testdata" / circuit
        r1cs, sym, inp = data / f"{circuit}.r1cs", data / f"{circuit}.sym", data / "input.json"
        if self.name == "native":
            run([CLI, "prove", "--pk", pk, "--r1cs", r1cs, "--sym", sym, "--input", inp, "--proof", proof])
        else:
            run(["node", TOOL, NODE_PKG, "prove", pk, r1cs, sym, inp, proof])

    def verify(self, vk, expected, proof, ok=True):
        if self.name == "native":
            run([CLI, "verify", "--vk", vk, "--expected", expected, "--proof", proof], expect_ok=ok)
        else:
            run(["node", TOOL, NODE_PKG, "verify", vk, expected, proof], expect_ok=ok)


    def commit(self, ty, value, commitment, secret):
        if self.name == "native":
            run([CLI, "predicate", "commit", "--type", ty, "--value", value, "--commitment", commitment, "--secret", secret])
        else:
            run(["node", TOOL, NODE_PKG, "predicate-commit", ty, value, commitment, secret])

    def predicate_prove(self, claim, proof, secrets):
        if self.name == "native":
            flags = ["--secret", secrets[0]] + (["--secret2", secrets[1]] if len(secrets) > 1 else [])
            run([CLI, "predicate", "prove", "--claim", claim, *flags, "--proof", proof])
        else:
            run(["node", TOOL, NODE_PKG, "predicate-prove", claim, proof, *secrets])

    def predicate_verify(self, claim, proof, ok=True):
        if self.name == "native":
            run([CLI, "predicate", "verify", "--claim", claim, "--proof", proof], expect_ok=ok)
        else:
            run(["node", TOOL, NODE_PKG, "predicate-verify", claim, proof], expect_ok=ok)


def build():
    steps = [
        ["cargo", "build", "--release", "-p", "zk-cli"],
        ["wasm-pack", "build", "crates/zk-wasm", "--target", "nodejs", "--release", "--out-dir", "../../target/wasm-node"],
    ]
    for step in steps:
        if subprocess.run([shutil.which(step[0])] + step[1:], cwd=ROOT).returncode != 0:
            raise SystemExit(f"FAIL: {' '.join(step)}")


def corrupt(source, target):
    data = bytearray(Path(source).read_bytes())
    data[len(data) // 2] ^= 0x55
    Path(target).write_bytes(data)


def predicate_claims(c):
    """name -> (claim json, altered claim json, commitment names to open). Each altered claim is a
    different, even if true, statement: a proof must never verify against it."""
    ge = lambda bound: f'{{"kind":"compare","commitment":"{c["age"]}","op":"ge","bound":"{bound}"}}'
    rng = lambda lo: f'{{"kind":"range","commitment":"{c["wide"]}","lo":"{lo}","hi":"5","lo_inclusive":true,"hi_inclusive":false}}'
    pair = lambda op: f'{{"kind":"compare_committed","left":"{c["low"]}","right":"{c["high"]}","op":"{op}"}}'
    opens = lambda name: f'{{"kind":"opens","commitment":"{c[name]}"}}'
    return {
        "opens": (opens("age"), opens("low"), ["age"]),
        "ge_u32": (ge(18), ge(19), ["age"]),
        "range_i128": (rng(-9), rng(-8), ["wide"]),
        "pair_i64": (pair("lt"), pair("gt"), ["low", "high"]),
    }


def predicate_matrix(backends, tmp):
    makers = itertools.cycle(backends.values())
    specs = {"age": ("u32", "20"), "wide": ("i128", "-7"), "low": ("i64", "-3"), "high": ("i64", "9")}
    commitments, secrets = {}, {}
    for name, (ty, value) in specs.items():
        maker = next(makers)
        commitment, secret = tmp / f"{name}.c", tmp / f"{name}.s"
        maker.commit(ty, value, commitment, secret)
        commitments[name], secrets[name] = commitment.read_text(), secret
    for name, (claim_json, altered_json, openings) in predicate_claims(commitments).items():
        claim, altered = tmp / f"{name}.claim.json", tmp / f"{name}.altered.json"
        claim.write_text(claim_json)
        altered.write_text(altered_json)
        for producer in backends.values():
            proof = tmp / f"{name}-{producer.name}.proof"
            producer.predicate_prove(claim, proof, [secrets[o] for o in openings])
            bad = tmp / f"{name}-{producer.name}.bad"
            corrupt(proof, bad)
            for verifier in backends.values():
                verifier.predicate_verify(claim, proof)
                verifier.predicate_verify(altered, proof, ok=False)
                verifier.predicate_verify(claim, bad, ok=False)
            print(f"PASS: predicate {name} produced by {producer.name}, verified by both (+negatives)")


def main():
    build()
    backends = {name: Backend(name) for name in ("native", "wasm")}
    tmp = ROOT / "target" / "interop"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True, exist_ok=True)
    for circuit, statement in STATEMENTS.items():
        r1cs = ROOT / "testdata" / circuit / f"{circuit}.r1cs"
        for producer, verifier in itertools.product(backends.values(), repeat=2):
            tag = f"{circuit}-{producer.name}"
            pk, vk, proof = tmp / f"{tag}.pk", tmp / f"{tag}.vk", tmp / f"{tag}.proof"
            producer.setup(r1cs, pk, vk)
            producer.prove(pk, circuit, proof)
            verifier.verify(vk, statement, proof)
            verifier.verify(vk, WRONG[circuit], proof, ok=False)
            bad = tmp / f"{tag}-{verifier.name}.bad"
            corrupt(proof, bad)
            verifier.verify(vk, statement, bad, ok=False)
            print(f"PASS: {circuit} produced by {producer.name}, verified by {verifier.name} (+negatives)")
    predicate_matrix(backends, tmp)
    print("PASS: interop matrix (windows host; linux NOT VALIDATED here)")


if __name__ == "__main__":
    main()
