"""Cross-backend interop matrix: native (zk CLI) and WebAssembly (Node) produce and verify each other's artifacts."""
import itertools
import os
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

    def set_commitment(self, ty, values, commitment):
        if self.name == "native":
            run([CLI, "predicate", "set", "--type", ty, "--values", values, "--commitment", commitment])
        else:
            run(["node", TOOL, NODE_PKG, "predicate-set", ty, values, commitment])

    def set_path(self, ty, values, value, proves, path):
        if self.name == "native":
            run([CLI, "predicate", "path", "--type", ty, "--values", values, "--value", value, "--proves", proves, "--path", path])
        else:
            run(["node", TOOL, NODE_PKG, "predicate-path", ty, values, value, proves, path])

    def predicate_prove(self, claim, proof, secrets):
        if self.name == "native":
            run([CLI, "predicate", "prove", "--claim", claim, "--secrets", ",".join(str(secret) for secret in secrets), "--proof", proof, "--min-bits", "115"])
        else:
            run(["node", TOOL, NODE_PKG, "predicate-prove", claim, proof, *secrets])

    def predicate_verify(self, claim, proof, ok=True):
        if self.name == "native":
            run([CLI, "predicate", "verify", "--claim", claim, "--proof", proof, "--min-bits", "115"], expect_ok=ok)
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
    conserve = lambda fee: (
        f'{{"kind":"sum","plus":["{c["in1"]}","{c["in2"]}"],"minus":["{c["out1"]}","{c["out2"]}"],'
        f'"plus_constant":"0","minus_constant":"{fee}","op":"eq"}}'
    )
    product = lambda y: f'{{"kind":"arithmetic","x":"{c["in2"]}","y":"{y}","z":"{c["out2"]}","t":"{c["out1"]}","op":"lt"}}'
    divide = lambda divisor: (
        f'{{"kind":"divide","dividend":"{c["rem_dividend"]}","divisor":"{divisor}",'
        f'"quotient":"{c["quotient"]}","remainder":"{c["remainder"]}"}}'
    )
    member = lambda root: f'{{"kind":"member","commitment":"{c["in2"]}","set":"{root}"}}'
    absent = lambda root: f'{{"kind":"absent","commitment":"{c["in1"]}","set":"{root}"}}'
    return {
        "member_u64": (member(c["set"]), member(c["other_set"]), ["in2", "member_path"]),
        "absent_u64": (absent(c["set"]), absent(c["other_set"]), ["in1", "absent_path"]),
        "opens": (opens("age"), opens("low"), ["age"]),
        "ge_u32": (ge(18), ge(19), ["age"]),
        "range_i128": (rng(-9), rng(-8), ["wide"]),
        "pair_i64": (pair("lt"), pair("gt"), ["low", "high"]),
        "conserve_u64": (conserve(10), conserve(11), ["in1", "in2", "out1", "out2"]),
        "product_u64": (product(3), product(4), ["in2", "out2", "out1"]),
        "divide_u64": (divide(9), divide(10), ["rem_dividend", "quotient", "remainder"]),
    }


def predicate_matrix(backends, tmp):
    os.environ["ZK_MIN_BITS"] = "115"  # explicit: the larger arithmetic circuits attain 115 bits
    makers = itertools.cycle(backends.values())
    specs = {"age": ("u32", "20"), "wide": ("i128", "-7"), "low": ("i64", "-3"), "high": ("i64", "9"),
             "in1": ("u64", "700"), "in2": ("u64", "300"), "out1": ("u64", "960"), "out2": ("u64", "30"),
             "rem_dividend": ("u64", "47"), "quotient": ("u64", "5"), "remainder": ("u64", "2")}
    commitments, secrets = {}, {}
    for name, (ty, value) in specs.items():
        maker = next(makers)
        commitment, secret = tmp / f"{name}.c", tmp / f"{name}.s"
        maker.commit(ty, value, commitment, secret)
        commitments[name], secrets[name] = commitment.read_text(), secret
    set_values = tmp / "set.json"
    set_values.write_text('["300","301","900"]')
    other_values = tmp / "other-set.json"
    other_values.write_text('["300","302","900"]')
    for name, values, out in (("set", set_values, "set"), ("other_set", other_values, "other_set")):
        commitment = tmp / f"{out}.c"
        next(makers).set_commitment("u64", values, commitment)
        commitments[name] = commitment.read_text()
    for name, value, proves in (("member_path", "300", "member"), ("absent_path", "700", "absent")):
        secrets[name] = tmp / f"{name}.json"
        next(makers).set_path("u64", set_values, value, proves, secrets[name])
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
