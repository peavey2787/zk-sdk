"""Cross-backend interop matrix: native (zk CLI) and WebAssembly (Node) produce and verify each other's artifacts."""
import itertools
import json
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


def run(command, *, expect_ok=True, env=None):
    done = subprocess.run([str(c) for c in command], capture_output=True, text=True, env={**os.environ, **(env or {})})
    if (done.returncode == 0) != expect_ok:
        raise SystemExit(f"FAIL: {' '.join(map(str, command))}\n{done.stdout}{done.stderr}")
    return done.stdout


class Backend:
    def __init__(self, name):
        self.name = name
        self.groth16 = None  # (key pack, trust list) once a Groth16 setup exists

    def groth16_flags(self, trust=None):
        """The key pack and trust list: native flags, or the WASM tool's environment."""
        if self.groth16 is None:
            return [], {}
        keys, trusted = self.groth16[0], trust or self.groth16[1]
        if self.name == "native":
            return ["--groth16-keys", keys, "--groth16-trust", trusted], {}
        return [], {"ZK_GROTH16_KEYS": str(keys), "ZK_GROTH16_TRUST": str(trusted)}

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


    def commit(self, scheme, ty, value, commitment, secret):
        if self.name == "native":
            run([CLI, "predicate", "commit", "--scheme", scheme, "--type", ty, "--value", value, "--commitment", commitment,
                 "--secret", secret])
        else:
            run(["node", TOOL, NODE_PKG, "predicate-commit", scheme, ty, value, commitment, secret])

    def set_commitment(self, scheme, ty, values, commitment):
        if self.name == "native":
            run([CLI, "predicate", "set", "--scheme", scheme, "--type", ty, "--values", values, "--commitment", commitment])
        else:
            run(["node", TOOL, NODE_PKG, "predicate-set", scheme, ty, values, commitment])

    def set_path(self, scheme, ty, values, value, proves, path):
        if self.name == "native":
            run([CLI, "predicate", "path", "--scheme", scheme, "--type", ty, "--values", values, "--value", value,
                 "--proves", proves, "--path", path])
        else:
            run(["node", TOOL, NODE_PKG, "predicate-path", scheme, ty, values, value, proves, path])

    def transition(self, spec, claim, opens):
        if self.name == "native":
            run([CLI, "predicate", "transition", "--spec", spec, "--claim", claim, "--open", opens])
        else:
            run(["node", TOOL, NODE_PKG, "predicate-transition", spec, claim, opens])

    def credential_issue(self, scheme, ty, entries, out):
        if self.name == "native":
            run([CLI, "predicate", "issue", "--scheme", scheme, "--type", ty, "--entries", entries, "--out", out])
        else:
            run(["node", TOOL, NODE_PKG, "predicate-issue", scheme, ty, entries, out])

    def credential_present(self, credential, now, options, claim, prefix):
        if self.name == "native":
            run([CLI, "predicate", "present", "--credential", credential, "--now", now, "--options", options,
                 "--claim", claim, "--secrets-prefix", prefix])
        else:
            run(["node", TOOL, NODE_PKG, "predicate-present", credential, now, options, claim, prefix])

    def predicate_prove(self, claim, proof, secrets, ok=True):
        flags, env = self.groth16_flags()
        if self.name == "native":
            run([CLI, "predicate", "prove", "--claim", claim, "--secrets", ",".join(str(secret) for secret in secrets), "--proof", proof, "--min-bits", "115", *flags], expect_ok=ok)
        else:
            run(["node", TOOL, NODE_PKG, "predicate-prove", claim, proof, *secrets], expect_ok=ok, env=env)

    def predicate_verify(self, claim, proof, ok=True, trust=None):
        flags, env = self.groth16_flags(trust)
        if self.name == "native":
            run([CLI, "predicate", "verify", "--claim", claim, "--proof", proof, "--min-bits", "115", *flags], expect_ok=ok)
        else:
            run(["node", TOOL, NODE_PKG, "predicate-verify", claim, proof], expect_ok=ok, env=env)


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


def groth16_setup(backends, tmp, claims, tag):
    """A trusted setup for the circuits `claims` need, made across both backends: WASM creates it,
    native adds a contribution, both verify it (and refuse a damaged copy), and native writes the
    trust list. Every backend proves and verifies with it from then on."""
    native, wasm = backends["native"], backends["wasm"]
    needed = {name for claim in claims for name in run(["node", TOOL, NODE_PKG, "groth16-circuits", claim]).strip().split(",")}
    first, keys, trust = tmp / f"{tag}-first.pack", tmp / f"{tag}.pack", tmp / f"{tag}.trust"
    run(["node", TOOL, NODE_PKG, "groth16-new", ",".join(sorted(needed - {""})), first, "wasm contributor"])
    run([CLI, "groth16", "contribute", "--keys", first, "--out", keys, "--name", "native contributor"])
    run(["node", TOOL, NODE_PKG, "groth16-verify", keys])
    run([CLI, "groth16", "verify", "--keys", keys, "--trust-out", trust])
    bad = tmp / f"{tag}-bad.pack"
    corrupt(keys, bad)
    run(["node", TOOL, NODE_PKG, "groth16-verify", bad], expect_ok=False)
    run([CLI, "groth16", "verify", "--keys", bad], expect_ok=False)
    for backend in backends.values():
        backend.groth16 = (keys, trust)
    print(f"PASS: groth16 setup {tag} created by wasm, extended by native, verified by both (+damaged copy refused)")


def predicate_claims(c):
    """name -> (claim json, altered claim json, commitment names to open). Each altered claim is a
    different, even if true, statement: a proof must never verify against it."""
    ge = lambda bound, p="": f'{{"kind":"compare","commitment":"{c[p + "age"]}","op":"ge","bound":"{bound}"}}'
    rng = lambda lo, p="": (
        f'{{"kind":"range","commitment":"{c[p + "wide"]}","lo":"{lo}","hi":"5","lo_inclusive":true,"hi_inclusive":false}}'
    )
    pair = lambda op, p="": f'{{"kind":"compare_committed","left":"{c[p + "low"]}","right":"{c[p + "high"]}","op":"{op}"}}'
    opens = lambda name: f'{{"kind":"opens","commitment":"{c[name]}"}}'
    g16_all = lambda bound: f'{{"kind":"all","claims":[{ge(bound, "g_")},{pair("lt", "g_")}]}}'
    conserve = lambda fee: (
        f'{{"kind":"sum","plus":["{c["in1"]}","{c["in2"]}"],"minus":["{c["out1"]}","{c["out2"]}"],'
        f'"plus_constant":"0","minus_constant":"{fee}","op":"eq"}}'
    )
    product = lambda y: f'{{"kind":"arithmetic","x":"{c["in2"]}","y":"{y}","z":"{c["out2"]}","t":"{c["out1"]}","op":"lt"}}'
    divide = lambda divisor: (
        f'{{"kind":"divide","dividend":"{c["rem_dividend"]}","divisor":"{divisor}",'
        f'"quotient":"{c["quotient"]}","remainder":"{c["remainder"]}"}}'
    )
    member = lambda root, p="": f'{{"kind":"member","commitment":"{c[p + "in2"]}","set":"{root}"}}'
    absent = lambda root: f'{{"kind":"absent","commitment":"{c["in1"]}","set":"{root}"}}'
    distance = lambda radius: (
        f'{{"kind":"distance","x":"{c["in2"]}","y":"{c["out2"]}","center_x":"0","center_y":"0",'
        f'"op":"le","radius":"{radius}"}}'
    )
    union = lambda hi, p="": (
        f'{{"kind":"in_any_range","commitment":"{c[p + "in2"]}","ranges":[["100","200"],["250","{hi}"]]}}'
    )
    g_product = lambda y: (
        f'{{"kind":"arithmetic","x":"{c["g_in2"]}","y":"{y}","z":"{c["g_out2"]}","t":"{c["g_out1"]}","op":"lt"}}'
    )
    both = lambda bound: (
        f'{{"kind":"all","claims":[{{"kind":"compare","commitment":"{c["in2"]}","op":"ge","bound":"{bound}"}},'
        f'{{"kind":"compare_committed","left":"{c["in2"]}","right":"{c["out2"]}","op":"gt"}}]}}'
    )
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
        "union_u64": (union(350), union(351), ["in2"]),
        "all_u64": (both(100), both(101), ["in2", "out2"]),
        "distance_u64": (distance(305), distance(300), ["in2", "out2"]),
        "groth16_opens": (opens("g_age"), opens("g_low"), ["g_age"]),
        "groth16_ge_u32": (ge(18, "g_"), ge(19, "g_"), ["g_age"]),
        "groth16_range_i128": (rng(-9, "g_"), rng(-8, "g_"), ["g_wide"]),
        "groth16_pair_i64": (pair("lt", "g_"), pair("gt", "g_"), ["g_low", "g_high"]),
        "groth16_all": (g16_all(18), g16_all(19), ["g_age", "g_low", "g_high"]),
        "groth16_product_u64": (g_product(3), g_product(4), ["g_in2", "g_out2", "g_out1"]),
        "groth16_union_u64": (union(350, "g_"), union(351, "g_"), ["g_in2"]),
        "groth16_member_u64": (member(c["g_set"], "g_"), member(c["g_other_set"], "g_"), ["g_in2", "g_member_path"]),
    }


def predicate_matrix(backends, tmp):
    os.environ["ZK_MIN_BITS"] = "115"  # explicit: the larger arithmetic circuits attain 115 bits
    makers = itertools.cycle(backends.values())
    specs = {"age": ("u32", "20"), "wide": ("i128", "-7"), "low": ("i64", "-3"), "high": ("i64", "9"),
             "in1": ("u64", "700"), "in2": ("u64", "300"), "out1": ("u64", "960"), "out2": ("u64", "30"),
             "rem_dividend": ("u64", "47"), "quotient": ("u64", "5"), "remainder": ("u64", "2")}
    groth16 = {f"g_{name}": spec for name, spec in specs.items() if name in ("age", "wide", "low", "high", "in2", "out1", "out2")}
    commitments, secrets = {}, {}
    for name, (ty, value) in {**specs, **groth16}.items():
        maker = next(makers)
        commitment, secret = tmp / f"{name}.c", tmp / f"{name}.s"
        maker.commit("groth16" if name in groth16 else "spartan-whir", ty, value, commitment, secret)
        commitments[name], secrets[name] = commitment.read_text(), secret
    set_values = tmp / "set.json"
    set_values.write_text('["300","301","900"]')
    other_values = tmp / "other-set.json"
    other_values.write_text('["300","302","900"]')
    for prefix, scheme in (("", "spartan-whir"), ("g_", "groth16")):
        for name, values in (("set", set_values), ("other_set", other_values)):
            commitment = tmp / f"{prefix}{name}.c"
            next(makers).set_commitment(scheme, "u64", values, commitment)
            commitments[prefix + name] = commitment.read_text()
    for name, scheme, value, proves in (("member_path", "spartan-whir", "300", "member"),
                                        ("absent_path", "spartan-whir", "700", "absent"),
                                        ("g_member_path", "groth16", "300", "member")):
        secrets[name] = tmp / f"{name}.json"
        next(makers).set_path(scheme, "u64", set_values, value, proves, secrets[name])
    untrusted = tmp / "untrusted.trust"
    untrusted.write_text("00" * 32 + "\n")
    claims = {}
    for name, (claim_json, altered_json, openings) in predicate_claims(commitments).items():
        claims[name] = (tmp / f"{name}.claim.json", tmp / f"{name}.altered.json", openings)
        claims[name][0].write_text(claim_json)
        claims[name][1].write_text(altered_json)
    groth16_setup(backends, tmp, [claim for name, (claim, _, _) in claims.items() if name.startswith("groth16_")], "g16")
    for name, (claim, altered, openings) in claims.items():
        for producer in backends.values():
            proof = tmp / f"{name}-{producer.name}.proof"
            producer.predicate_prove(claim, proof, [secrets[o] for o in openings])
            bad = tmp / f"{name}-{producer.name}.bad"
            corrupt(proof, bad)
            for verifier in backends.values():
                verifier.predicate_verify(claim, proof)
                verifier.predicate_verify(altered, proof, ok=False)
                verifier.predicate_verify(claim, bad, ok=False)
                if name.startswith("groth16_"):
                    verifier.predicate_verify(claim, proof, ok=False, trust=untrusted)
            print(f"PASS: predicate {name} produced by {producer.name}, verified by both (+negatives)")
    transition_matrix(backends, tmp, commitments, secrets)


def transition_matrix(backends, tmp, commitments, secrets):
    """Lower a state transition with each backend, then prove and verify across both."""
    spec = tmp / "transition.json"
    spec.write_text(json.dumps({
        "old": [commitments["in1"], commitments["in2"]], "new": [commitments["out1"], commitments["out2"]],
        "rules": [{"kind": "require", "field": 0, "op": "ge", "bound": "500"},
                  {"kind": "conserve", "fields": [0, 1], "fee": "10"}]}))
    by_commitment = {commitments[n]: secrets[n] for n in ("in1", "in2", "out1", "out2")}
    for lowering in backends.values():
        claim, opens = tmp / f"step-{lowering.name}.claim.json", tmp / f"step-{lowering.name}.open.json"
        lowering.transition(spec, claim, opens)
        order = [by_commitment[c] for c in json.loads(opens.read_text())]
        for producer in backends.values():
            proof = tmp / f"step-{lowering.name}-{producer.name}.proof"
            producer.predicate_prove(claim, proof, order)
            for verifier in backends.values():
                verifier.predicate_verify(claim, proof)
        print(f"PASS: transition lowered by {lowering.name}, proven and verified by both")


def credential_matrix(backends, tmp):
    """Issue with one backend, present with the other, prove and verify across both."""
    entries = tmp / "entries.json"
    entries.write_text('[{"attribute":"30","serial":"7","expiry":"2000000000"}]')
    options = tmp / "present-options.json"
    options.write_text('{"also":[{"kind":"compare","commitment":"$attribute","op":"ge","bound":"18"}]}')
    issuer, holder = backends.values()
    for issuing, presenting, scheme in ((issuer, holder, "spartan-whir"), (holder, issuer, "groth16")):
        issued = tmp / f"issued-{issuing.name}.json"
        issuing.credential_issue(scheme, "u32", entries, issued)
        credential = tmp / f"credential-{issuing.name}.json"
        credential.write_text(json.loads(issued.read_text())["credentials"][0])
        claim, prefix = tmp / f"cred-{presenting.name}.claim.json", str(tmp / f"cred-{presenting.name}.s")
        presenting.credential_present(credential, "1700000000", options, claim, prefix)
        if scheme == "groth16":
            groth16_setup(backends, tmp, [claim], "g16-credential")
        secrets = sorted(tmp.glob(f"cred-{presenting.name}.s[0-9]"))
        late, late_prefix = tmp / f"late-{presenting.name}.claim.json", str(tmp / f"late-{presenting.name}.s")
        presenting.credential_present(credential, "2000000001", options, late, late_prefix)
        presenting.predicate_prove(late, tmp / "late.proof", sorted(tmp.glob(f"late-{presenting.name}.s[0-9]")), ok=False)
        for producer in backends.values():
            proof = tmp / f"cred-{issuing.name}-{presenting.name}-{producer.name}.proof"
            producer.predicate_prove(claim, proof, secrets)
            for verifier in backends.values():
                verifier.predicate_verify(claim, proof)
        print(f"PASS: {scheme} credential issued by {issuing.name}, presented by {presenting.name}, proven and verified by both")


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
    credential_matrix(backends, tmp)
    print("PASS: interop matrix (windows host; linux NOT VALIDATED here)")


if __name__ == "__main__":
    main()
