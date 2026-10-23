//! Real end-to-end runs of the native `zk` binary over the shipped circuits. No mocks.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn testdata(circuit: &str, file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(circuit)
        .join(file)
}

fn zk(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zk"))
        .args(args)
        .output()
        .expect("zk binary runs")
}

fn path(p: &Path) -> &str {
    p.to_str().expect("utf-8 path")
}

struct Run {
    dir: tempfile::TempDir,
    circuit: &'static str,
}

impl Run {
    fn new(circuit: &'static str) -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            circuit,
        }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn setup(&self, extra: &[&str]) -> Output {
        let r1cs = testdata(self.circuit, &format!("{}.r1cs", self.circuit));
        let (pk, vk) = (self.file("pk"), self.file("vk"));
        let mut args = vec![
            "setup",
            "--r1cs",
            path(&r1cs),
            "--pk",
            path(&pk),
            "--vk",
            path(&vk),
        ];
        args.extend_from_slice(extra);
        zk(&args)
    }

    fn prove(&self, input: &Path) -> Output {
        let r1cs = testdata(self.circuit, &format!("{}.r1cs", self.circuit));
        let sym = testdata(self.circuit, &format!("{}.sym", self.circuit));
        let (pk, proof) = (self.file("pk"), self.file("proof"));
        zk(&[
            "prove",
            "--pk",
            path(&pk),
            "--r1cs",
            path(&r1cs),
            "--sym",
            path(&sym),
            "--input",
            path(input),
            "--proof",
            path(&proof),
        ])
    }

    fn verify(&self, vk: &Path, expected: &str, proof: &Path) -> Output {
        zk(&[
            "verify",
            "--vk",
            path(vk),
            "--expected",
            expected,
            "--proof",
            path(proof),
        ])
    }
}

fn input_file(run: &Run, json: &str) -> PathBuf {
    let path = run.file("input.json");
    fs::write(&path, json).unwrap();
    path
}

#[test]
fn age_over_full_pipeline_and_negative_cases() {
    let run = Run::new("age_over");
    assert!(run.setup(&[]).status.success());
    let input = testdata("age_over", "input.json");
    assert!(run.prove(&input).status.success());
    let (vk, proof) = (run.file("vk"), run.file("proof"));

    assert!(run.verify(&vk, "1,18", &proof).status.success());
    assert!(
        !run.verify(&vk, "1,19", &proof).status.success(),
        "wrong statement"
    );
    assert!(
        !run.verify(&vk, "0,18", &proof).status.success(),
        "wrong verdict"
    );

    let under_range = input_file(&run, r#"{"age":"256","threshold":"18"}"#);
    assert!(
        !run.prove(&under_range).status.success(),
        "witness must not exist"
    );

    let mut corrupt = fs::read(&proof).unwrap();
    let middle = corrupt.len() / 2;
    corrupt[middle] ^= 1;
    let corrupt_path = run.file("corrupt");
    fs::write(&corrupt_path, &corrupt).unwrap();
    assert!(!run.verify(&vk, "1,18", &corrupt_path).status.success());

    let truncated = run.file("truncated");
    fs::write(&truncated, &fs::read(&proof).unwrap()[..100]).unwrap();
    assert!(!run.verify(&vk, "1,18", &truncated).status.success());

    let other = Run::new("age_over");
    assert!(other.setup(&["--bits", "100"]).status.success());
    assert!(
        !run.verify(&other.file("vk"), "1,18", &proof)
            .status
            .success(),
        "foreign key"
    );
}

#[test]
fn unsupported_security_is_rejected_not_rounded() {
    let run = Run::new("age_over");
    for bits in ["99", "119", "128"] {
        assert!(!run.setup(&["--bits", bits]).status.success(), "{bits}");
    }
    assert!(!run.setup(&["--soundness", "fast"]).status.success());
}

#[test]
fn arithmetic_and_millionaires_prove_and_verify() {
    let arithmetic = Run::new("arithmetic");
    assert!(arithmetic.setup(&[]).status.success());
    assert!(arithmetic
        .prove(&testdata("arithmetic", "input.json"))
        .status
        .success());
    let (vk, proof) = (arithmetic.file("vk"), arithmetic.file("proof"));
    assert!(arithmetic.verify(&vk, "1603,5", &proof).status.success());
    assert!(!arithmetic.verify(&vk, "1604,5", &proof).status.success());

    let mil = Run::new("millionaires");
    assert!(mil.setup(&[]).status.success());
    assert!(mil
        .prove(&testdata("millionaires", "input.json"))
        .status
        .success());
    let (vk, proof) = (mil.file("vk"), mil.file("proof"));
    assert!(mil.verify(&vk, "1", &proof).status.success());
    assert!(
        !mil.verify(&vk, "0", &proof).status.success(),
        "dishonest verdict"
    );
}

/// Built-in predicates through the real binary; each command is its own process, so verification
/// never shares memory with the prover.
mod predicates {
    use super::*;

    fn run(args: &[&str]) -> Output {
        zk(&[&["predicate"], args].concat())
    }

    fn ok(args: &[&str]) {
        let out = run(args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn commit(dir: &Path, name: &str, ty: &str, value: &str) -> (String, PathBuf) {
        let (commitment, secret) = (dir.join(format!("{name}.c")), dir.join(format!("{name}.s")));
        ok(&[
            "commit",
            "--type",
            ty,
            "--value",
            value,
            "--commitment",
            path(&commitment),
            "--secret",
            path(&secret),
        ]);
        (fs::read_to_string(commitment).unwrap(), secret)
    }

    fn claim(dir: &Path, name: &str, json: &str) -> PathBuf {
        let file = dir.join(format!("{name}.json"));
        fs::write(&file, json).unwrap();
        file
    }

    #[test]
    fn every_family_proves_and_verifies_in_separate_processes() {
        let dir = tempfile::tempdir().unwrap();
        let (age, age_secret) = commit(dir.path(), "age", "u32", "20");
        let (low, low_secret) = commit(dir.path(), "low", "i64", "-3");
        let (high, high_secret) = commit(dir.path(), "high", "i64", "9");
        let opens = |c: &str| format!(r#"{{"kind":"opens","commitment":"{c}"}}"#);
        let ge = |bound: u32| {
            format!(r#"{{"kind":"compare","commitment":"{age}","op":"ge","bound":"{bound}"}}"#)
        };
        let range = |hi: u32| {
            format!(
                r#"{{"kind":"range","commitment":"{age}","lo":"18","hi":"{hi}","lo_inclusive":true,"hi_inclusive":false}}"#
            )
        };
        let pair = |op: &str| {
            format!(r#"{{"kind":"compare_committed","left":"{low}","right":"{high}","op":"{op}"}}"#)
        };
        let cases = [
            ("opens", opens(&age), opens(&low), vec![&age_secret]),
            ("ge", ge(18), ge(19), vec![&age_secret]),
            ("range", range(21), range(22), vec![&age_secret]),
            (
                "pair",
                pair("lt"),
                pair("gt"),
                vec![&low_secret, &high_secret],
            ),
        ];
        for (name, json, altered, secrets) in cases {
            let (claim_file, proof) = (
                claim(dir.path(), name, &json),
                dir.path().join(format!("{name}.proof")),
            );
            let list = secrets
                .iter()
                .map(|s| path(s))
                .collect::<Vec<_>>()
                .join(",");
            ok(&[
                "prove",
                "--claim",
                path(&claim_file),
                "--secrets",
                &list,
                "--proof",
                path(&proof),
            ]);
            ok(&[
                "verify",
                "--claim",
                path(&claim_file),
                "--proof",
                path(&proof),
            ]);
            let altered = claim(dir.path(), "altered", &altered);
            assert!(
                !run(&["verify", "--claim", path(&altered), "--proof", path(&proof)])
                    .status
                    .success(),
                "{name}"
            );
        }
    }

    #[test]
    fn conservation_proves_and_verifies_in_separate_processes() {
        let dir = tempfile::tempdir().unwrap();
        let values = [
            ("in1", "700"),
            ("in2", "300"),
            ("out1", "960"),
            ("out2", "30"),
        ];
        let made: Vec<_> = values
            .iter()
            .map(|(name, value)| commit(dir.path(), name, "u64", value))
            .collect();
        let conserve = |fee: u32| {
            format!(
                r#"{{"kind":"sum","plus":["{}","{}"],"minus":["{}","{}"],"minus_constant":"{fee}","op":"eq"}}"#,
                made[0].0, made[1].0, made[2].0, made[3].0
            )
        };
        let secrets = made
            .iter()
            .map(|m| path(&m.1))
            .collect::<Vec<_>>()
            .join(",");
        let (claim_file, proof) = (
            claim(dir.path(), "c", &conserve(10)),
            dir.path().join("c.proof"),
        );
        ok(&[
            "prove",
            "--claim",
            path(&claim_file),
            "--secrets",
            &secrets,
            "--proof",
            path(&proof),
        ]);
        ok(&[
            "verify",
            "--claim",
            path(&claim_file),
            "--proof",
            path(&proof),
        ]);
        let described = run(&["describe", "--claim", path(&claim_file)]);
        assert!(String::from_utf8_lossy(&described.stdout).starts_with("sum4_64 115-bit"));
        let unbalanced = claim(dir.path(), "u", &conserve(11));
        assert!(!run(&[
            "verify",
            "--claim",
            path(&unbalanced),
            "--proof",
            path(&proof)
        ])
        .status
        .success());
        let refused = dir.path().join("refused.proof");
        assert!(!run(&[
            "prove",
            "--claim",
            path(&unbalanced),
            "--secrets",
            &secrets,
            "--proof",
            path(&refused)
        ])
        .status
        .success());
        assert!(!refused.exists());
        let short = path(&made[0].1);
        assert!(!run(&[
            "prove",
            "--claim",
            path(&claim_file),
            "--secrets",
            short,
            "--proof",
            path(&refused)
        ])
        .status
        .success());
    }

    #[test]
    fn false_claims_and_bad_inputs_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (age, secret) = commit(dir.path(), "age", "u32", "17");
        let proof = dir.path().join("p");
        let false_claim = claim(
            dir.path(),
            "f",
            &format!(r#"{{"kind":"compare","commitment":"{age}","op":"ge","bound":"18"}}"#),
        );
        assert!(!run(&[
            "prove",
            "--claim",
            path(&false_claim),
            "--secrets",
            path(&secret),
            "--proof",
            path(&proof)
        ])
        .status
        .success());
        assert!(!proof.exists(), "no proof file for a false claim");
        let garbage = claim(dir.path(), "g", "{\"kind\":\"teleport\"}");
        assert!(!run(&["describe", "--claim", path(&garbage)])
            .status
            .success());
        assert!(!run(&[
            "commit",
            "--type",
            "u32",
            "--value",
            "-1",
            "--commitment",
            path(&dir.path().join("c")),
            "--secret",
            path(&dir.path().join("s"))
        ])
        .status
        .success());
    }
}
