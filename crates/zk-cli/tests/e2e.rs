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
