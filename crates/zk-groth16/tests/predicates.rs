//! Real Groth16 proofs for the core BN254 predicate circuits under an ephemeral trusted setup made
//! from the published phase 1: honest statements prove and verify, false ones cannot be proven, and
//! a proof never verifies for different public signals or a different circuit.

mod common;

use std::sync::OnceLock;
use std::time::Instant;

use zk_groth16::{circuits, commit, random_scalar, FieldInputs, Fr, Setup, PROOF_BYTES};

const FAMILIES: [&str; 4] = ["open", "compare", "range", "compare_committed"];

/// One setup for every family at every width, authorized for verification.
fn setup() -> &'static Setup {
    static SETUP: OnceLock<Setup> = OnceLock::new();
    SETUP.get_or_init(|| {
        let names: Vec<String> = WIDTHS
            .iter()
            .flat_map(|(bits, _)| FAMILIES.iter().map(move |f| format!("{f}_{bits}")))
            .collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        common::trusted(common::create(&names, "predicates test"))
    })
}

/// Unsigned value as `limbs` little-endian 16-bit limbs.
fn limbs(value: u128, count: usize) -> Vec<u16> {
    (0..count).map(|i| (value >> (16 * i)) as u16).collect()
}

struct Opening {
    limbs: Vec<u16>,
    blinding: Fr,
    commitment: Fr,
}

fn open(value: u128, count: usize) -> Opening {
    let limbs = limbs(value, count);
    let blinding = random_scalar().unwrap();
    let commitment = commit(false, &limbs, blinding);
    Opening {
        limbs,
        blinding,
        commitment,
    }
}

#[derive(Default)]
struct Inputs(FieldInputs<zk_groth16::Bn254>);

impl Inputs {
    fn set(mut self, name: &str, value: Fr) -> Self {
        self.0.insert(name.into(), value);
        self
    }

    fn array(mut self, name: &str, values: &[u16]) -> Self {
        for (i, v) in values.iter().enumerate() {
            self.0.insert(format!("{name}[{i}]"), Fr::from(*v));
        }
        self
    }

    fn opening(self, prefix: &str, o: &Opening) -> Self {
        self.array(&format!("{prefix}limb"), &o.limbs)
            .set(&format!("{prefix}blinding[0]"), o.blinding)
    }

    fn accept(self, (lt, eq, gt): (u64, u64, u64)) -> Self {
        self.set("accept_lt", Fr::from(lt))
            .set("accept_eq", Fr::from(eq))
            .set("accept_gt", Fr::from(gt))
    }
}

const GE: (u64, u64, u64) = (0, 1, 1);
const LT: (u64, u64, u64) = (1, 0, 0);
const WIDTHS: [(u32, usize); 3] = [(32, 2), (64, 4), (128, 8)];

fn compare_inputs(
    bits: u32,
    count: usize,
    value: u128,
    bound: u128,
    op: (u64, u64, u64),
) -> (String, Inputs) {
    let o = open(value, count);
    let inputs = Inputs::default()
        .set("commitment[0]", o.commitment)
        .set("signed", Fr::from(0u64))
        .accept(op)
        .array("bound", &limbs(bound, count))
        .opening("", &o);
    (format!("compare_{bits}"), inputs)
}

fn prove_and_verify(name: &str, inputs: Inputs) {
    let circuit = setup().circuit(name).unwrap();
    let out = circuit.prove(&inputs.0).unwrap();
    assert_eq!(out.proof.len(), PROOF_BYTES);
    let vk = setup().verifying_key(name).unwrap();
    vk.verify(&out.public_signals, &out.proof).unwrap();
    let mut other = out.public_signals.clone();
    other[0] += Fr::from(1u64);
    assert!(
        vk.verify(&other, &out.proof).is_err(),
        "{name}: substituted claim"
    );
    let mut damaged = out.proof.clone();
    damaged[40] ^= 1;
    assert!(
        vk.verify(&out.public_signals, &damaged).is_err(),
        "{name}: damaged proof"
    );
}

/// One true statement per family at this width (values at the edges of the type).
fn cases(bits: u32, count: usize) -> Vec<(String, Inputs)> {
    let max = if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    };
    let o = open(max, count);
    let opens = Inputs::default()
        .set("commitment[0]", o.commitment)
        .set("signed", Fr::from(0u64))
        .opening("", &o);
    let o = open(500, count);
    let range = Inputs::default()
        .set("commitment[0]", o.commitment)
        .set("signed", Fr::from(0u64))
        .set("lo_inclusive", Fr::from(1u64))
        .set("hi_inclusive", Fr::from(0u64))
        .array("lo", &limbs(500, count))
        .array("hi", &limbs(max, count))
        .opening("", &o);
    let (left, right) = (open(7, count), open(max, count));
    let committed = Inputs::default()
        .set("left[0]", left.commitment)
        .set("right[0]", right.commitment)
        .set("signed", Fr::from(0u64))
        .accept(LT)
        .opening("left_", &left)
        .opening("right_", &right);
    vec![
        (format!("open_{bits}"), opens),
        compare_inputs(bits, count, 20, 18, GE),
        (format!("range_{bits}"), range),
        (format!("compare_committed_{bits}"), committed),
    ]
}

#[test]
fn every_family_proves_and_verifies_at_every_width() {
    assert_eq!(circuits().count(), 45);
    for (bits, count) in WIDTHS {
        for (name, inputs) in cases(bits, count) {
            prove_and_verify(&name, inputs);
        }
    }
}

/// `cargo test --release -p zk-groth16 --test predicates -- --ignored --nocapture [samples via
/// ZK_BENCH_SAMPLES, default 20]`: prove (witness included) and verify times per circuit, measured
/// the same way as the Spartan-WHIR `bench_predicates` example.
#[test]
#[ignore = "benchmark; run explicitly"]
fn benchmark() {
    let samples: usize = std::env::var("ZK_BENCH_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let threads = std::thread::available_parallelism().map_or(1, usize::from);
    println!("threads={threads} samples={samples}");
    println!(
        "{:<24}{:>8}{:>10}{:>9}{:>9}{:>10}{:>8}",
        "circuit", "constr", "load_ms", "p50", "p95", "verify_ms", "proof_B"
    );
    for (bits, count) in WIDTHS {
        for (name, inputs) in cases(bits, count) {
            let started = Instant::now();
            let circuit = setup().circuit(&name).unwrap();
            let load_ms = started.elapsed().as_secs_f64() * 1e3;
            let mut times = Vec::with_capacity(samples);
            let mut out = circuit.prove(&inputs.0).unwrap();
            for _ in 0..samples {
                let started = Instant::now();
                out = circuit.prove(&inputs.0).unwrap();
                times.push(started.elapsed().as_secs_f64() * 1e3);
            }
            let vk = setup().verifying_key(&name).unwrap();
            let started = Instant::now();
            vk.verify(&out.public_signals, &out.proof).unwrap();
            let verify_ms = started.elapsed().as_secs_f64() * 1e3;
            times.sort_by(f64::total_cmp);
            let at = |q: f64| {
                times[((times.len() as f64 * q).ceil() as usize).clamp(1, times.len()) - 1]
            };
            println!(
                "{:<24}{:>8}{:>10.0}{:>9.1}{:>9.1}{:>10.1}{:>8}",
                name,
                circuit.constraints(),
                load_ms,
                at(0.5),
                at(0.95),
                verify_ms,
                out.proof.len()
            );
        }
    }
}

#[test]
fn false_statements_and_wrong_openings_cannot_be_proven() {
    let (name, inputs) = compare_inputs(64, 4, 17, 18, GE);
    let circuit = setup().circuit(&name).unwrap();
    assert!(circuit.prove(&inputs.0).is_err(), "17 >= 18");
    let (_, inputs) = compare_inputs(64, 4, 20, 18, GE);
    let forged = inputs.set("blinding[0]", Fr::from(1u64));
    assert!(circuit.prove(&forged.0).is_err(), "wrong blinding");
}

#[test]
fn a_proof_is_bound_to_its_circuit() {
    let (name, inputs) = compare_inputs(32, 2, 20, 18, GE);
    let out = setup().circuit(&name).unwrap().prove(&inputs.0).unwrap();
    let other = setup().verifying_key("compare_64").unwrap();
    assert!(other.verify(&out.public_signals, &out.proof).is_err());
}

#[test]
fn commitments_hide_and_bind() {
    let blinding = random_scalar().unwrap();
    let a = commit(false, &limbs(5, 2), blinding);
    assert_ne!(a, commit(false, &limbs(6, 2), blinding));
    assert_ne!(a, commit(true, &limbs(5, 2), blinding));
    assert_ne!(a, commit(false, &limbs(5, 4), blinding));
    assert_ne!(a, commit(false, &limbs(5, 2), random_scalar().unwrap()));
}
