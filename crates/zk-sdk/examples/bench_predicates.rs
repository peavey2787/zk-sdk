//! Per-predicate benchmark over the real library: `cargo run --release -p zk-sdk --example bench_predicates [samples]`.
//! Reports setup, prove (witness included) and verify quantiles plus proof size for each built-in
//! circuit. Quantiles above the sample count's resolution are reported as `n/a`, not extrapolated.

use std::time::Instant;

use zk_sdk::predicate::{Commitment, IntType, Op, Predicate, Predicates};

fn quantile(sorted: &[f64], q: f64, resolution: usize) -> String {
    if sorted.len() < resolution {
        return "n/a".into();
    }
    let index = ((sorted.len() as f64 * q).ceil() as usize).clamp(1, sorted.len()) - 1;
    format!("{:.0}", sorted[index])
}

fn main() -> zk_sdk::Result<()> {
    let samples: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    println!(
        "threads={} samples={samples} (p95 needs >=20 samples, p99 needs >=100)",
        rayon_threads()
    );
    println!(
        "{:<24}{:>10}{:>9}{:>9}{:>9}{:>10}{:>10}",
        "circuit", "setup_ms", "p50", "p95", "p99", "verify_ms", "proof_B"
    );
    for (ty, label) in [(IntType::U32, 32), (IntType::U64, 64), (IntType::U128, 128)] {
        let (a, oa) = Commitment::commit(ty, 20u32)?;
        let (b, ob) = Commitment::commit(ty, 30u32)?;
        let cases: [(&str, Predicate, Vec<zk_sdk::predicate::Opening>); 4] = [
            ("open", Predicate::opens(a), vec![oa.clone()]),
            ("compare", Predicate::at_least(a, 18), vec![oa.clone()]),
            ("range", Predicate::in_range(a, 10, 40), vec![oa.clone()]),
            (
                "compare_committed",
                Predicate::compare_committed(a, Op::Lt, b),
                vec![oa.clone(), ob],
            ),
        ];
        for (family, claim, openings) in cases {
            let zk = Predicates::new();
            let started = Instant::now();
            zk.prove(&claim, witness(&openings))?; // first call includes circuit load and setup
            let setup_ms = started.elapsed().as_secs_f64() * 1e3;
            let mut times = Vec::new();
            let mut proof = zk.prove(&claim, witness(&openings))?;
            for _ in 0..samples {
                let started = Instant::now();
                proof = zk.prove(&claim, witness(&openings))?;
                times.push(started.elapsed().as_secs_f64() * 1e3);
            }
            let started = Instant::now();
            zk.verify(&claim, &proof)?;
            let verify_ms = started.elapsed().as_secs_f64() * 1e3;
            times.sort_by(f64::total_cmp);
            println!(
                "{:<24}{:>10.0}{:>9}{:>9}{:>9}{:>10.1}{:>10}",
                format!("{family}_{label}"),
                setup_ms,
                quantile(&times, 0.5, 1),
                quantile(&times, 0.95, 20),
                quantile(&times, 0.99, 100),
                verify_ms,
                proof.as_bytes().len()
            );
        }
    }
    Ok(())
}

fn witness(openings: &[zk_sdk::predicate::Opening]) -> zk_sdk::predicate::Witness {
    match openings {
        [one] => one.into(),
        [left, right] => (left.clone(), right.clone()).into(),
        _ => unreachable!("every benchmark case has one or two openings"),
    }
}

fn rayon_threads() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}
