//! Per-predicate benchmark over the real library: `cargo run --release -p zk-sdk --example bench_predicates [samples]`.
//! Reports setup, prove (witness included) and verify quantiles plus proof size for each built-in
//! circuit. Quantiles above the sample count's resolution are reported as `n/a`, not extrapolated.

use std::time::Instant;

use zk_sdk::predicate::{Commitment, IntType, Op, Opening, Predicate, Predicates, Witness};

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
        for (family, claim, openings) in cases(ty)? {
            let zk = Predicates::new().with_minimum_bits(115); // the larger circuits attain 115 bits
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

/// Every benchmarked claim over `ty`, with the openings that prove it.
fn cases(ty: IntType) -> zk_sdk::Result<Vec<(&'static str, Predicate, Vec<Opening>)>> {
    let values = |numbers: &[u32]| -> zk_sdk::Result<(Vec<Commitment>, Vec<Opening>)> {
        numbers
            .iter()
            .map(|n| Commitment::commit(ty, *n))
            .collect::<zk_sdk::Result<Vec<_>>>()
            .map(|pairs| pairs.into_iter().unzip())
    };
    let (c, o) = values(&[20, 30])?;
    let (small, small_openings) = values(&[20, 30, 40, 9])?;
    let (wide, wide_openings) = values(&[10, 20, 30, 40, 5, 10, 15, 20])?;
    let (product, product_openings) = values(&[20, 60])?;
    let (division, division_openings) = values(&[47, 5, 2])?;
    Ok(vec![
        ("open", Predicate::opens(c[0]), vec![o[0].clone()]),
        ("compare", Predicate::at_least(c[0], 18), vec![o[0].clone()]),
        (
            "range",
            Predicate::in_range(c[0], 10, 40),
            vec![o[0].clone()],
        ),
        (
            "compare_committed",
            Predicate::compare_committed(c[0], Op::Lt, c[1]),
            o,
        ),
        (
            "conserve4",
            Predicate::conserve(small[..2].to_vec(), small[2..].to_vec(), 1u8),
            small_openings,
        ),
        (
            "conserve8",
            Predicate::conserve(wide[..4].to_vec(), wide[4..].to_vec(), 50u8),
            wide_openings,
        ),
        (
            "multiply",
            Predicate::multiply(product[0], 3u8, product[1]),
            product_openings,
        ),
        (
            "divide",
            Predicate::divide(division[0], 9u8, division[1], division[2]),
            division_openings,
        ),
    ])
}

fn witness(openings: &[Opening]) -> Witness {
    openings.to_vec().into()
}

fn rayon_threads() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}
