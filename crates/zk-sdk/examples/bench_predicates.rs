//! Per-predicate benchmark over the real library: `cargo run --release -p zk-sdk --example bench_predicates [samples]`.
//! Reports setup, prove (witness included) and verify quantiles plus proof size for each built-in
//! circuit. Quantiles above the sample count's resolution are reported as `n/a`, not extrapolated.

use std::time::Instant;

use zk_sdk::predicate::{
    Commitment, IntType, Number, Op, Opening, Predicate, Predicates, SetPath, SetTree, Witness,
};

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
        for (family, claim, openings, path) in cases(ty)? {
            let zk = Predicates::new().with_minimum_bits(115); // the larger circuits attain 115 bits
            let started = Instant::now();
            zk.prove(&claim, witness(&openings, &path))?; // first call includes circuit load and setup
            let setup_ms = started.elapsed().as_secs_f64() * 1e3;
            let mut times = Vec::new();
            let mut proof = zk.prove(&claim, witness(&openings, &path))?;
            for _ in 0..samples {
                let started = Instant::now();
                proof = zk.prove(&claim, witness(&openings, &path))?;
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

/// A benchmarked claim: its circuit family, the claim, the openings and any set path that prove it.
type Case = (&'static str, Predicate, Vec<Opening>, Option<SetPath>);

/// Membership and absence of a committed value in a set of `size` members, at the matching depth.
fn set_cases(ty: IntType, size: u32, depth: usize) -> zk_sdk::Result<Vec<Case>> {
    let tree = SetTree::new(ty, (0..size).map(|v| Number::from(v * 2)))?;
    let (member, member_opening) = Commitment::commit(ty, 2u8)?;
    let (stranger, stranger_opening) = Commitment::commit(ty, 3u8)?;
    let root = tree.commitment();
    assert_eq!(root.depth(), depth);
    let leaf = if depth == 8 { "member8" } else { "member20" };
    let gap = if depth == 8 { "absent8" } else { "absent20" };
    Ok(vec![
        (
            leaf,
            Predicate::member_of(member, root),
            vec![member_opening],
            Some(tree.member_path(2u8)?),
        ),
        (
            gap,
            Predicate::not_member_of(stranger, root),
            vec![stranger_opening],
            Some(tree.absence_path(3u8)?),
        ),
    ])
}

/// Every benchmarked claim over `ty`, with the openings that prove it.
fn cases(ty: IntType) -> zk_sdk::Result<Vec<Case>> {
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
    let mut cases: Vec<Case> = vec![
        ("open", Predicate::opens(c[0]), vec![o[0].clone()], None),
        (
            "compare",
            Predicate::at_least(c[0], 18),
            vec![o[0].clone()],
            None,
        ),
        (
            "range",
            Predicate::in_range(c[0], 10, 40),
            vec![o[0].clone()],
            None,
        ),
        (
            "compare_committed",
            Predicate::compare_committed(c[0], Op::Lt, c[1]),
            o,
            None,
        ),
        (
            "conserve4",
            Predicate::conserve(small[..2].to_vec(), small[2..].to_vec(), 1u8),
            small_openings,
            None,
        ),
        (
            "conserve8",
            Predicate::conserve(wide[..4].to_vec(), wide[4..].to_vec(), 50u8),
            wide_openings,
            None,
        ),
        (
            "multiply",
            Predicate::multiply(product[0], 3u8, product[1]),
            product_openings,
            None,
        ),
        (
            "divide",
            Predicate::divide(division[0], 9u8, division[1], division[2]),
            division_openings,
            None,
        ),
    ];
    cases.extend(set_cases(ty, 100, 8)?);
    cases.extend(set_cases(ty, 300, 20)?);
    Ok(cases)
}

fn witness(openings: &[Opening], path: &Option<SetPath>) -> Witness {
    let witness = Witness::from(openings.to_vec());
    match path {
        Some(path) => witness.with_path(path.clone()),
        None => witness,
    }
}

fn rayon_threads() -> usize {
    std::thread::available_parallelism().map_or(1, usize::from)
}
