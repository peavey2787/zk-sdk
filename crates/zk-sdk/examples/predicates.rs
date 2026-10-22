//! One example per predicate family, each with a true claim, a boundary claim and a false claim:
//! `cargo run --release -p zk-sdk --example predicates`.

use zk_sdk::predicate::{Commitment, IntType, Op, Predicate, Predicates};
use zk_sdk::Result;

fn main() -> Result<()> {
    let zk = Predicates::new();

    // Age threshold: the commitment is public, the age stays private.
    let (age, opening) = Commitment::commit(IntType::U32, 18u32)?;
    let claim = Predicate::at_least(age, 18); // boundary: exactly 18
    let proof = zk.prove(&claim, &opening)?;
    zk.verify(&claim, &proof)?;
    println!(
        "age >= 18: proved and verified ({} B)",
        proof.as_bytes().len()
    );
    println!(
        "age >= 19: {}",
        outcome(zk.prove(&Predicate::at_least(age, 19), &opening))
    );

    // Equality / inequality.
    let (id, opening) = Commitment::commit(IntType::U64, 4242u64)?;
    zk.verify(
        &Predicate::equals(id, 4242),
        &zk.prove(&Predicate::equals(id, 4242), &opening)?,
    )?;
    println!(
        "id != 4243: {}",
        outcome(zk.prove(&Predicate::not_equals(id, 4243), &opening))
    );
    println!(
        "id != 4242: {}",
        outcome(zk.prove(&Predicate::not_equals(id, 4242), &opening))
    );

    // Signed range with an exclusive end.
    let (temperature, opening) = Commitment::commit(IntType::I64, -4i64)?;
    let claim = Predicate::in_range_with(temperature, -10, -4, true, false);
    println!("-10 <= t < -4: {}", outcome(zk.prove(&claim, &opening)));
    let claim = Predicate::in_range(temperature, -10, -4);
    zk.verify(&claim, &zk.prove(&claim, &opening)?)?;
    println!("-10 <= t <= -4: proved and verified");

    // Committed value against another committed value, held by the same prover.
    let (balance, balance_opening) = Commitment::commit(IntType::I128, 1_000i32)?;
    let (debt, debt_opening) = Commitment::commit(IntType::I128, 250i32)?;
    let claim = Predicate::compare_committed(balance, Op::Ge, debt);
    let proof = zk.prove(&claim, (balance_opening, debt_opening))?;
    zk.verify(&claim, &proof)?;
    println!("balance >= debt: proved and verified");

    // Knowledge of an opening.
    let claim = Predicate::opens(balance);
    println!(
        "opens(balance) with the wrong secret: {}",
        outcome(zk.prove(&claim, &opening))
    );
    Ok(())
}

fn outcome<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => "proved".into(),
        Err(error) => format!("refused ({error})"),
    }
}
