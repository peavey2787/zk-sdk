//! Differential test of every arithmetic circuit against the reference semantics.
//!
//! For thousands of randomised and boundary claims over all six integer types, the circuit's
//! witness exists (every constraint is satisfied) exactly when `Predicate::holds` says the claim
//! is true. This catches both an unsound circuit (accepts a false claim) and an incomplete one
//! (rejects a true claim) without paying for a proof per case; real proofs are exercised in
//! `tests/arithmetic.rs`.

use std::collections::HashMap;

use zk_witness::WitnessCalculator;

use super::bundle;
use super::claim::{Op, Operand, Predicate};
use super::commit::{Commitment, Opening, FIELD_MODULUS};
use super::engine::assignment;
use super::int::{IntType, Number, Width};
use super::set::{SetPath, SetTree};

const TYPES: [IntType; 6] = [
    IntType::U32,
    IntType::I32,
    IntType::U64,
    IntType::I64,
    IntType::U128,
    IntType::I128,
];
const OPS: [Op; 6] = [Op::Lt, Op::Le, Op::Gt, Op::Ge, Op::Eq, Op::Ne];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn wide(&mut self) -> u128 {
        (u128::from(self.next()) << 64) | u128::from(self.next())
    }
}

/// Bits of magnitude small enough that `x * y + z` of three samples still fits the type.
fn small_bits(ty: IntType) -> u32 {
    match ty.width {
        Width::W32 => 14,
        Width::W64 => 30,
        Width::W128 => 60,
    }
}

fn small(ty: IntType, rng: &mut Rng) -> i128 {
    let bits = rng.below(small_bits(ty) as usize + 1);
    let magnitude = if bits == 0 {
        0
    } else {
        i128::from(rng.next() >> (64 - bits))
    };
    if ty.signed && rng.below(2) == 1 {
        -magnitude
    } else {
        magnitude
    }
}

fn type_min(ty: IntType) -> Number {
    match (ty.signed, ty.width) {
        (false, _) => Number::from(0u8),
        (true, Width::W128) => Number::from(i128::MIN),
        (true, width) => Number::from(-(1i128 << (width.bits() - 1))),
    }
}

fn type_max(ty: IntType) -> Number {
    match (ty.signed, ty.width) {
        (false, Width::W128) => Number::from(u128::MAX),
        (false, width) => Number::from((1u128 << width.bits()) - 1),
        (true, Width::W128) => Number::from(i128::MAX),
        (true, width) => Number::from((1i128 << (width.bits() - 1)) - 1),
    }
}

/// A uniformly random value of the full range of `ty`.
fn uniform(ty: IntType, rng: &mut Rng) -> Number {
    let bits = ty.width.bits();
    let raw = rng.wide() & (u128::MAX >> (128 - bits));
    if !ty.signed {
        return Number::from(raw);
    }
    let shift = 128 - bits;
    Number::from(((raw << shift) as i128) >> shift)
}

/// Mostly small values, often boundary values, sometimes anything.
fn any(ty: IntType, rng: &mut Rng) -> Number {
    match rng.below(4) {
        0 => [
            type_min(ty),
            type_max(ty),
            Number::from(0u8),
            Number::from(1u8),
        ][rng.below(4)],
        1 => uniform(ty, rng),
        _ => Number::from(small(ty, rng)),
    }
}

/// A non-negative amount that fits the width of `ty`.
fn amount(ty: IntType, rng: &mut Rng) -> Number {
    let mask = u128::MAX >> (128 - ty.width.bits());
    match rng.below(3) {
        0 => Number::from(0u8),
        1 => Number::from(rng.wide() & mask),
        _ => Number::from(small(IntType::new(ty.width, false), rng) as u128),
    }
}

struct Case {
    claim: Predicate,
    openings: Vec<Opening>,
    path: Option<SetPath>,
}

impl Case {
    fn new(claim: Predicate, openings: Vec<Opening>) -> Self {
        Self {
            claim,
            openings,
            path: None,
        }
    }
}

fn blinding(rng: &mut Rng) -> [u32; 8] {
    std::array::from_fn(|_| (rng.next() % u64::from(FIELD_MODULUS)) as u32)
}

fn commit(ty: IntType, value: Number, rng: &mut Rng) -> (Commitment, Opening) {
    Commitment::commit_with_blinding(ty, value, blinding(rng)).unwrap()
}

/// Commit to `values`; with `public`, some positions become public operands instead.
fn operands(
    ty: IntType,
    values: [Number; 4],
    public: [bool; 4],
    rng: &mut Rng,
) -> ([Operand; 4], Vec<Opening>) {
    let mut openings = Vec::new();
    let operands = std::array::from_fn(|i| {
        if public[i] {
            Operand::Public(values[i])
        } else {
            let (commitment, opening) = commit(ty, values[i], rng);
            openings.push(opening);
            Operand::Committed(commitment)
        }
    });
    (operands, openings)
}

/// Which of the four operands are public: never all of them.
fn visibility(rng: &mut Rng) -> [bool; 4] {
    let mut public: [bool; 4] = std::array::from_fn(|_| rng.below(3) == 0);
    if public.iter().all(|p| *p) {
        public[rng.below(4)] = false;
    }
    public
}

fn sum_case(ty: IntType, rng: &mut Rng) -> Case {
    let count = 1 + rng.below(8);
    let plus_count = rng.below(count + 1);
    let values: Vec<Number> = (0..count).map(|_| any(ty, rng)).collect();
    let (commitments, openings): (Vec<_>, Vec<_>) =
        values.iter().map(|v| commit(ty, *v, rng)).unzip();
    let (plus, minus) = commitments.split_at(plus_count);
    let claim = Predicate::sum(
        plus.to_vec(),
        amount(ty, rng),
        OPS[rng.below(6)],
        minus.to_vec(),
        amount(ty, rng),
    );
    Case::new(claim, openings)
}

/// A sum that balances exactly: the right constant is solved from small values.
fn balanced_sum_case(ty: IntType, rng: &mut Rng) -> Case {
    let count = 2 + rng.below(7);
    let mut plus_count = 1 + rng.below(count - 1);
    let mut raw: Vec<i128> = (0..count).map(|_| small(ty, rng)).collect();
    let sides = |raw: &[i128], at: usize| {
        (
            raw[..at].iter().sum::<i128>(),
            raw[at..].iter().sum::<i128>(),
        )
    };
    if sides(&raw, plus_count).0 < sides(&raw, plus_count).1 {
        // Inputs must cover outputs: swap the two groups so the fee is non-negative.
        raw.rotate_left(plus_count);
        plus_count = count - plus_count;
    }
    let (left, right) = sides(&raw, plus_count);
    let fee = (left - right + rng.below(3) as i128 - 1).max(0);
    let (commitments, openings): (Vec<_>, Vec<_>) = raw
        .iter()
        .map(|v| commit(ty, Number::from(*v), rng))
        .unzip();
    let (inputs, outputs) = commitments.split_at(plus_count);
    Case::new(
        Predicate::conserve(inputs.to_vec(), outputs.to_vec(), fee as u128),
        openings,
    )
}

fn arithmetic_case(ty: IntType, rng: &mut Rng) -> Case {
    let (x, y, z) = (small(ty, rng), small(ty, rng), small(ty, rng));
    let exact = x * y + z;
    let t = match rng.below(4) {
        0 => exact + 1,
        1 => exact - 1,
        2 => small(ty, rng),
        _ => exact,
    };
    let t = if ty.signed { t } else { t.max(0) };
    let values = [x, y, z, t].map(Number::from);
    let (operands, openings) = operands(ty, values, visibility(rng), rng);
    let [x, y, z, t] = operands;
    let op = if rng.below(2) == 0 {
        Op::Eq
    } else {
        OPS[rng.below(6)]
    };
    Case::new(Predicate::arithmetic(x, y, z, op, t), openings)
}

fn extreme_arithmetic_case(ty: IntType, rng: &mut Rng) -> Case {
    let values = [any(ty, rng), any(ty, rng), any(ty, rng), any(ty, rng)];
    let (operands, openings) = operands(ty, values, visibility(rng), rng);
    let [x, y, z, t] = operands;
    Case::new(
        Predicate::arithmetic(x, y, z, OPS[rng.below(6)], t),
        openings,
    )
}

fn divide_case(ty: IntType, rng: &mut Rng) -> Case {
    let divisor = small(ty, rng);
    let quotient = small(ty, rng);
    let remainder = match rng.below(5) {
        0 => divisor,
        1 if ty.signed => -1,
        2 => (divisor - 1).max(0),
        3 => 0,
        _ => small(ty, rng).abs(),
    };
    let divisor = if ty.signed && rng.below(8) == 0 {
        -divisor
    } else {
        divisor
    };
    let dividend = quotient * divisor + remainder + i128::from(rng.below(6) == 0);
    let values = [dividend, divisor, quotient, remainder].map(Number::from);
    let (operands, openings) = operands(ty, values, visibility(rng), rng);
    let [dividend, divisor, quotient, remainder] = operands;
    Case::new(
        Predicate::divide(dividend, divisor, quotient, remainder),
        openings,
    )
}

/// A committed point near a public centre, with a radius that is often exactly on the boundary.
fn distance_case(ty: IntType, rng: &mut Rng) -> Case {
    let reach = |rng: &mut Rng| small(ty, rng) % 1000;
    let (cx, cy) = (small(ty, rng), small(ty, rng));
    let (dx, dy) = (reach(rng), reach(rng));
    let (x, y) = (cx + dx, cy + dy);
    let exact = (dx * dx + dy * dy) as f64;
    let radius = match rng.below(5) {
        0 => exact.sqrt().floor() as i128,
        1 => exact.sqrt().ceil() as i128,
        2 => 0,
        3 => i128::from(small(IntType::new(ty.width, false), rng).unsigned_abs() as u64),
        _ => exact.sqrt().round() as i128 + 1,
    };
    let (x, y) = if rng.below(6) == 0 {
        (any(ty, rng), any(ty, rng))
    } else {
        (Number::from(x), Number::from(y))
    };
    let (cx, cy) = (Number::from(cx), Number::from(cy));
    let ((x, ox), (y, oy)) = (commit(ty, x, rng), commit(ty, y, rng));
    Case::new(
        Predicate::distance(x, y, (cx, cy), OPS[rng.below(6)], Number::from(radius)),
        vec![ox, oy],
    )
}

#[test]
fn distances_agree_with_the_semantics() {
    run("distance", 40, distance_case);
}

fn fits(ty: IntType, case: &Case) -> bool {
    case.claim.statement().is_ok() && case.openings.iter().all(|o| o.ty() == ty)
}

fn calculator<'a>(
    cache: &'a mut HashMap<String, WitnessCalculator>,
    circuit: &str,
) -> &'a WitnessCalculator {
    cache.entry(circuit.to_owned()).or_insert_with(|| {
        let bundled = bundle::lookup(circuit).unwrap();
        WitnessCalculator::new(bundled.r1cs, bundled.sym).unwrap()
    })
}

#[derive(Default)]
struct Tally {
    held: usize,
    refused: usize,
}

fn agree(case: &Case, cache: &mut HashMap<String, WitnessCalculator>, tally: &mut Tally) {
    let statement = case.claim.statement().unwrap();
    let values: Vec<Number> = case.openings.iter().map(Opening::value).collect();
    let expected = case.claim.holds(&values, case.path.as_ref()).unwrap();
    // A path of the wrong kind cannot even be assigned: that is "no witness" too.
    let satisfiable = assignment(&statement, &case.openings, case.path.as_ref())
        .map(|inputs| {
            calculator(cache, statement.circuit())
                .witness(&inputs)
                .is_ok()
        })
        .unwrap_or(false);
    assert_eq!(
        satisfiable,
        expected,
        "circuit {} disagrees with the semantics for {:?} over {:?}",
        statement.circuit(),
        case.claim,
        values
    );
    if expected {
        tally.held += 1;
    } else {
        tally.refused += 1;
    }
}

fn run(name: &str, rounds: usize, build: fn(IntType, &mut Rng) -> Case) {
    let mut cache = HashMap::new();
    let mut tally = Tally::default();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ name.len() as u64);
    for ty in TYPES {
        for _ in 0..rounds {
            let case = build(ty, &mut rng);
            assert!(
                fits(ty, &case),
                "{name}: generator produced an invalid case"
            );
            agree(&case, &mut cache, &mut tally);
        }
    }
    assert!(
        tally.held >= rounds && tally.refused >= rounds,
        "{name} must exercise both outcomes, got {} true / {} false",
        tally.held,
        tally.refused
    );
}

#[test]
fn sums_agree_with_the_semantics() {
    run("sum", 40, sum_case);
}

#[test]
fn balanced_conservation_agrees_with_the_semantics() {
    run("balanced", 40, balanced_sum_case);
}

#[test]
fn products_agree_with_the_semantics() {
    run("arithmetic", 40, arithmetic_case);
}

#[test]
fn extreme_products_agree_with_the_semantics() {
    run("extreme", 40, extreme_arithmetic_case);
}

#[test]
fn division_agrees_with_the_semantics() {
    run("divide", 40, divide_case);
}

/// A small set of values of `ty`, plus a probe that is a member about half of the time.
fn set_case(ty: IntType, rng: &mut Rng) -> Case {
    let members: Vec<Number> = (0..rng.below(6)).map(|_| any(ty, rng)).collect();
    let tree = SetTree::new(ty, members.clone()).unwrap();
    let probe = if !members.is_empty() && rng.below(2) == 0 {
        members[rng.below(members.len())]
    } else {
        any(ty, rng)
    };
    let (commitment, opening) = commit(ty, probe, rng);
    let absent = rng.below(2) == 0;
    // Mostly the honest path; sometimes the path of a different probe, which must be refused.
    let wrong = rng.below(4) == 0;
    let asked = if wrong { any(ty, rng) } else { probe };
    let path = if absent {
        tree.absence_path(asked)
    } else {
        tree.member_path(asked)
    };
    let claim = if absent {
        Predicate::not_member_of(commitment, tree.commitment())
    } else {
        Predicate::member_of(commitment, tree.commitment())
    };
    Case {
        claim,
        openings: vec![opening],
        path: path.ok().or_else(|| {
            tree.absence_path(0u8)
                .or_else(|_| tree.member_path(0u8))
                .ok()
        }),
    }
}

#[test]
fn set_claims_agree_with_the_semantics() {
    run("sets", 12, set_case);
}
