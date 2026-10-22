//! Witness generation for every shipped circuit, from committed compiler output.

use zk_witness::{parse_inputs_json, WitnessCalculator, WitnessError};

fn arithmetic() -> WitnessCalculator {
    WitnessCalculator::new(
        include_bytes!("../../../testdata/arithmetic/arithmetic.r1cs"),
        include_str!("../../../testdata/arithmetic/arithmetic.sym"),
    )
    .unwrap()
}

fn millionaires() -> WitnessCalculator {
    WitnessCalculator::new(
        include_bytes!("../../../testdata/millionaires/millionaires.r1cs"),
        include_str!("../../../testdata/millionaires/millionaires.sym"),
    )
    .unwrap()
}

fn richer(alice: u64, bob: u64) -> Result<u64, WitnessError> {
    let json = format!(r#"{{"alice":"{alice}","bob":"{bob}"}}"#);
    let w = millionaires().witness(&parse_inputs_json(&json).unwrap())?;
    Ok(w.public_signals[0])
}

#[test]
fn arithmetic_matches_closed_form() {
    let inputs =
        parse_inputs_json(include_str!("../../../testdata/arithmetic/input.json")).unwrap();
    let w = arithmetic().witness(&inputs).unwrap();
    // x = 5, secret = 7: y = (5 * 7 + 5)^2 + 3 = 1603; public order is output y, then x.
    assert_eq!(w.public_signals, vec![1603, 5]);
}

#[test]
fn millionaires_verdicts_and_boundaries() {
    let max = (1 << 29) - 1;
    assert_eq!(richer(2_000_000, 1_000_000), Ok(1));
    assert_eq!(richer(1_000_000, 1_000_000), Ok(0));
    assert_eq!(richer(5, 1_000_000), Ok(0));
    assert_eq!(richer(max, max - 1), Ok(1));
    assert_eq!(richer(max - 1, max), Ok(0));
    assert_eq!(richer(0, 0), Ok(0));
}

#[test]
fn millionaires_rejects_values_outside_the_29_bit_range() {
    assert!(richer(1 << 29, 0).is_err());
    assert!(richer(0, 1 << 29).is_err());
}
