//! Portable circom witness calculator. Pure Rust, so the same code runs on Windows, Linux and
//! wasm32 with no C++ toolchain, WSL or Linux binary. KoalaBear is built in; other backends plug
//! their own prime field in through [`Field`].
mod error;
mod field;
mod inputs;
mod r1cs;
mod solve;
mod sym;
mod wtns;

use std::collections::BTreeMap;

pub use error::{Result, WitnessError};
pub use field::{Field, KoalaBear};
pub use inputs::{parse_json as parse_inputs_json, Inputs};
pub use r1cs::{Constraint, LinearCombination, R1cs, Term};

/// Named inputs over the field `F` (KoalaBear inputs are [`Inputs`]).
pub type FieldInputs<F> = BTreeMap<String, <F as Field>::Element>;

/// A circuit ready to generate witnesses over the field `F`.
pub struct WitnessCalculator<F: Field = KoalaBear> {
    r1cs: R1cs<F::Element>,
    signals: sym::SignalMap,
}

/// A generated witness plus the public signals it implies (circom order: outputs, then public
/// inputs). The public signals are derived by the prover and are not an independent statement.
pub struct Witness<F: Field = KoalaBear> {
    /// Every wire value, wire 0 (the constant 1) first.
    pub assignment: Vec<F::Element>,
    pub public_signals: Vec<F::Element>,
}

impl<F: Field> Witness<F> {
    /// The witness as a circom `.wtns` file.
    pub fn wtns(&self) -> Vec<u8> {
        wtns::encode::<F>(&self.assignment)
    }
}

impl WitnessCalculator {
    /// A KoalaBear calculator.
    pub fn new(r1cs: &[u8], sym: &str) -> Result<Self> {
        Self::in_field(r1cs, sym)
    }
}

impl<F: Field> WitnessCalculator<F> {
    /// A calculator over `F`; the `.r1cs` header prime must be F's modulus.
    pub fn in_field(r1cs: &[u8], sym: &str) -> Result<Self> {
        Ok(Self {
            r1cs: r1cs::parse::<F>(r1cs)?,
            signals: sym::parse(sym)?,
        })
    }

    /// The parsed constraint system.
    pub fn r1cs(&self) -> &R1cs<F::Element> {
        &self.r1cs
    }

    /// Resolve named inputs to wires, rejecting unknown, non-input, duplicate and missing ones.
    fn wire_inputs(&self, inputs: &FieldInputs<F>) -> Result<Vec<(u32, F::Element)>> {
        let range = self.r1cs.input_wires();
        let mut assigned = Vec::with_capacity(inputs.len());
        for (name, value) in inputs {
            let wire = self
                .signals
                .get(&format!("main.{name}"))
                .copied()
                .filter(|w| range.contains(w))
                .ok_or_else(|| WitnessError::UnknownInput(name.clone()))?;
            if !F::is_canonical(*value) {
                return Err(WitnessError::NotCanonical(name.clone()));
            }
            assigned.push((wire, *value));
        }
        self.require_all(&assigned)?;
        Ok(assigned)
    }

    fn require_all(&self, assigned: &[(u32, F::Element)]) -> Result<()> {
        let missing = self.signals.iter().find(|(name, wire)| {
            name.starts_with("main.")
                && self.r1cs.input_wires().contains(wire)
                && !assigned.iter().any(|(w, _)| w == *wire)
        });
        match missing {
            Some((name, _)) => Err(WitnessError::MissingInput(
                name.trim_start_matches("main.").into(),
            )),
            None => Ok(()),
        }
    }

    /// Generate and satisfiability-check a witness. Fails rather than emit an invalid one.
    pub fn witness(&self, inputs: &FieldInputs<F>) -> Result<Witness<F>> {
        let assignment = solve::solve::<F>(&self.r1cs, &self.wire_inputs(inputs)?)?;
        let public_signals = assignment[1..=self.r1cs.n_public()].to_vec();
        Ok(Witness {
            assignment,
            public_signals,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const R1CS: &[u8] = include_bytes!("../../../testdata/age_over/age_over.r1cs");
    const SYM: &str = include_str!("../../../testdata/age_over/age_over.sym");
    const REFERENCE: &[u8] = include_bytes!("../../../testdata/age_over/age_over.wtns");

    fn inputs(age: u64, threshold: u64) -> Inputs {
        [("age".to_owned(), age), ("threshold".to_owned(), threshold)]
            .into_iter()
            .collect()
    }

    #[test]
    fn matches_the_circom_cpp_reference_witness_byte_for_byte() {
        let calc = WitnessCalculator::new(R1CS, SYM).unwrap();
        let witness = calc.witness(&inputs(20, 18)).unwrap();
        assert_eq!(witness.wtns(), REFERENCE);
        assert_eq!(witness.public_signals, vec![1, 18]);
    }

    #[test]
    fn computes_both_verdicts() {
        let calc = WitnessCalculator::new(R1CS, SYM).unwrap();
        for (age, threshold, holds) in [(18, 18, 0), (17, 18, 0), (19, 18, 1), (255, 0, 1)] {
            let w = calc.witness(&inputs(age, threshold)).unwrap();
            assert_eq!(
                w.public_signals,
                vec![holds, threshold],
                "{age}>{threshold}"
            );
        }
    }

    #[test]
    fn rejects_bad_inputs() {
        let calc = WitnessCalculator::new(R1CS, SYM).unwrap();
        let out_of_range = calc.witness(&inputs(256, 18));
        assert!(matches!(
            out_of_range,
            Err(WitnessError::Unsatisfied(_) | WitnessError::Unsolved(_))
        ));
        let mut unknown = inputs(20, 18);
        unknown.insert("nope".into(), 1);
        assert_eq!(
            calc.witness(&unknown).err(),
            Some(WitnessError::UnknownInput("nope".into()))
        );
        let mut missing = inputs(20, 18);
        missing.remove("age");
        assert_eq!(
            calc.witness(&missing).err(),
            Some(WitnessError::MissingInput("age".into()))
        );
        let huge = calc.witness(&inputs(u64::MAX, 18));
        assert_eq!(huge.err(), Some(WitnessError::NotCanonical("age".into())));
    }
}
