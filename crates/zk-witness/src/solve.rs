//! Generic R1CS witness solver. It never trusts its own derivations: the finished assignment is
//! always checked against every constraint, so a solver bug can only cause a failure, never a
//! witness for a false statement.
//!
//! Strategy: repeatedly pick a constraint that is linear in its unknowns after substituting known
//! wires and solve it. Boolean wires (constraint `w * (w - 1) = 0`) additionally allow decoding a
//! known value into bits, which resolves circom's `Num2Bits` hint (`out[i] <-- (in >> i) & 1`).

use std::collections::BTreeMap;

use crate::{
    field::Field,
    r1cs::{Constraint, LinearCombination, R1cs, Term},
    Result, WitnessError,
};

type Linear<E> = BTreeMap<u32, E>;

enum Step {
    Done,
    Assigned,
    Stuck,
}

struct Solver<'a, F: Field> {
    r1cs: &'a R1cs<F::Element>,
    values: Vec<Option<F::Element>>,
    boolean: Vec<bool>,
}

/// Known part of a linear combination and its still-unknown terms.
fn split<F: Field>(
    values: &[Option<F::Element>],
    lc: &LinearCombination<F::Element>,
) -> (F::Element, Vec<Term<F::Element>>) {
    let mut known = F::ZERO;
    let mut unknown = Vec::new();
    for term in lc {
        match values[term.wire as usize] {
            Some(v) => known = F::add(known, F::mul(term.coef, v)),
            None => unknown.push(*term),
        }
    }
    (known, unknown)
}

fn accumulate<F: Field>(
    into: &mut Linear<F::Element>,
    terms: &[Term<F::Element>],
    scale: F::Element,
) {
    for term in terms {
        let slot = into.entry(term.wire).or_insert(F::ZERO);
        *slot = F::add(*slot, F::mul(term.coef, scale));
    }
}

/// Recognise `w * (w - 1) = 0` in any scaling and return `w`.
fn boolean_wire<F: Field>(c: &Constraint<F::Element>) -> Option<u32> {
    let (single, pair) = if c.a.len() == 1 {
        (&c.a, &c.b)
    } else {
        (&c.b, &c.a)
    };
    let [Term { wire, coef: ca }] = single[..] else {
        return None;
    };
    let [first, second] = pair[..] else {
        return None;
    };
    let (one, var) = if first.wire == 0 {
        (first, second)
    } else {
        (second, first)
    };
    (c.c.is_empty()
        && one.wire == 0
        && var.wire == wire
        && ca != F::ZERO
        && one.coef == F::neg(var.coef))
    .then_some(wire)
}

/// `sum(coef_i * bit_i) = target` with distinct power-of-two coefficients (or their negations).
fn decode_bits<F: Field>(
    terms: &Linear<F::Element>,
    target: F::Element,
) -> Option<Vec<(u32, F::Element)>> {
    decode_signed::<F>(terms, target, false).or_else(|| decode_signed::<F>(terms, target, true))
}

fn decode_signed<F: Field>(
    terms: &Linear<F::Element>,
    target: F::Element,
    negate: bool,
) -> Option<Vec<(u32, F::Element)>> {
    let sign = |v: F::Element| F::to_u128(if negate { F::neg(v) } else { v });
    let mut weights = terms
        .iter()
        .map(|(wire, coef)| Some((*wire, sign(*coef).filter(|w| w.is_power_of_two())?)))
        .collect::<Option<Vec<(u32, u128)>>>()?;
    weights.sort_by_key(|(_, weight)| std::cmp::Reverse(*weight));
    let mut remaining = sign(target)?;
    let mut bits = Vec::with_capacity(weights.len());
    for (wire, weight) in weights {
        let bit = remaining >= weight;
        remaining -= u128::from(bit) * weight;
        bits.push((wire, if bit { F::ONE } else { F::ZERO }));
    }
    (remaining == 0).then_some(bits)
}

impl<'a, F: Field> Solver<'a, F> {
    fn new(r1cs: &'a R1cs<F::Element>, inputs: &[(u32, F::Element)]) -> Self {
        let mut values = vec![None; r1cs.n_wires as usize];
        values[0] = Some(F::ONE);
        for (wire, value) in inputs {
            values[*wire as usize] = Some(*value);
        }
        let mut boolean = vec![false; r1cs.n_wires as usize];
        for wire in r1cs.constraints.iter().filter_map(boolean_wire::<F>) {
            boolean[wire as usize] = true;
        }
        Self {
            r1cs,
            values,
            boolean,
        }
    }

    /// Solve `sum(coef * x) = target` over the unknown wires.
    fn solve_linear(&mut self, terms: Linear<F::Element>, target: F::Element) -> Step {
        let terms: Linear<F::Element> = terms.into_iter().filter(|(_, c)| *c != F::ZERO).collect();
        if terms.is_empty() {
            return Step::Done;
        }
        if let (1, Some((wire, coef))) = (terms.len(), terms.iter().next()) {
            self.values[*wire as usize] = Some(F::mul(target, F::inv(*coef)));
            return Step::Assigned;
        }
        let all_boolean = terms.keys().all(|w| self.boolean[*w as usize]);
        match all_boolean
            .then(|| decode_bits::<F>(&terms, target))
            .flatten()
        {
            Some(bits) => {
                for (wire, bit) in bits {
                    self.values[wire as usize] = Some(bit);
                }
                Step::Assigned
            }
            None => Step::Stuck,
        }
    }

    fn step(&mut self, c: &Constraint<F::Element>) -> Step {
        let (ka, ua) = split::<F>(&self.values, &c.a);
        let (kb, ub) = split::<F>(&self.values, &c.b);
        let (kc, uc) = split::<F>(&self.values, &c.c);
        // a * B = C  (or A * b = C) is linear in the unknowns when one side is fully known.
        let (scale, other, known_other) = match (ua.is_empty(), ub.is_empty()) {
            (true, _) => (ka, ub, kb),
            (_, true) => (kb, ua, ka),
            _ => return Step::Stuck,
        };
        let mut terms = Linear::new();
        accumulate::<F>(&mut terms, &other, scale);
        accumulate::<F>(&mut terms, &uc, F::neg(F::ONE));
        self.solve_linear(terms, F::sub(kc, F::mul(scale, known_other)))
    }

    fn run(&mut self) {
        let mut pending: Vec<&Constraint<F::Element>> = self.r1cs.constraints.iter().collect();
        loop {
            let before = pending.len();
            let mut assigned = false;
            let mut still = Vec::with_capacity(before);
            for c in pending {
                match self.step(c) {
                    Step::Done => {}
                    Step::Assigned => {
                        assigned = true;
                        still.push(c);
                    }
                    Step::Stuck => still.push(c),
                }
            }
            pending = still;
            if !assigned && pending.len() == before {
                return;
            }
        }
    }
}

fn evaluate<F: Field>(lc: &LinearCombination<F::Element>, w: &[F::Element]) -> F::Element {
    lc.iter().fold(F::ZERO, |acc, t| {
        F::add(acc, F::mul(t.coef, w[t.wire as usize]))
    })
}

pub fn check<F: Field>(r1cs: &R1cs<F::Element>, w: &[F::Element]) -> Result<()> {
    for (index, c) in r1cs.constraints.iter().enumerate() {
        if F::mul(evaluate::<F>(&c.a, w), evaluate::<F>(&c.b, w)) != evaluate::<F>(&c.c, w) {
            return Err(WitnessError::Unsatisfied(index));
        }
    }
    Ok(())
}

/// Complete the assignment from `(wire, value)` inputs. Returns all wire values, wire 0 first.
pub fn solve<F: Field>(
    r1cs: &R1cs<F::Element>,
    inputs: &[(u32, F::Element)],
) -> Result<Vec<F::Element>> {
    let mut solver = Solver::<F>::new(r1cs, inputs);
    solver.run();
    let unsolved = solver.values.iter().filter(|v| v.is_none()).count();
    if unsolved > 0 {
        return Err(WitnessError::Unsolved(unsolved));
    }
    let witness: Vec<F::Element> = solver.values.into_iter().flatten().collect();
    check::<F>(r1cs, &witness)?;
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::KoalaBear;

    type K = KoalaBear;

    #[test]
    fn bit_decoding_handles_signs_and_remainders() {
        let terms: Linear<u64> = [(1, 1), (2, 2), (3, 4)].into_iter().collect();
        assert_eq!(
            decode_bits::<K>(&terms, 5),
            Some(vec![(3, 1), (2, 0), (1, 1)])
        );
        assert_eq!(decode_bits::<K>(&terms, 8), None);
        let negated: Linear<u64> = [(1, K::neg(1)), (2, K::neg(2))].into_iter().collect();
        assert_eq!(
            decode_bits::<K>(&negated, K::neg(3)),
            Some(vec![(2, 1), (1, 1)])
        );
        let not_powers: Linear<u64> = [(1, 3), (2, 4)].into_iter().collect();
        assert_eq!(decode_bits::<K>(&not_powers, 3), None);
    }
}
