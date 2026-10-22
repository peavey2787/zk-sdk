//! Generic R1CS witness solver. It never trusts its own derivations: the finished assignment is
//! always checked against every constraint, so a solver bug can only cause a failure, never a
//! witness for a false statement.
//!
//! Strategy: repeatedly pick a constraint that is linear in its unknowns after substituting known
//! wires and solve it. Boolean wires (constraint `w * (w - 1) = 0`) additionally allow decoding a
//! known value into bits, which resolves circom's `Num2Bits` hint (`out[i] <-- (in >> i) & 1`).

use std::collections::BTreeMap;

use crate::{
    field::{add, inv, mul, neg, sub, P},
    r1cs::{Constraint, LinearCombination, R1cs, Term},
    Result, WitnessError,
};

type Linear = BTreeMap<u32, u64>;

enum Step {
    Done,
    Assigned,
    Stuck,
}

struct Solver<'a> {
    r1cs: &'a R1cs,
    values: Vec<Option<u64>>,
    boolean: Vec<bool>,
}

/// Known part of a linear combination and its still-unknown terms.
fn split(values: &[Option<u64>], lc: &LinearCombination) -> (u64, Vec<Term>) {
    let mut known = 0;
    let mut unknown = Vec::new();
    for term in lc {
        match values[term.wire as usize] {
            Some(v) => known = add(known, mul(term.coef, v)),
            None => unknown.push(*term),
        }
    }
    (known, unknown)
}

fn accumulate(into: &mut Linear, terms: &[Term], scale: u64) {
    for term in terms {
        let slot = into.entry(term.wire).or_insert(0);
        *slot = add(*slot, mul(term.coef, scale));
    }
}

fn is_zero(lc: &LinearCombination) -> bool {
    lc.is_empty()
}

/// Recognise `w * (w - 1) = 0` in any scaling and return `w`.
fn boolean_wire(c: &Constraint) -> Option<u32> {
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
    (is_zero(&c.c) && one.wire == 0 && var.wire == wire && ca != 0 && one.coef == neg(var.coef))
        .then_some(wire)
}

/// `sum(coef_i * bit_i) = target` with distinct power-of-two coefficients (or their negations).
fn decode_bits(terms: &Linear, target: u64) -> Option<Vec<(u32, u64)>> {
    let negative = terms.values().all(|c| *c > P / 2);
    let sign = |v: u64| if negative { neg(v) } else { v };
    let mut weights: Vec<(u32, u64)> = terms.iter().map(|(w, c)| (*w, sign(*c))).collect();
    if !weights.iter().all(|(_, c)| c.is_power_of_two()) {
        return None;
    }
    weights.sort_by_key(|(_, weight)| std::cmp::Reverse(*weight));
    let mut remaining = sign(target);
    let mut bits = Vec::with_capacity(weights.len());
    for (wire, weight) in weights {
        let bit = u64::from(remaining >= weight);
        remaining -= bit * weight;
        bits.push((wire, bit));
    }
    (remaining == 0).then_some(bits)
}

impl<'a> Solver<'a> {
    fn new(r1cs: &'a R1cs, inputs: &[(u32, u64)]) -> Self {
        let mut values = vec![None; r1cs.n_wires as usize];
        values[0] = Some(1);
        for (wire, value) in inputs {
            values[*wire as usize] = Some(*value);
        }
        let mut boolean = vec![false; r1cs.n_wires as usize];
        for wire in r1cs.constraints.iter().filter_map(boolean_wire) {
            boolean[wire as usize] = true;
        }
        Self {
            r1cs,
            values,
            boolean,
        }
    }

    /// Solve `sum(coef * x) = target` over the unknown wires.
    fn solve_linear(&mut self, terms: Linear, target: u64) -> Step {
        let terms: Linear = terms.into_iter().filter(|(_, c)| *c != 0).collect();
        if terms.is_empty() {
            return Step::Done;
        }
        if let (1, Some((wire, coef))) = (terms.len(), terms.iter().next()) {
            self.values[*wire as usize] = Some(mul(target, inv(*coef)));
            return Step::Assigned;
        }
        let all_boolean = terms.keys().all(|w| self.boolean[*w as usize]);
        match all_boolean.then(|| decode_bits(&terms, target)).flatten() {
            Some(bits) => {
                for (wire, bit) in bits {
                    self.values[wire as usize] = Some(bit);
                }
                Step::Assigned
            }
            None => Step::Stuck,
        }
    }

    fn step(&mut self, c: &Constraint) -> Step {
        let (ka, ua) = split(&self.values, &c.a);
        let (kb, ub) = split(&self.values, &c.b);
        let (kc, uc) = split(&self.values, &c.c);
        // a * B = C  (or A * b = C) is linear in the unknowns when one side is fully known.
        let (scale, other, known_other) = match (ua.is_empty(), ub.is_empty()) {
            (true, _) => (ka, ub, kb),
            (_, true) => (kb, ua, ka),
            _ => return Step::Stuck,
        };
        let mut terms = Linear::new();
        accumulate(&mut terms, &other, scale);
        accumulate(&mut terms, &uc, neg(1));
        self.solve_linear(terms, sub(kc, mul(scale, known_other)))
    }

    fn run(&mut self) {
        let mut pending: Vec<&Constraint> = self.r1cs.constraints.iter().collect();
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

fn evaluate(lc: &LinearCombination, w: &[u64]) -> u64 {
    lc.iter()
        .fold(0, |acc, t| add(acc, mul(t.coef, w[t.wire as usize])))
}

pub fn check(r1cs: &R1cs, w: &[u64]) -> Result<()> {
    for (index, c) in r1cs.constraints.iter().enumerate() {
        if mul(evaluate(&c.a, w), evaluate(&c.b, w)) != evaluate(&c.c, w) {
            return Err(WitnessError::Unsatisfied(index));
        }
    }
    Ok(())
}

/// Complete the assignment from `(wire, value)` inputs. Returns all wire values, wire 0 first.
pub fn solve(r1cs: &R1cs, inputs: &[(u32, u64)]) -> Result<Vec<u64>> {
    let mut solver = Solver::new(r1cs, inputs);
    solver.run();
    let unsolved = solver.values.iter().filter(|v| v.is_none()).count();
    if unsolved > 0 {
        return Err(WitnessError::Unsolved(unsolved));
    }
    let witness: Vec<u64> = solver.values.into_iter().flatten().collect();
    check(r1cs, &witness)?;
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_decoding_handles_signs_and_remainders() {
        let terms: Linear = [(1, 1), (2, 2), (3, 4)].into_iter().collect();
        assert_eq!(decode_bits(&terms, 5), Some(vec![(3, 1), (2, 0), (1, 1)]));
        assert_eq!(decode_bits(&terms, 8), None);
        let negated: Linear = [(1, neg(1)), (2, neg(2))].into_iter().collect();
        assert_eq!(decode_bits(&negated, neg(3)), Some(vec![(2, 1), (1, 1)]));
        let not_powers: Linear = [(1, 3), (2, 4)].into_iter().collect();
        assert_eq!(decode_bits(&not_powers, 3), None);
    }
}
