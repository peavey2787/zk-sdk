//! Reference semantics of a claim: does it hold for the values behind its commitments?
//!
//! This is the mathematics the circuits enforce, on unbounded integers. The engine consults it
//! before proving so a false claim fails with a clear message instead of an unsatisfiable circuit,
//! and the tests use it as the independent oracle for the circuits. It is not a security boundary:
//! a verifier never runs it, and a prover who skipped it still could not produce a proof.

use std::cmp::Ordering;
use std::slice::Iter;

use super::claim::{Operand, Predicate};
use super::exact::Int;
use super::int::Number;
use super::set::{self, SetPath};
use crate::{Result, ZkError};

/// The opened values in witness order, consumed as the claim's committed positions are visited.
struct Values<'a>(Iter<'a, Number>);

impl Values<'_> {
    fn committed(&mut self) -> Result<Int> {
        self.0
            .next()
            .map(|n| Int::from(*n))
            .ok_or_else(|| ZkError::Predicate("fewer opened values than committed terms".into()))
    }

    fn operand(&mut self, operand: &Operand) -> Result<Int> {
        match operand {
            Operand::Public(number) => Ok(Int::from(*number)),
            Operand::Committed(_) => self.committed(),
        }
    }

    fn total(&mut self, count: usize, constant: Number) -> Result<Int> {
        (0..count).try_fold(
            Int::from(constant),
            |sum, _| Ok(sum.add(&self.committed()?)),
        )
    }

    fn finished(self) -> bool {
        self.0.len() == 0
    }
}

/// Why a claim is false, phrased for the prover who holds the values.
type Refusal = Option<String>;

fn refuse_unless(holds: bool, reason: impl FnOnce() -> String) -> Refusal {
    (!holds).then(reason)
}

fn side(ordering: Ordering) -> &'static str {
    match ordering {
        Ordering::Less => "is less than",
        Ordering::Equal => "equals",
        Ordering::Greater => "is greater than",
    }
}

impl Predicate {
    /// `None` when the claim is true for the committed positions' `values` (in witness order),
    /// otherwise why it is false.
    pub(super) fn refusal(&self, values: &[Number], path: Option<&SetPath>) -> Result<Refusal> {
        let mut values = Values(values.iter());
        let verdict = self.evaluate(&mut values, path)?;
        if values.finished() {
            Ok(verdict)
        } else {
            Err(ZkError::Predicate(
                "more opened values than committed terms".into(),
            ))
        }
    }

    fn evaluate(&self, values: &mut Values, path: Option<&SetPath>) -> Result<Refusal> {
        Ok(match self {
            Self::Opens { .. } => values.committed().map(|_| None)?,
            Self::Compare { op, bound, .. } => {
                let ordering = values.committed()?.compare(&Int::from(*bound));
                refuse_unless(op.accepts(ordering), || {
                    format!(
                        "the committed value {} the bound, which `{op:?}` does not accept",
                        side(ordering)
                    )
                })
            }
            Self::Range {
                lo,
                hi,
                lo_inclusive,
                hi_inclusive,
                ..
            } => {
                let value = values.committed()?;
                let above = value.compare(&Int::from(*lo));
                let below = value.compare(&Int::from(*hi));
                refuse_unless(
                    (above == Ordering::Greater || (*lo_inclusive && above == Ordering::Equal))
                        && (below == Ordering::Less || (*hi_inclusive && below == Ordering::Equal)),
                    || {
                        format!("the committed value is outside the range: it {} the low end and {} the high end", side(above), side(below))
                    },
                )
            }
            Self::CompareCommitted { op, .. } => {
                let ordering = values.committed()?.compare(&values.committed()?);
                refuse_unless(op.accepts(ordering), || {
                    format!(
                        "the left value {} the right value, which `{op:?}` does not accept",
                        side(ordering)
                    )
                })
            }
            Self::Sum {
                plus,
                minus,
                plus_constant,
                minus_constant,
                op,
            } => {
                let left = values.total(plus.len(), *plus_constant)?;
                let right = values.total(minus.len(), *minus_constant)?;
                let ordering = left.compare(&right);
                refuse_unless(op.accepts(ordering), || {
                    format!(
                        "the plus side {} the minus side, which `{op:?}` does not accept",
                        side(ordering)
                    )
                })
            }
            Self::Arithmetic { x, y, z, t, op } => {
                let (x, y) = (values.operand(x)?, values.operand(y)?);
                let (z, t) = (values.operand(z)?, values.operand(t)?);
                let ordering = x.mul(&y).add(&z).compare(&t);
                refuse_unless(op.accepts(ordering), || {
                    format!("x*y+z {} t, which `{op:?}` does not accept", side(ordering))
                })
            }
            Self::Divide {
                dividend,
                divisor,
                quotient,
                remainder,
            } => {
                let dividend = values.operand(dividend)?;
                let divisor = values.operand(divisor)?;
                let quotient = values.operand(quotient)?;
                let remainder = values.operand(remainder)?;
                division_refusal(&dividend, &divisor, &quotient, &remainder)
            }
            Self::Distance {
                center_x,
                center_y,
                op,
                radius,
                ..
            } => {
                let dx = values.committed()?.subtract(&Int::from(*center_x));
                let dy = values.committed()?.subtract(&Int::from(*center_y));
                let radius = Int::from(*radius);
                let ordering = dx.mul(&dx).add(&dy.mul(&dy)).compare(&radius.mul(&radius));
                refuse_unless(op.accepts(ordering), || {
                    format!(
                        "the squared distance {} the squared radius, which `{op:?}` does not accept",
                        side(ordering)
                    )
                })
            }
            Self::Member { set, .. } | Self::Absent { set, .. } => {
                let value = values.0.next().ok_or_else(|| {
                    ZkError::Predicate("fewer opened values than committed terms".into())
                })?;
                let absent = matches!(self, Self::Absent { .. });
                set::refusal(set, absent, set.ty().encode(*value)?, path)?
            }
        })
    }
}

fn division_refusal(dividend: &Int, divisor: &Int, quotient: &Int, remainder: &Int) -> Refusal {
    let zero = Int::zero();
    if divisor.compare(&zero) != Ordering::Greater {
        Some("the divisor must be positive (division by zero or a negative divisor)".into())
    } else if quotient.mul(divisor).add(remainder) != *dividend {
        Some("dividend != quotient * divisor + remainder".into())
    } else if remainder.compare(&zero) == Ordering::Less {
        Some("the remainder must not be negative".into())
    } else {
        refuse_unless(remainder.compare(divisor) == Ordering::Less, || {
            "the remainder must be less than the divisor".into()
        })
    }
}

#[cfg(test)]
impl Predicate {
    /// Whether the claim is true for `values`, in witness order.
    pub(super) fn holds(&self, values: &[Number], path: Option<&SetPath>) -> Result<bool> {
        self.refusal(values, path).map(|reason| reason.is_none())
    }
}

#[cfg(test)]
mod tests {
    impl Predicate {
        fn holds_plain(&self, values: &[Number]) -> Result<bool> {
            self.holds(values, None)
        }
    }

    use super::*;
    use crate::predicate::commit::Commitment;
    use crate::predicate::int::IntType;

    fn commitment() -> Commitment {
        Commitment::commit_with_blinding(IntType::I128, 0, [1; 8])
            .unwrap()
            .0
    }

    fn numbers(values: &[i128]) -> Vec<Number> {
        values.iter().map(|v| Number::from(*v)).collect()
    }

    #[test]
    fn sums_are_exact_beyond_the_integer_width() {
        let c = commitment();
        let claim = Predicate::conserve(vec![c, c], vec![c, c], 5);
        let near_max = i128::MAX;
        assert!(claim
            .holds_plain(&numbers(&[near_max, near_max, near_max, near_max - 5]))
            .unwrap());
        assert!(!claim
            .holds_plain(&numbers(&[near_max, near_max, near_max, near_max]))
            .unwrap());
        let wrap = Predicate::sum_equals(vec![c, c], c);
        assert!(
            !wrap
                .holds_plain(&numbers(&[i128::MAX, 1, i128::MIN]))
                .unwrap(),
            "2^127 - 1 + 1 is 2^127, not the wrapped -2^127"
        );
    }

    #[test]
    fn products_and_division_follow_the_stated_rules() {
        let c = commitment();
        let product = Predicate::multiply(c, c, c);
        assert!(product.holds_plain(&numbers(&[-6, 7, -42])).unwrap());
        assert!(!product.holds_plain(&numbers(&[6, 7, 43])).unwrap());
        let wide = Predicate::multiply(c, c, c);
        assert!(!wide
            .holds_plain(&numbers(&[1 << 100, 1 << 100, 0]))
            .unwrap());
        let divide = Predicate::divide(c, c, c, c);
        // Values in claim order: dividend, divisor, quotient, remainder.
        assert!(divide.holds_plain(&numbers(&[-10, 3, -4, 2])).unwrap());
        assert!(
            !divide.holds_plain(&numbers(&[-10, 3, -3, -1])).unwrap(),
            "remainder < 0"
        );
        assert!(
            !divide.holds_plain(&numbers(&[12, 3, 3, 3])).unwrap(),
            "remainder == divisor"
        );
        assert!(
            !divide.holds_plain(&numbers(&[0, 0, 0, 0])).unwrap(),
            "division by zero"
        );
        assert!(
            !divide.holds_plain(&numbers(&[14, -3, -4, 2])).unwrap(),
            "negative divisor"
        );
    }

    #[test]
    fn wrong_value_counts_are_errors() {
        let c = commitment();
        assert!(Predicate::opens(c).holds_plain(&[]).is_err());
        assert!(Predicate::opens(c).holds_plain(&numbers(&[1, 2])).is_err());
    }
}
