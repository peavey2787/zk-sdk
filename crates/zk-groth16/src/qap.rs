//! The R1CS-to-QAP step exactly as snarkjs sets it up, so proofs match snarkjs zkeys.
//!
//! snarkjs adds one row `A = signal, B = 0` per public input (and the constant 1) after the
//! circuit's constraints, and takes the quotient on the odd coset of the domain (points `w * g^i`
//! with `w` a primitive root of order 2n), whose Lagrange basis the zkey's H section already
//! encodes. The prover therefore supplies the evaluations `A(x) B(x) - C(x)` on that coset, without
//! dividing by the vanishing polynomial.

use ark_bn254::Fr;
use ark_ff::Zero;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

/// Sparse rows of `(coefficient, wire)`.
pub type Matrix = Vec<Vec<(Fr, usize)>>;

/// The A and B matrices of an r1cs (C is implied: every satisfied row has `C = A * B`).
pub struct Qap {
    pub a: Matrix,
    pub b: Matrix,
    /// The constant wire plus the public signals.
    pub n_inputs: usize,
    pub domain: Radix2EvaluationDomain<Fr>,
}

fn evaluate(row: &[(Fr, usize)], assignment: &[Fr]) -> Fr {
    row.iter()
        .map(|(coef, wire)| *coef * assignment[*wire])
        .sum()
}

impl Qap {
    /// `None` if the system is too large for BN254's two-adic domain.
    pub fn new(a: Matrix, b: Matrix, n_inputs: usize) -> Option<Self> {
        let domain = Radix2EvaluationDomain::new(a.len() + n_inputs)?;
        // The odd coset needs a domain twice as large.
        Radix2EvaluationDomain::<Fr>::new(2 * domain.size())?;
        Some(Self {
            a,
            b,
            n_inputs,
            domain,
        })
    }

    /// Evaluations of `A B - C` on the odd coset for a satisfying `assignment`.
    pub fn quotient(&self, assignment: &[Fr]) -> Vec<Fr> {
        let size = self.domain.size();
        let mut a = vec![Fr::zero(); size];
        let mut b = vec![Fr::zero(); size];
        let mut c = vec![Fr::zero(); size];
        for (i, (row_a, row_b)) in self.a.iter().zip(&self.b).enumerate() {
            a[i] = evaluate(row_a, assignment);
            b[i] = evaluate(row_b, assignment);
            c[i] = a[i] * b[i];
        }
        let rows = self.a.len();
        a[rows..rows + self.n_inputs].copy_from_slice(&assignment[..self.n_inputs]);

        let shift = Radix2EvaluationDomain::<Fr>::new(2 * size)
            .expect("checked in new")
            .element(1);
        let odd = self.domain.get_coset(shift).expect("checked in new");
        for values in [&mut a, &mut b, &mut c] {
            self.domain.ifft_in_place(values);
            odd.fft_in_place(values);
        }
        a.iter()
            .zip(&b)
            .zip(&c)
            .map(|((a, b), c)| *a * b - c)
            .collect()
    }
}
