//! Arithmetic in the KoalaBear field, p = 2^31 - 2^24 + 1. Elements are canonical `u64 < P`.

pub const P: u64 = 2_130_706_433;

pub fn add(a: u64, b: u64) -> u64 {
    (a + b) % P
}

pub fn neg(a: u64) -> u64 {
    (P - a) % P
}

pub fn sub(a: u64, b: u64) -> u64 {
    add(a, neg(b))
}

pub fn mul(a: u64, b: u64) -> u64 {
    a * b % P
}

/// Inverse by Fermat. `a` must be non-zero.
pub fn inv(a: u64) -> u64 {
    let (mut result, mut base, mut exp) = (1, a, P - 2);
    while exp > 0 {
        if exp & 1 == 1 {
            result = mul(result, base);
        }
        base = mul(base, base);
        exp >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_and_subtraction() {
        for a in [1, 2, 18, P - 1, 123_456_789] {
            assert_eq!(mul(a, inv(a)), 1);
        }
        assert_eq!(sub(3, 5), P - 2);
        assert_eq!(add(P - 1, 1), 0);
        assert_eq!(neg(0), 0);
    }
}
