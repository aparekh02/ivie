//! Polynomial model of the in-AIR Poseidon permutation (`zknet_core::stark::hash`),
//! restricted to a tunable number of rounds `R`.
//!
//! Two views of the same reduced-round hash, used by the algebraic attack:
//!
//!   * **numeric** — `permute_r` / `leaf_r` evaluate the real round map (reusing
//!     `hash::round` and `hash::constants`) for `R` rounds, so a recovered
//!     preimage can be checked against the genuine primitive, not a re-implementation;
//!   * **symbolic** — `leaf_poly` composes the rounds over the polynomial ring
//!     `F_p[b]`, tracking the whole state `(s0(b), s1(b), s2(b))` as univariate
//!     polynomials in the single unknown input limb `b`. The output polynomial
//!     `s0(b) - target` is exactly the generator of the elimination ideal of the
//!     iterated round system (the intermediate state variables eliminated), i.e.
//!     the univariate Groebner basis of the preimage ideal under an elimination
//!     order. Its degree is `3^R` — the algebraic-degree growth that is the whole
//!     security argument of an arithmetization-friendly hash.
//!
//! The leaf domain is `P([b, 0, TAG_LEAF])[0]`, matching `hash::leaf`.

use ark_poly::DenseUVPolynomial;
use ark_poly::univariate::DensePolynomial;
use ark_ff::Zero;
use zknet_core::stark::field::F;
use zknet_core::stark::hash::{self, TAG_LEAF};

/// Reduced-round permutation: apply the first `r` real rounds of the permutation.
pub fn permute_r(input: [F; 3], r: usize) -> [F; 3] {
    let c = hash::constants();
    let r = r.min(hash::ROUNDS);
    c[..r].iter().fold(input, hash::round)
}

/// Reduced-round leaf hash: `P_r([b, 0, TAG_LEAF])[0]`. The attack target.
pub fn leaf_r(b: F, r: usize) -> F {
    permute_r([b, F::zero(), F::from(TAG_LEAF)], r)[0]
}

type Poly = DensePolynomial<F>;

fn cube(p: &Poly) -> Poly {
    // p^3 via two naive multiplications (schoolbook; degrees are modest for the R we run).
    p.naive_mul(p).naive_mul(p)
}

fn add_const(p: &Poly, c: F) -> Poly {
    let mut v = p.coeffs.to_vec();
    if v.is_empty() {
        v.push(c);
    } else {
        v[0] += c;
    }
    Poly::from_coefficients_vec(v)
}

fn scale(p: &Poly, k: F) -> Poly {
    Poly::from_coefficients_vec(p.coeffs.iter().map(|&x| x * k).collect())
}

/// Symbolic round on the polynomial state: mirrors `hash::round`
/// (`s_j += C; s_j = s_j^3; s = M·s`) with `M = [[3,1,1],[1,-1,1],[1,1,-2]]`.
fn round_poly(s: &[Poly; 3], c: &[F; 3]) -> [Poly; 3] {
    let cubes = [
        cube(&add_const(&s[0], c[0])),
        cube(&add_const(&s[1], c[1])),
        cube(&add_const(&s[2], c[2])),
    ];
    let sum = &(&cubes[0] + &cubes[1]) + &cubes[2];
    // out0 = sum + 2 c0 ; out1 = sum - 2 c1 ; out2 = sum - 3 c2
    let two = F::from(2u64);
    let three = F::from(3u64);
    [
        &sum + &scale(&cubes[0], two),
        &sum + &scale(&cubes[1], -two),
        &sum + &scale(&cubes[2], -three),
    ]
}

/// The elimination polynomial `f(b) = leaf_r(b) - target` over `F_p[b]`.
/// `f` is monic-up-to-scalar of degree `3^r`; its `F_p`-roots are exactly the
/// reduced-round preimages of `target` in the leaf domain.
pub fn leaf_poly(target: F, r: usize) -> Poly {
    let b = Poly::from_coefficients_vec(vec![F::zero(), F::from(1u64)]); // b
    let mut s = [
        b,
        Poly::zero(),
        Poly::from_coefficients_vec(vec![F::from(TAG_LEAF)]),
    ];
    let c = hash::constants();
    for cr in c[..r.min(hash::ROUNDS)].iter() {
        s = round_poly(&s, cr);
    }
    // f(b) = s0(b) - target
    add_const(&s[0], -target)
}

/// Algebraic degree of the reduced-round leaf hash: `3^r` (capped at the field
/// size in the exponent for reporting). This is the attacker-facing cost knob.
pub fn algebraic_degree_log2(r: usize) -> f64 {
    (r as f64) * (3f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::Polynomial;

    #[test]
    fn symbolic_matches_numeric() {
        // The composed polynomial, evaluated at a point, equals the real hash.
        for r in 0..=5 {
            let f = leaf_poly(F::zero(), r); // target 0 -> f(b) = leaf_r(b)
            for b in [1u64, 2, 7, 12345] {
                let bb = F::from(b);
                let got = f.evaluate(&bb);
                assert_eq!(got, leaf_r(bb, r), "mismatch at r={r}, b={b}");
            }
        }
    }

    #[test]
    fn degree_is_three_to_the_r() {
        for r in 0..=5 {
            let f = leaf_poly(F::from(999u64), r);
            assert_eq!(f.degree(), 3usize.pow(r as u32), "degree 3^{r}");
        }
    }
}
