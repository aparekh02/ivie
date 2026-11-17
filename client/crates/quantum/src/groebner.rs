//! The algebraic (Groebner/elimination) preimage attack on reduced-round Poseidon.
//!
//! For the single-input leaf domain the iterated round system has one true
//! unknown (the input limb `b`); eliminating the intermediate state variables
//! yields a single univariate generator `f(b) = leaf_r(b) - target` over `F_p`
//! (`poseidon::leaf_poly`) — this *is* the Groebner basis of the preimage ideal
//! under an elimination order. Solving the preimage is then finding the
//! `F_p`-roots of `f`, which is classical finite-field root finding:
//!
//!   1. `g = gcd(f, x^p - x)` keeps exactly the roots lying in the base field
//!      (every balance/limb is an `F_p` element), collapsing a degree-`3^r`
//!      polynomial to the product of its linear factors;
//!   2. Cantor–Zassenhaus equal-degree splitting pulls one linear factor
//!      `x - b*` out of `g`, and `b*` is a preimage.
//!
//! This costs `~log2(p)` polynomial squarings mod `f` (each `~deg(f)^1.6` field
//! ops with FFT), i.e. `~3^r` work up to polylog factors — vastly below the
//! `~p ≈ 2^251` of brute force and below the `2^125` of a Grover preimage
//! search, *as long as `3^r` is small enough to materialize `f`*. That caveat is
//! the entire security margin, quantified in `margin`.

use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_poly::univariate::{DensePolynomial, DenseOrSparsePolynomial};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use zknet_core::stark::field::F;
use crate::poseidon;

type Poly = DensePolynomial<F>;

/// `a mod m` (polynomial remainder over the field `F`).
fn rem(a: &Poly, m: &Poly) -> Poly {
    let da: DenseOrSparsePolynomial<F> = a.into();
    let dm: DenseOrSparsePolynomial<F> = m.into();
    da.divide_with_q_and_r(&dm).map(|(_, r)| r).unwrap_or_else(|| a.clone())
}

fn mulmod(a: &Poly, b: &Poly, m: &Poly) -> Poly {
    rem(&a.naive_mul(b), m)
}

/// Monic gcd of `a` and `b`.
fn gcd(mut a: Poly, mut b: Poly) -> Poly {
    while !b.is_zero() {
        let r = rem(&a, &b);
        a = b;
        b = r;
    }
    // normalize to monic
    if let Some(lead) = a.coeffs.last().copied().filter(|l| !l.is_zero()) {
        let inv = lead.inverse().unwrap();
        a = DensePolynomial::from_coefficients_vec(a.coeffs.iter().map(|&x| x * inv).collect());
    }
    a
}

/// MSB-first bits of the big-endian integer held in little-endian `bytes`.
fn bits_msb(bytes_le: &[u8]) -> Vec<bool> {
    let mut bits = Vec::new();
    for byte in bytes_le.iter().rev() {
        for k in (0..8).rev() {
            bits.push((byte >> k) & 1 == 1);
        }
    }
    // drop leading zeros
    let first = bits.iter().position(|&b| b).unwrap_or(bits.len());
    bits.split_off(first)
}

/// `base^exp mod m`, exponent given as MSB-first bits.
fn powmod(base: &Poly, exp_bits: &[bool], m: &Poly) -> Poly {
    let one = DensePolynomial::from_coefficients_vec(vec![F::from(1u64)]);
    let base = rem(base, m);
    let mut acc = one;
    for &bit in exp_bits {
        acc = mulmod(&acc, &acc, m);
        if bit {
            acc = mulmod(&acc, &base, m);
        }
    }
    acc
}

fn modulus_bits() -> Vec<bool> {
    bits_msb(&F::MODULUS.to_bytes_le())
}

/// MSB-first bits of `(p-1)/2` (p is odd, so subtract 1 = clear bit 0, then >>1).
fn half_pm1_bits() -> Vec<bool> {
    let mut bytes = F::MODULUS.to_bytes_le();
    bytes[0] &= !1u8; // p-1
    // shift right by one bit across the LE byte array
    let mut carry = 0u8;
    for byte in bytes.iter_mut().rev() {
        let new_carry = *byte & 1;
        *byte = (*byte >> 1) | (carry << 7);
        carry = new_carry;
    }
    bits_msb(&bytes)
}

fn x_poly() -> Poly {
    DensePolynomial::from_coefficients_vec(vec![F::zero(), F::from(1u64)])
}

/// Deterministic xorshift → field element, for Cantor–Zassenhaus random shifts.
fn rng(state: &mut u64) -> F {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    F::from(*state)
}

/// Cantor–Zassenhaus: extract one `F_p`-root of a squarefree polynomial that
/// splits into linear factors (as `g` from `gcd(f, x^p-x)` does).
fn one_root(g: &Poly, seed: u64) -> Option<F> {
    if g.degree() == 0 {
        return None;
    }
    if g.degree() == 1 {
        // g = c1 x + c0  ->  root = -c0/c1
        let c0 = g.coeffs.first().copied().unwrap_or(F::zero());
        let c1 = g.coeffs[1];
        return Some(-c0 * c1.inverse().unwrap());
    }
    let half = half_pm1_bits();
    let mut state = seed | 1;
    for _ in 0..64 {
        let a = rng(&mut state);
        // h = (x + a)^((p-1)/2) - 1  mod g
        let xa = DensePolynomial::from_coefficients_vec(vec![a, F::from(1u64)]);
        let mut hp = powmod(&xa, &half, g);
        if hp.coeffs.is_empty() {
            hp = DensePolynomial::from_coefficients_vec(vec![F::zero()]);
        } else {
            hp.coeffs[0] -= F::from(1u64);
        }
        let h = gcd(g.clone(), hp);
        let d = h.degree();
        if d >= 1 && d < g.degree() {
            // recurse into the smaller split factor
            return one_root(&h, seed.wrapping_mul(6364136223846793005).wrapping_add(1));
        }
    }
    None
}

/// Find one `F_p`-root of an arbitrary univariate `f` over `F_p`: keep the
/// base-field roots via `gcd(f, x^p - x)` and split one out. Shared by the
/// univariate elimination attack here and the XL solver in [`crate::xl`].
pub fn one_fp_root(f: &Poly, seed: u64) -> Option<F> {
    if f.degree() == 0 {
        return None;
    }
    let xp = powmod(&x_poly(), &modulus_bits(), f);
    let xpx = &xp - &x_poly();
    let g = gcd(f.clone(), xpx);
    if g.degree() < 1 {
        return None;
    }
    one_root(&g, seed)
}

/// All `F_p`-roots of `f` (up to `limit`), by repeatedly splitting out linear
/// factors. Used to exhibit *second preimages* (a collision in the leaf hash),
/// which let a wallet value be swapped under an unchanged Merkle root.
pub fn fp_roots(f: &Poly, seed: u64, limit: usize) -> Vec<F> {
    let xp = powmod(&x_poly(), &modulus_bits(), f);
    let xpx = &xp - &x_poly();
    let mut g = gcd(f.clone(), xpx);
    let mut out = Vec::new();
    let mut s = seed | 1;
    while g.degree() >= 1 && out.len() < limit {
        let Some(root) = one_root(&g, s) else { break };
        out.push(root);
        // divide g by (x - root)
        let lin = DensePolynomial::from_coefficients_vec(vec![-root, F::from(1u64)]);
        let dg: DenseOrSparsePolynomial<F> = (&g).into();
        let dl: DenseOrSparsePolynomial<F> = (&lin).into();
        match dg.divide_with_q_and_r(&dl) {
            Some((q, _)) => g = q,
            None => break,
        }
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
    }
    out
}

/// Outcome of the algebraic attack at `rounds`.
pub struct Preimage {
    pub rounds: usize,
    pub target: F,
    /// Recovered preimage `b*` with `leaf_r(b*, rounds) == target`, if found.
    pub found: Option<F>,
    /// Degree of the elimination polynomial = `3^rounds`.
    pub elim_degree: usize,
    /// Number of distinct `F_p`-preimages (degree of `gcd(f, x^p-x)`).
    pub root_count: usize,
    /// It actually verifies against the real `hash` round map.
    pub verified: bool,
}

/// Run the elimination attack: build `f`, keep its `F_p`-roots, recover one,
/// and verify it against the genuine reduced-round permutation.
pub fn attack(target: F, rounds: usize, seed: u64) -> Preimage {
    let f = poseidon::leaf_poly(target, rounds);
    let elim_degree = f.degree();

    // g = gcd(f, x^p - x): the F_p-rational roots.
    let xp = powmod(&x_poly(), &modulus_bits(), &f);
    let xpx = &xp - &x_poly();
    let g = gcd(f.clone(), xpx);
    let root_count = g.degree();

    let found = if root_count >= 1 { one_root(&g, seed) } else { None };
    let verified = found.map(|b| poseidon::leaf_r(b, rounds) == target).unwrap_or(false);

    Preimage { rounds, target, found, elim_degree, root_count, verified }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_reduced_round_preimage() {
        // Blind attack: pick a secret, publish only its reduced-round leaf hash,
        // recover a preimage from the hash alone, and verify it hashes back.
        for r in 1..=6 {
            let secret = F::from(0xABCDEF1234567u64 + r as u64);
            let target = poseidon::leaf_r(secret, r);
            let res = attack(target, r, 0xC0FFEE ^ r as u64);
            assert!(res.found.is_some(), "no preimage recovered at r={r}");
            assert!(res.verified, "recovered preimage does not verify at r={r}");
            assert!(res.root_count >= 1, "secret itself is a root, so >=1 at r={r}");
        }
    }
}
