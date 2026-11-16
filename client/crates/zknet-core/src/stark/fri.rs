//! FRI, in the shape of Stone / StarkWare's FriLayer.sol.
//!
//! Evaluations are stored in BIT-REVERSED order, so the 8 points of every
//! coset x·⟨ω_8⟩ sit in 8 consecutive slots and one Merkle leaf holds one
//! coset. Each committed layer is folded by 8 (three folds by 2 with β, β²,
//! β⁴) into the next; once the degree bound is ≤ 64 the last layer is sent as
//! coefficients. Layer 0 is the DEEP composition itself (StarkWare's
//! `friStepSizes[0] == 0`).

use super::field::{self, F};
use ark_ff::{Field, One};
use std::sync::OnceLock;

pub const STEP: u32 = 3;
pub const COSET: usize = 1 << STEP;
pub const MAX_LAST_LOG: u32 = 6;

pub fn bitrev(i: usize, log: u32) -> usize {
    if log == 0 { 0 } else { i.reverse_bits() >> (usize::BITS - log) }
}

/// (committed layers, log2 of last-layer coefficient count) for degree bound 2^log_d.
pub fn plan(log_d: u32) -> (usize, u32) {
    let k = log_d.saturating_sub(MAX_LAST_LOG).div_ceil(STEP);
    (k as usize, log_d - STEP * k)
}

/// ω_8^-j for j = 0..8.
fn w8_inv() -> &'static [F; 8] {
    static T: OnceLock<[F; 8]> = OnceLock::new();
    T.get_or_init(|| {
        let wi = field::root(8).inverse().unwrap();
        let mut t = [F::one(); 8];
        for j in 1..8 {
            t[j] = t[j - 1] * wi;
        }
        t
    })
}

#[inline]
pub fn fold2(a: F, b: F, xinv: F, beta: F, half: F) -> F {
    (a + b) * half + beta * (a - b) * half * xinv
}

/// Folds one coset (bit-reversed: slot j holds f(x0·ω_8^bitrev3(j))) to f'(x0^8).
pub fn fold_coset(v: &[F], x0_inv: F, beta: F) -> F {
    let half = F::from(2u64).inverse().unwrap();
    let w = w8_inv();
    // round 1: pairs (2k, 2k+1) at x0·ω_8^bitrev3(2k), bitrev3(2k) = 0, 2, 1, 3
    let e1 = [0usize, 2, 1, 3];
    let r1: Vec<F> = (0..4).map(|k| fold2(v[2 * k], v[2 * k + 1], x0_inv * w[e1[k]], beta, half)).collect();
    // round 2: points x0²·{1, ω_8^2}
    let x2 = x0_inv.square();
    let b2 = beta.square();
    let r2 = [fold2(r1[0], r1[1], x2, b2, half), fold2(r1[2], r1[3], x2 * w[2], b2, half)];
    // round 3: point x0^4
    fold2(r2[0], r2[1], x2.square(), b2.square(), half)
}

/// Domain point of bit-reversed slot `i` in a layer of size 2^log with coset offset `off`.
pub fn point(off: F, log: u32, i: usize) -> F {
    off * field::pow(field::root(1 << log), bitrev(i, log) as u64)
}
