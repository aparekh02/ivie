//! QAOA search for a reduced-round Poseidon preimage — the "quantum hashing
//! engine" that breaks the hash down into a cost landscape.
//!
//! A full exact statevector simulation (no `sqrt(N)` shortcut): `n` qubits index
//! candidate inputs `b = x` in a window `[0, 2^n)`. The **cost Hamiltonian** is
//! diagonal,
//!
//! ```text
//!   C(x) = popcount( low_m_bits(leaf_r(x)) XOR low_m_bits(target) )
//! ```
//!
//! the Hamming distance between the candidate's hash output and the target over
//! the lowest `m` output bits. Its ground states `C(x) = 0` are exactly the
//! (windowed) preimages. Unlike a flat Grover oracle this cost is *graded* — a
//! near-miss scores low — so the QAOA phase separator `e^{-iγC}` plus the
//! transverse-field mixer `e^{-iβ∑X}` have real structure to amplify. We run `p`
//! layers, optimize `(γ,β)` by grid search, and report the probability mass the
//! optimized state puts on a true preimage versus the uniform `2^-n`.
//!
//! Honest scope: on a *random* (structureless) hash this reduces to amplitude
//! amplification and cannot beat Grover's `2^{m/2}`. The point of running it on
//! the real reduced-round map is to see whether the low-degree algebraic
//! structure leaks a landscape gradient — a diagnostic the algebraic attack
//! (`groebner`/`xl`) then exploits exactly.

use zknet_core::stark::field::F;
use ark_ff::{BigInteger, PrimeField};
use crate::poseidon;

#[derive(Clone, Copy)]
struct C64 {
    re: f64,
    im: f64,
}
impl C64 {
    fn new(re: f64, im: f64) -> Self {
        C64 { re, im }
    }
    fn norm2(&self) -> f64 {
        self.re * self.re + self.im * self.im
    }
    fn mul(&self, o: C64) -> C64 {
        C64::new(self.re * o.re - self.im * o.im, self.re * o.im + self.im * o.re)
    }
}

/// Lowest `m` bits of a field element's canonical integer form.
fn low_bits(x: F, m: u32) -> u64 {
    let bytes = x.into_bigint().to_bytes_le();
    let mut v = 0u64;
    for (i, &byte) in bytes.iter().take(8).enumerate() {
        v |= (byte as u64) << (8 * i);
    }
    if m >= 64 { v } else { v & ((1u64 << m) - 1) }
}

/// Cost array `C(x)` over the window `[0, 2^n)` for an `r`-round preimage of
/// `target`, comparing the lowest `m` output bits.
pub fn cost_table(target: F, r: usize, n: u32, m: u32) -> Vec<u32> {
    let tgt = low_bits(target, m);
    (0..(1u64 << n))
        .map(|x| (low_bits(poseidon::leaf_r(F::from(x), r), m) ^ tgt).count_ones())
        .collect()
}

/// One optimized QAOA run.
pub struct QaoaResult {
    pub n: u32,
    pub layers: usize,
    /// Probability the optimized state samples a true preimage (`C(x)=0`).
    pub success_prob: f64,
    /// Uniform baseline `marked / 2^n`.
    pub uniform_prob: f64,
    /// success_prob / uniform_prob.
    pub amplification: f64,
    /// Best angles found (γ_l, β_l per layer).
    pub gammas: Vec<f64>,
    pub betas: Vec<f64>,
    /// Number of windowed preimages (ground states).
    pub marked: usize,
    /// Top candidates by probability: (x, prob).
    pub top: Vec<(u64, f64)>,
}

fn apply_phase(state: &mut [C64], cost: &[u32], gamma: f64) {
    for (a, &c) in state.iter_mut().zip(cost) {
        let theta = -gamma * c as f64;
        *a = a.mul(C64::new(theta.cos(), theta.sin()));
    }
}

fn apply_mixer(state: &mut [C64], n: u32, beta: f64) {
    let (cb, sb) = (beta.cos(), beta.sin());
    for k in 0..n {
        let bit = 1usize << k;
        for x in 0..state.len() {
            if x & bit == 0 {
                let y = x | bit;
                let a0 = state[x];
                let a1 = state[y];
                // e^{-iβX}: a0' = cosβ a0 - i sinβ a1 ; a1' = -i sinβ a0 + cosβ a1
                state[x] = C64::new(cb * a0.re + sb * a1.im, cb * a0.im - sb * a1.re);
                state[y] = C64::new(cb * a1.re + sb * a0.im, cb * a1.im - sb * a0.re);
            }
        }
    }
}

fn run_angles(cost: &[u32], n: u32, gammas: &[f64], betas: &[f64]) -> Vec<C64> {
    let size = cost.len();
    let amp = (1.0 / size as f64).sqrt();
    let mut state = vec![C64::new(amp, 0.0); size];
    for (&g, &b) in gammas.iter().zip(betas) {
        apply_phase(&mut state, cost, g);
        apply_mixer(&mut state, n, b);
    }
    state
}

fn success(state: &[C64], cost: &[u32]) -> f64 {
    state.iter().zip(cost).filter(|&(_, &c)| c == 0).map(|(a, _)| a.norm2()).sum()
}

/// Run `p`-layer QAOA with a grid search over the angles (`grid` points each in
/// `[0, 2π)` for γ and `[0, π)` for β).
pub fn optimize(target: F, r: usize, n: u32, m: u32, p: usize, grid: usize) -> QaoaResult {
    use std::f64::consts::PI;
    let cost = cost_table(target, r, n, m);
    let marked = cost.iter().filter(|&&c| c == 0).count();
    let uniform = marked as f64 / (1u64 << n) as f64;

    let gvals: Vec<f64> = (0..grid).map(|i| 2.0 * PI * i as f64 / grid as f64).collect();
    let bvals: Vec<f64> = (0..grid).map(|i| PI * i as f64 / grid as f64).collect();

    // layer-greedy angle search: fix earlier layers, grid-search the newest.
    let mut gammas: Vec<f64> = Vec::new();
    let mut betas: Vec<f64> = Vec::new();
    for _ in 0..p {
        let mut best = (-1.0f64, 0.0, 0.0);
        for &g in &gvals {
            for &b in &bvals {
                gammas.push(g);
                betas.push(b);
                let st = run_angles(&cost, n, &gammas, &betas);
                let s = success(&st, &cost);
                if s > best.0 {
                    best = (s, g, b);
                }
                gammas.pop();
                betas.pop();
            }
        }
        gammas.push(best.1);
        betas.push(best.2);
    }

    let state = run_angles(&cost, n, &gammas, &betas);
    let success_prob = success(&state, &cost);
    let mut probs: Vec<(u64, f64)> = state.iter().enumerate().map(|(x, a)| (x as u64, a.norm2())).collect();
    probs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    probs.truncate(8);

    QaoaResult {
        n,
        layers: p,
        success_prob,
        uniform_prob: uniform,
        amplification: if uniform > 0.0 { success_prob / uniform } else { 0.0 },
        gammas,
        betas,
        marked,
        top: probs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qaoa_amplifies_the_preimage() {
        // Put a known preimage in the window; QAOA must raise its sampling
        // probability above the uniform baseline.
        let r = 3;
        let secret = F::from(42u64);
        let target = poseidon::leaf_r(secret, r);
        let res = optimize(target, r, 10, 12, 1, 24);
        assert!(res.marked >= 1, "the secret must be a ground state");
        assert!(
            res.success_prob > res.uniform_prob,
            "QAOA did not amplify: {} <= {}",
            res.success_prob,
            res.uniform_prob
        );
    }
}
