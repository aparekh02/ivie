//! A real Grover amplitude-amplification simulation (statevector), not just a
//! `sqrt(N)` formula. The amplitudes are real throughout, because the phase
//! oracle and the inversion-about-the-mean diffuser keep them real, so one
//! `Vec<f64>` of length N = 2^n is the exact state.
//!
//! ```text
//!   |psi_0> = uniform superposition            amp[x] = 1/sqrt(N)
//!   oracle  : amp[x] -> -amp[x]  for marked x  (phase flip)
//!   diffuser: amp[x] -> 2*mean - amp[x]        (inversion about the mean)
//!   repeat k times; success = sum over marked x of amp[x]^2
//! ```
//!
//! For a search with M marked items the optimal iteration count is
//! `k ≈ (pi/4)·sqrt(N/M)`, after which the success probability is near 1. The
//! classical baseline is `N/M` expected oracle calls, so Grover's `k` queries
//! against the classical `N/M` is the measured quadratic speedup.

use rayon::prelude::*;

/// What one Grover experiment measured.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub n: usize,
    /// N = 2^n, the size of the search space.
    pub space: u64,
    /// Number of inputs the oracle marks.
    pub marked: u64,
    /// Grover iterations run (the quantum oracle-call count).
    pub iters: usize,
    /// Probability a final measurement yields a marked input.
    pub success: f64,
    /// Classical expected oracle calls to hit a marked input: N / M.
    pub classical_calls: f64,
    /// log2 of the quantum oracle-call count (the measured quantum exponent).
    pub quantum_bits: f64,
    /// log2 of the classical oracle-call count.
    pub classical_bits: f64,
}

/// Evaluates the oracle on every input in [0, 2^n) (parallel), returning the
/// marked bitmap. Toy sizes only: this is the exponential scan the quantum
/// algorithm is meant to avoid, used here to set up and score the simulation.
pub fn marked_set<F>(n: usize, oracle: F) -> Vec<bool>
where
    F: Fn(u64) -> bool + Sync + Send,
{
    (0..(1u64 << n)).into_par_iter().map(oracle).collect()
}

/// Optimal Grover iterations for M marked items in a space of size 2^n:
/// `round(pi/(4·theta) - 1/2)` with `theta = asin(sqrt(M/N))`.
pub fn optimal_iters(n: usize, m: u64) -> usize {
    if m == 0 {
        return 0;
    }
    let nn = (1u64 << n) as f64;
    let theta = (m as f64 / nn).sqrt().asin();
    if theta == 0.0 {
        return 0;
    }
    ((std::f64::consts::FRAC_PI_2 / theta - 1.0) / 2.0).max(0.0).round() as usize
}

/// Runs `iters` Grover rounds against a precomputed marked bitmap and returns
/// the success probability.
pub fn run(n: usize, marks: &[bool], iters: usize) -> f64 {
    let n_states = 1usize << n;
    let mut amp = vec![1.0f64 / (n_states as f64).sqrt(); n_states];
    for _ in 0..iters {
        for (x, a) in amp.iter_mut().enumerate() {
            if marks[x] {
                *a = -*a;
            }
        }
        let mean: f64 = amp.iter().sum::<f64>() / n_states as f64;
        for a in amp.iter_mut() {
            *a = 2.0 * mean - *a;
        }
    }
    marks.iter().zip(&amp).filter(|(m, _)| **m).map(|(_, a)| a * a).sum()
}

/// Builds the marked set, picks the optimal iteration count, runs the
/// simulation, and reports the measured quantum vs classical cost.
pub fn search<F>(n: usize, oracle: F) -> Outcome
where
    F: Fn(u64) -> bool + Sync + Send,
{
    let marks = marked_set(n, oracle);
    let marked = marks.iter().filter(|b| **b).count() as u64;
    let iters = optimal_iters(n, marked);
    let success = if marked == 0 { 0.0 } else { run(n, &marks, iters) };
    let space = 1u64 << n;
    let classical_calls = if marked == 0 { f64::INFINITY } else { space as f64 / marked as f64 };
    Outcome {
        n,
        space,
        marked,
        iters,
        success,
        classical_calls,
        quantum_bits: if iters == 0 { 0.0 } else { (iters as f64).log2() },
        classical_bits: classical_calls.log2(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_single_marked_item() {
        // One needle in 2^12: Grover concentrates almost all probability on it.
        let target = 2730u64;
        let out = search(12, |x| x == target);
        assert_eq!(out.marked, 1);
        assert!(out.success > 0.99, "success {} after {} iters", out.success, out.iters);
        // ~ (pi/4) sqrt(4096) = ~50 iters vs 4096 classical
        assert!(out.iters >= 40 && out.iters <= 60, "iters {}", out.iters);
    }

    #[test]
    fn speedup_is_quadratic() {
        // M marked -> ~ (pi/4) sqrt(N/M) iters; doubling n adds ~0.5 to the exponent.
        let o1 = search(10, |x| x % 256 == 0); // N/M = 256, sqrt = 16
        let o2 = search(14, |x| x % 256 == 0); // N/M = 256 again
        assert!((o1.quantum_bits - o2.quantum_bits).abs() < 0.6);
        assert!(o1.success > 0.9 && o2.success > 0.9);
    }

    #[test]
    fn empty_search_terminates() {
        let out = search(8, |_| false);
        assert_eq!(out.marked, 0);
        assert_eq!(out.iters, 0);
        assert_eq!(out.success, 0.0);
    }
}
