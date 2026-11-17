//! End-to-end orchestration: turn the reduced-round algebraic preimage attack
//! into the thing it threatens — a forged Merkle leaf — and quantify exactly how
//! many rounds of the in-AIR Poseidon put that out of reach (the security
//! margin). Also assembles the [`VizData`] that the visual-memory page renders.
//!
//! Threat model, stated honestly:
//!
//! * A STARK verifier commits to the state tree *before* the challenge `z`
//!   (`merkle.rs`). To tamper with a wallet's balance while keeping the
//!   committed root valid, an attacker needs a **second preimage** of that
//!   account's leaf: `b' != b` with `leaf(b') = leaf(b)`. Then the opened value
//!   changes but the hash, path and root do not.
//! * At the real `ROUNDS = 127` the leaf hash has algebraic degree `3^127 ≈
//!   2^201`, so the elimination polynomial cannot even be written down and the
//!   only route is a `~2^125` Grover preimage search — unreachable. The attack
//!   below therefore operates on a **reduced-round** hash and reports the round
//!   count at which it dies. That curve is the deliverable: it says how much
//!   margin `ROUNDS = 127` actually buys.

use serde::Serialize;
use ark_ff::PrimeField;
use zknet_core::stark::field::F;
use zknet_core::stark::hash;
use crate::{groebner, poseidon, qaoa, xl};

fn f_to_dec(x: F) -> String {
    x.into_bigint().to_string()
}

/// log2 of the field modulus `p = 2^251 + 17·2^192 + 1` (≈ 251.0).
pub fn field_bits() -> f64 {
    (F::MODULUS_BIT_SIZE - 1) as f64
}

const LOG2_3: f64 = 1.5849625007211562;

/// One round count on the margin curve.
#[derive(Serialize, Clone)]
pub struct RoundPoint {
    pub rounds: usize,
    /// log2 of the elimination-polynomial degree = `rounds · log2 3`.
    pub degree_log2: f64,
    /// log2 of the algebraic attack work: `~ (3^r) · log2(p)` field ops
    /// (root finding: `log2(p)` squarings, each quasi-linear in the degree).
    pub work_log2: f64,
    /// Can the degree-`3^r` polynomial be materialized at all (<= 2^28 terms)?
    pub materializable: bool,
    /// Did we actually run the elimination attack at this round count?
    pub ran: bool,
    /// Did the run recover a verified preimage?
    pub recovered: bool,
}

/// The security-margin curve for the in-AIR Poseidon leaf hash.
#[derive(Serialize)]
pub struct Margin {
    pub field_bits: f64,
    /// Grover preimage cost on the full hash: `field_bits / 2`.
    pub grover_preimage_bits: f64,
    pub full_rounds: usize,
    /// Algebraic degree at full rounds: `127 · log2 3 ≈ 201`.
    pub full_degree_log2: f64,
    pub points: Vec<RoundPoint>,
    /// First round count whose degree exceeds 2^64 / 2^96 / the Grover line.
    pub cross_64: usize,
    pub cross_96: usize,
    pub cross_grover: usize,
}

/// Build the margin curve. `ran_through` marks the round counts actually
/// executed (so the page can show measured vs projected).
pub fn margin(ran_through: usize, recovered_through: usize) -> Margin {
    let fb = field_bits();
    let mut points = Vec::new();
    let cross = |bits: f64| -> usize { ((bits / LOG2_3).ceil() as usize).max(1) };
    for r in 1..=hash::ROUNDS {
        let deg = r as f64 * LOG2_3;
        // root-finding work ~ 3^r squarings-equivalent * log2(p); keep in log2.
        let work = deg + fb.log2();
        points.push(RoundPoint {
            rounds: r,
            degree_log2: deg,
            work_log2: work,
            materializable: deg <= 28.0,
            ran: r <= ran_through,
            recovered: r <= recovered_through,
        });
        if r >= 40 {
            break;
        }
    }
    Margin {
        field_bits: fb,
        grover_preimage_bits: fb / 2.0,
        full_rounds: hash::ROUNDS,
        full_degree_log2: hash::ROUNDS as f64 * LOG2_3,
        points,
        cross_64: cross(64.0),
        cross_96: cross(96.0),
        cross_grover: cross(fb / 2.0),
    }
}

/// A forged / tamperable leaf via the reduced-round elimination attack.
#[derive(Serialize)]
pub struct LeafForgery {
    pub rounds: usize,
    pub committed_target: String,
    pub recovered_preimage: Option<String>,
    pub verified: bool,
    /// Number of distinct `F_p` preimages of the committed leaf.
    pub preimage_count: usize,
    /// A genuine second preimage `b' != b`, if one exists (enables tampering).
    pub second_preimage: Option<String>,
    pub original_value: String,
    /// True if a second preimage was found: the wallet value can be swapped
    /// under an unchanged Merkle root.
    pub tamperable: bool,
}

/// Forge a preimage of a committed reduced-round leaf, and look for a second
/// preimage that would let the committed value be swapped.
pub fn forge_leaf(original_value: u64, rounds: usize, seed: u64) -> LeafForgery {
    let b = F::from(original_value);
    let target = poseidon::leaf_r(b, rounds);
    let res = groebner::attack(target, rounds, seed);
    let f = poseidon::leaf_poly(target, rounds);
    let roots = groebner::fp_roots(&f, seed, 8);
    let second = roots.iter().copied().find(|&r| r != b);
    LeafForgery {
        rounds,
        committed_target: f_to_dec(target),
        recovered_preimage: res.found.map(f_to_dec),
        verified: res.verified,
        preimage_count: roots.len(),
        second_preimage: second.map(f_to_dec),
        original_value: f_to_dec(b),
        tamperable: second.is_some(),
    }
}

#[derive(Serialize)]
pub struct XlSummary {
    pub rounds: usize,
    pub vars: usize,
    pub gens: usize,
    pub solving_degree: Option<usize>,
    pub matrix_rows: Option<usize>,
    pub matrix_cols: Option<usize>,
    pub verified: bool,
}

#[derive(Serialize)]
pub struct QaoaSummary {
    pub n: u32,
    pub layers: usize,
    pub success_prob: f64,
    pub uniform_prob: f64,
    pub amplification: f64,
    pub marked: usize,
    pub top: Vec<(u64, f64)>,
}

/// Everything the visual-memory page needs, in one serializable blob.
#[derive(Serialize)]
pub struct VizData {
    pub field_bits: f64,
    pub full_rounds: usize,
    pub margin: Margin,
    pub forgery: LeafForgery,
    pub xl: Vec<XlSummary>,
    pub qaoa: QaoaSummary,
    /// log2 degree growth per round, for the headline chart.
    pub degree_growth: Vec<(usize, f64)>,
}

/// Run the full lab and assemble the visualization payload.
pub fn assemble(ran_through: usize, recovered_through: usize) -> VizData {
    let margin = margin(ran_through, recovered_through);
    let forgery = forge_leaf(1_000_000, 5, 0xBEEF);

    let mut xls = Vec::new();
    for r in 1..=2 {
        let secret = F::from(31337u64 + r as u64);
        let target = poseidon::leaf_r(secret, r);
        let res = xl::attack(target, r, 16, 6000);
        xls.push(XlSummary {
            rounds: r,
            vars: res.vars,
            gens: res.gens,
            solving_degree: res.solving_degree,
            matrix_rows: res.matrix.map(|m| m.0),
            matrix_cols: res.matrix.map(|m| m.1),
            verified: res.verified,
        });
    }

    let q = qaoa::optimize(poseidon::leaf_r(F::from(42u64), 3), 3, 12, 14, 2, 20);
    let qaoa = QaoaSummary {
        n: q.n,
        layers: q.layers,
        success_prob: q.success_prob,
        uniform_prob: q.uniform_prob,
        amplification: q.amplification,
        marked: q.marked,
        top: q.top,
    };

    let degree_growth: Vec<(usize, f64)> = margin.points.iter().map(|p| (p.rounds, p.degree_log2)).collect();

    VizData {
        field_bits: margin.field_bits,
        full_rounds: hash::ROUNDS,
        margin,
        forgery,
        xl: xls,
        qaoa,
        degree_growth,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forged_leaf_verifies() {
        let fg = forge_leaf(1_000_000, 5, 0xBEEF);
        assert!(fg.verified, "reduced-round leaf preimage must verify");
        assert!(fg.preimage_count >= 1);
    }

    #[test]
    fn margin_crossovers_are_ordered() {
        let m = margin(6, 6);
        assert!(m.cross_64 <= m.cross_96);
        assert!(m.cross_96 <= m.cross_grover);
        assert!(m.full_degree_log2 > m.grover_preimage_bits, "full rounds beat the Grover line");
    }
}
