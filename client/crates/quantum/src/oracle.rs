//! The STARK verifier's security floors, as Grover oracles over one integer.
//!
//! Each oracle is a boolean predicate `f(x) -> bool` on a candidate integer `x`
//! (a nonce, or a leaf preimage). Grover searches for an `x` with `f(x) = true`.
//! The predicates use the same keccak primitive as the real verifier, only with
//! the search parameters shrunk so a statevector simulation fits in memory. The
//! measured exponent is what extrapolates to full scale.
//!
//! Two floors, matching the wedges found in the AIR / verifier review:
//!
//! * [`MerklePreimage`] — "inject a point." The Merkle commitment binds the
//!   opened values to a root fixed before `z`. Its hashes are keccak truncated
//!   to 160 bits (`merkle.rs`: `MASK`). Finding a second preimage of a
//!   committed slot lets a forged value carry a valid path, breaking the
//!   commit-before-`z` property. Cost = `2^(bits/2)` under Grover.
//!
//! * [`Grind`] — the Fiat-Shamir query lottery. A forged proof agrees with a
//!   true codeword on a fraction `rho` of positions. The prover grinds a nonce
//!   (`channel.rs`: proof-of-work then query derivation) until the `Q` drawn
//!   positions all land on agreeing positions and the PoW passes. Marked
//!   density = `2^-pow · rho^Q`. Cost = `2^((pow + Q·log2(1/rho))/2)` under Grover.

use alloy_primitives::{B256, U256, keccak256};

/// High `bits` bits of a 256-bit hash as an integer (`bits <= 64`). This mirrors
/// `merkle::masked`, which keeps the high 160 bits; here the width is a knob.
pub fn trunc(h: B256, bits: u32) -> u64 {
    debug_assert!(bits <= 64);
    (U256::from_be_bytes(h.0) >> (256 - bits as usize)).to::<u64>()
}

fn keccak_u64(x: u64) -> B256 {
    keccak256(x.to_be_bytes())
}

// -------------------------------------------------------------- Merkle floor

/// Second-preimage search against one Merkle leaf hash truncated to `bits`.
///
/// `target` is the committed leaf hash (set to the truncation of a real value's
/// hash, so at least one preimage exists). Grover looks for an `x` whose leaf
/// hash matches — a value it can open at a queried position with a path that
/// still reaches the committed root. Expected marked count over a space of
/// `2^n` is `2^(n-bits)`, so the iteration count is `~2^(bits/2)` regardless of
/// `n` (as long as `n >= bits`): the quantum second-preimage exponent.
pub struct MerklePreimage {
    pub bits: u32,
    pub target: u64,
}

impl MerklePreimage {
    /// Picks `target` as the truncation of a real committed value's hash.
    pub fn new(bits: u32, committed_value: u64) -> Self {
        MerklePreimage { bits, target: trunc(keccak_u64(committed_value), bits) }
    }

    pub fn marks(&self, x: u64) -> bool {
        trunc(keccak_u64(x), self.bits) == self.target
    }

    /// Predicted Grover exponent (log2 of the oracle-call count): `bits/2`.
    pub fn predicted_bits(&self) -> f64 {
        self.bits as f64 / 2.0
    }
}

// --------------------------------------------------------- Fiat-Shamir floor

/// The grinding / query-avoidance search over a nonce.
///
/// A position in `[0, 2^domain_log)` is "good" (where the forged codeword
/// happens to agree) with probability `~rho = good_num / good_den`, fixed by a
/// keccak predicate. The oracle marks a nonce when its proof-of-work has
/// `pow_bits` leading zeros AND all `queries` derived positions are good.
pub struct Grind {
    pub seed: B256,
    pub pow_bits: u32,
    pub queries: usize,
    pub domain_log: u32,
    pub good_num: u64,
    pub good_den: u64,
}

impl Grind {
    pub fn new(pow_bits: u32, queries: usize, domain_log: u32, good_num: u64, good_den: u64) -> Self {
        Grind { seed: keccak256(b"zknet.quantum.grind"), pow_bits, queries, domain_log, good_num, good_den }
    }

    /// Mirrors `channel::pow_ok`: the hash of (seed, nonce) must have `pow_bits`
    /// leading zero bits.
    fn pow_ok(&self, nonce: u64) -> bool {
        let mut b = [0u8; 40];
        b[..32].copy_from_slice(self.seed.as_slice());
        b[32..].copy_from_slice(&nonce.to_be_bytes());
        (U256::from_be_bytes(keccak256(b).0).leading_zeros() as u32) >= self.pow_bits
    }

    /// A position is good with probability `good_num / good_den` (a fixed
    /// keccak predicate, standing in for "the forged codeword agrees here").
    fn good(&self, pos: u64) -> bool {
        let h = trunc(keccak256([b"pos".as_slice(), &pos.to_be_bytes()].concat()), 32);
        h % self.good_den < self.good_num
    }

    /// Mirrors `channel::queries`: derive `queries` positions from (seed, nonce).
    fn positions_good(&self, nonce: u64) -> bool {
        let mask = (1u64 << self.domain_log) - 1;
        (0..self.queries).all(|q| {
            let mut b = [0u8; 48];
            b[..32].copy_from_slice(self.seed.as_slice());
            b[32..40].copy_from_slice(&nonce.to_be_bytes());
            b[40..].copy_from_slice(&(q as u64).to_be_bytes());
            self.good(trunc(keccak256(b), 32) & mask)
        })
    }

    pub fn marks(&self, nonce: u64) -> bool {
        self.pow_ok(nonce) && self.positions_good(nonce)
    }

    /// Density of marked nonces: `2^-pow · rho^queries`.
    pub fn log2_density(&self) -> f64 {
        let rho = self.good_num as f64 / self.good_den as f64;
        -(self.pow_bits as f64) + self.queries as f64 * rho.log2()
    }

    /// Predicted Grover exponent: half the search depth `-log2(density)`.
    pub fn predicted_bits(&self) -> f64 {
        -self.log2_density() / 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_target_has_a_preimage() {
        let o = MerklePreimage::new(12, 42);
        assert!(o.marks(42), "the committed value is itself a preimage");
    }

    #[test]
    fn grind_density_matches_params() {
        let g = Grind::new(4, 3, 6, 1, 2); // pow 4, 3 queries, rho = 1/2
        assert!((g.log2_density() - (-7.0)).abs() < 1e-9);
        assert!((g.predicted_bits() - 3.5).abs() < 1e-9);
    }
}
