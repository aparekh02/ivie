//! Merkle commitments, StarkWare-style:
//!
//! * hashes are keccak256 truncated to their high 160 bits
//!   (`COMMITMENT_MASK` in StarkWare's MerkleVerifier.sol), which is enough
//!   for collision resistance at the conjectured security level and saves gas
//! * leaves are `keccak256(row bytes) & MASK`; nodes are `keccak256(l ‖ r) & MASK`
//! * openings are batched: all queried leaves of one tree are verified together,
//!   and the proof carries each needed sibling once ("multi-proof"), in the
//!   order a bottom-up queue consumes them.

use alloy_primitives::{B256, keccak256};
use rayon::prelude::*;

/// High 160 bits.
pub const MASK: B256 = B256::new([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

pub fn masked(h: B256) -> B256 {
    h & MASK
}

pub fn leaf(data: &[u8]) -> B256 {
    masked(keccak256(data))
}

pub fn hash2(l: &B256, r: &B256) -> B256 {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(l.as_slice());
    b[32..].copy_from_slice(r.as_slice());
    masked(keccak256(b))
}

pub struct Tree {
    /// layers[0] = leaf hashes, last = [root]
    layers: Vec<Vec<B256>>,
}

impl Tree {
    pub fn new(leaves: Vec<B256>) -> Self {
        assert!(leaves.len().is_power_of_two());
        let mut layers = vec![leaves];
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let next: Vec<B256> = prev.par_chunks(2).map(|p| hash2(&p[0], &p[1])).collect();
            layers.push(next);
        }
        Tree { layers }
    }

    pub fn root(&self) -> B256 {
        self.layers.last().unwrap()[0]
    }

    pub fn depth(&self) -> usize {
        self.layers.len() - 1
    }

    /// Batched decommitment for sorted, unique leaf indices.
    pub fn multiproof(&self, idx: &[usize]) -> Vec<B256> {
        let mut out = vec![];
        let mut cur: Vec<usize> = idx.to_vec();
        for level in &self.layers[..self.depth()] {
            let mut next = Vec::with_capacity(cur.len());
            let mut i = 0;
            while i < cur.len() {
                let k = cur[i];
                if k & 1 == 0 && i + 1 < cur.len() && cur[i + 1] == k + 1 {
                    i += 2;
                } else {
                    out.push(level[k ^ 1]);
                    i += 1;
                }
                next.push(k >> 1);
            }
            cur = next;
        }
        out
    }
}

/// Verifies leaves (sorted by unique index) against `root` with a
/// multi-proof `stream` for a tree of the given depth. The whole stream must be
/// consumed. Same algorithm as `_merkleMulti` in StarkVerifier.sol.
pub fn verify_multi(root: &B256, depth: usize, leaves: &[(usize, B256)], stream: &[B256]) -> bool {
    let mut cur: Vec<(usize, B256)> = leaves.to_vec();
    let mut s = 0;
    for _ in 0..depth {
        let mut next = Vec::with_capacity(cur.len());
        let mut i = 0;
        while i < cur.len() {
            let (k, h) = cur[i];
            if k >> depth != 0 {
                return false;
            }
            let sib = if k & 1 == 0 && i + 1 < cur.len() && cur[i + 1].0 == k + 1 {
                i += 2;
                cur[i - 1].1
            } else {
                let Some(x) = stream.get(s) else { return false };
                s += 1;
                i += 1;
                *x
            };
            next.push((k >> 1, if k & 1 == 0 { hash2(&h, &sib) } else { hash2(&sib, &h) }));
        }
        cur = next;
    }
    s == stream.len() && cur.len() == 1 && cur[0] == (0, *root)
}
