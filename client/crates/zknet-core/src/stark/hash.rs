//! The in-AIR hash: a width-3 Poseidon-style permutation with x^3 S-boxes,
//! ROUNDS full rounds, and Starknet's t=3 MDS matrix
//!
//! ```text
//!   round r:  s_j += C[r][j];   s_j = s_j^3;   s = M·s
//!   M = [[3, 1, 1], [1, -1, 1], [1, 1, -2]]
//! ```
//!
//! Round constants are nothing-up-my-sleeve: `keccak256("zknet.poseidon.v1" ‖ r ‖ j) mod p`.
//! With 127 full rounds the algebraic degree is 3^127 ≈ 2^201. This is a
//! research parameter set, NOT audited Poseidon. One round is one trace row,
//! so a permutation is one 128-row cycle (127 rounds and one I/O row).
//!
//!   leaf(balance) = P(balance, 0, 1)[0]
//!   node(l, r)    = P(l, r, 2)[0]
//! The third element is a domain tag (capacity).

use super::field::F;
use alloy_primitives::keccak256;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use std::sync::OnceLock;

pub const ROUNDS: usize = 127;
pub const TAG_LEAF: u64 = 1;
pub const TAG_NODE: u64 = 2;

pub fn constants() -> &'static [[F; 3]; ROUNDS] {
    static C: OnceLock<[[F; 3]; ROUNDS]> = OnceLock::new();
    C.get_or_init(|| {
        let mut c = [[F::from(0u64); 3]; ROUNDS];
        for (r, row) in c.iter_mut().enumerate() {
            for (j, x) in row.iter_mut().enumerate() {
                let mut pre = b"zknet.poseidon.v1".to_vec();
                pre.push(r as u8);
                pre.push(j as u8);
                *x = F::from_be_bytes_mod_order(keccak256(&pre).as_slice());
            }
        }
        c
    })
}

#[inline]
pub fn mds(t: [F; 3]) -> [F; 3] {
    let s = t[0] + t[1] + t[2];
    // [3,1,1]·t = s + 2 t0 ; [1,-1,1]·t = s - 2 t1 ; [1,1,-2]·t = s - 3 t2
    [s + t[0].double(), s - t[1].double(), s - t[2].double() - t[2]]
}

#[inline]
pub fn round(s: [F; 3], c: &[F; 3]) -> [F; 3] {
    let cube = |x: F| x * x.square();
    mds([cube(s[0] + c[0]), cube(s[1] + c[1]), cube(s[2] + c[2])])
}

/// All ROUNDS+1 states: `out[0]` = input, `out[r+1] = round_r(out[r])`.
pub fn trace(input: [F; 3]) -> Vec<[F; 3]> {
    let c = constants();
    let mut v = Vec::with_capacity(ROUNDS + 1);
    v.push(input);
    for cr in c.iter() {
        let s = round(*v.last().unwrap(), cr);
        v.push(s);
    }
    v
}

pub fn permute(input: [F; 3]) -> [F; 3] {
    let c = constants();
    c.iter().fold(input, round)
}

pub fn leaf(balance: F) -> F {
    permute([balance, F::from(0u64), F::from(TAG_LEAF)])[0]
}

pub fn node(l: F, r: F) -> F {
    permute([l, r, F::from(TAG_NODE)])[0]
}
