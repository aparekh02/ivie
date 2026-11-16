//! Fiat-Shamir channel, modeled on StarkWare's VerifierChannel.sol.
//!
//! ```text
//!   digest_0       = keccak(public input)                 counter = 0
//!   mix(x)         : digest = keccak((digest + 1) ‖ x)    counter = 0
//!   random bytes   : keccak(digest ‖ u256 counter), counter += 1
//!   field element  : rejection-sample random bytes below 31·p, reduce mod p
//!   queries        : four 64-bit words per random hash, & (N - 1), then sorted + deduped
//!   proof of work  : h = keccak(0x0123456789abcded ‖ digest ‖ u8 bits)
//!                    keccak(h ‖ u64 nonce) < 2^(256 - bits); then mix(u64 nonce)
//! ```

use super::field::{F, P, be32};
use alloy_primitives::{B256, U256, keccak256};
use ark_ff::PrimeField;

/// Largest multiple of p below 2^256.
pub const BOUND: U256 = P.wrapping_mul(U256::from_limbs([31, 0, 0, 0]));
pub const POW_PREFIX: [u8; 8] = 0x0123456789abcdedu64.to_be_bytes();

#[derive(Clone, Debug)]
pub struct Channel {
    pub digest: B256,
    pub counter: u64,
}

impl Channel {
    pub fn new(public_input: &[u8]) -> Self {
        Channel { digest: keccak256(public_input), counter: 0 }
    }

    pub fn mix(&mut self, x: &[u8]) {
        let mut b = (U256::from_be_bytes(self.digest.0).wrapping_add(U256::from(1))).to_be_bytes::<32>().to_vec();
        b.extend_from_slice(x);
        self.digest = keccak256(b);
        self.counter = 0;
    }

    pub fn mix_field(&mut self, xs: &[F]) {
        self.mix(&xs.iter().flat_map(be32).collect::<Vec<u8>>());
    }

    fn random(&mut self) -> U256 {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(self.digest.as_slice());
        b[56..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        U256::from_be_bytes(keccak256(b).0)
    }

    pub fn field(&mut self) -> F {
        loop {
            let r = self.random();
            if r < BOUND {
                return F::from_be_bytes_mod_order(&(r % P).to_be_bytes::<32>());
            }
        }
    }

    /// `q` positions in [0, n), sorted and deduplicated.
    pub fn queries(&mut self, q: usize, n: usize) -> Vec<usize> {
        let mut out = Vec::with_capacity(q);
        while out.len() < q {
            let r = self.random().to_be_bytes::<32>();
            for w in r.chunks(8) {
                if out.len() < q {
                    out.push((u64::from_be_bytes(w.try_into().unwrap()) as usize) & (n - 1));
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    pub fn pow_seed(&self, bits: u8) -> B256 {
        let mut b = POW_PREFIX.to_vec();
        b.extend_from_slice(self.digest.as_slice());
        b.push(bits);
        keccak256(b)
    }
}

/// Smallest nonce passing the proof of work, searched in parallel blocks.
pub fn grind(seed: &B256, bits: u8) -> u64 {
    use rayon::prelude::*;
    const BLOCK: u64 = 1 << 18;
    (0..).find_map(|b: u64| (b * BLOCK..(b + 1) * BLOCK).into_par_iter().find_first(|n| pow_ok(seed, *n, bits))).unwrap()
}

pub fn pow_ok(seed: &B256, nonce: u64, bits: u8) -> bool {
    let mut b = [0u8; 40];
    b[..32].copy_from_slice(seed.as_slice());
    b[32..].copy_from_slice(&nonce.to_be_bytes());
    U256::from_be_bytes(keccak256(b).0).leading_zeros() >= bits as usize
}

/// The public input the channel is seeded with:
/// `"zknet.stark.v2" ‖ u8 logT ‖ prevRoot ‖ newRoot ‖ keccak(txs)`.
pub fn public_input(log_t: u32, prev: &B256, new: &B256, txs: &[u8]) -> Vec<u8> {
    let mut b = b"zknet.stark.v2".to_vec();
    b.push(log_t as u8);
    b.extend_from_slice(prev.as_slice());
    b.extend_from_slice(new.as_slice());
    b.extend_from_slice(keccak256(txs).as_slice());
    b
}
