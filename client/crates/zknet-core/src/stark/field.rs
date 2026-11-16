//! The STARK field: p = 2^251 + 17·2^192 + 1 (StarkWare's field, used by
//! Starknet's L1 verifier). The multiplicative group has two-adicity 192 and
//! generator 3, so FFT domains of any practical size exist. Elements fit in one
//! EVM word, so Solidity uses `mulmod`/`addmod` with no extension field.

#![allow(unexpected_cfgs)] // ark-ff's MontConfig derive checks cfg(asm)

use alloy_primitives::{B256, U256};
use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use ark_ff::{BigInteger, Field, PrimeField};

#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[generator = "3"]
pub struct FConfig;

pub type F = Fp256<MontBackend<FConfig, 4>>;

/// p as a U256 (matches `P` in the Solidity verifier).
pub const P: U256 = U256::from_limbs([1, 0, 0, 0x0800_0000_0000_0011]);

/// Coset offset of every LDE / FRI domain (the group generator).
pub fn offset() -> F {
    F::from(3u64)
}

pub fn be32(x: &F) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_be());
    out
}

pub fn to_u256(x: &F) -> U256 {
    U256::from_be_bytes(be32(x))
}

pub fn to_b256(x: &F) -> B256 {
    B256::from(be32(x))
}

/// `None` unless `x < p` (the verifier rejects non-canonical encodings).
pub fn from_u256(x: U256) -> Option<F> {
    (x < P).then(|| F::from_be_bytes_mod_order(&x.to_be_bytes::<32>()))
}

pub fn from_b256(x: B256) -> Option<F> {
    from_u256(U256::from_be_bytes(x.0))
}

/// Primitive n-th root of unity, n a power of two: 3^((p-1)/n).
pub fn root(n: usize) -> F {
    assert!(n.is_power_of_two());
    let e = (P - U256::from(1)) / U256::from(n);
    F::from(3u64).pow(e.as_limbs())
}

pub fn pow(x: F, e: u64) -> F {
    x.pow([e])
}

/// -1 in the field.
pub fn neg_one() -> F {
    -F::from(1u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

    #[test]
    fn modulus_and_roots() {
        assert_eq!(U256::from_be_bytes(be32(&neg_one())) + U256::from(1), P);
        for log in [1, 7, 11, 16, 20] {
            let n = 1usize << log;
            let d = Radix2EvaluationDomain::<F>::new(n).unwrap();
            assert_eq!(d.group_gen(), root(n), "arkworks root for 2^{log}");
            assert_eq!(pow(root(n), n as u64 / 2), neg_one());
        }
        // x -> x^3 is a permutation iff gcd(3, p-1) = 1
        assert_eq!((P - U256::from(1)) % U256::from(3), U256::from(1));
    }
}
