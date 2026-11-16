//! Native Groth16 verifier that follows the on-chain rules.
//!
//! It works on the same bytes the contract receives, so a disagreement
//! between this verifier and `eth_call verify` means one of them has a bug.
//! It rejects what the precompiles reject: coordinates `>= p` (never reduced),
//! off-curve points, points outside the order-r subgroup (G2, and G1 on
//! BLS12-381), public inputs `>= r`, and VKs that `prepare()` refuses
//! (identity alpha/beta/gamma/delta, gamma == delta).
//!
//! Check:  e(A, B) · e(alpha, -beta) · e(vk_x, -gamma) · e(C, -delta) == 1
//! where vk_x = IC[0] + Σ input_i · IC[i+1].

use crate::encode::Curve;
use alloy_primitives::U256;
use serde::{Deserialize, Serialize};

/// Why a proof or VK was rejected. [`Reject::reverts_on_chain`] says whether
/// the contract reverts here (malformed lengths) or returns `false`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Reject {
    #[error("BadVKLength")]
    BadVkLength,
    #[error("BadProofLength (expected {expected} bytes, got {got})")]
    BadProofLength { expected: usize, got: usize },
    #[error("InputCountMismatch (expected {expected}, got {got})")]
    InputCountMismatch { expected: usize, got: usize },
    #[error("InvalidVK: {why}")]
    InvalidVk { why: String },
    #[error("public input {index} is >= r")]
    InputNotInField { index: usize },
    #[error("{point}: coordinate >= p (non-canonical)")]
    NonCanonical { point: &'static str },
    #[error("{point}: not on curve")]
    NotOnCurve { point: &'static str },
    #[error("{point}: not in the prime-order subgroup")]
    NotInSubgroup { point: &'static str },
    #[error("pairing check failed")]
    Pairing,
}

impl Reject {
    /// `true` when `ZKVerifierRegistry.verify` reverts on this input instead of returning `false`.
    pub fn reverts_on_chain(&self) -> bool {
        matches!(self, Reject::BadVkLength | Reject::BadProofLength { .. } | Reject::InputCountMismatch { .. })
    }
}

/// Verify `proof` for `inputs` against a RAW (unprepared) VK, as passed to `register`.
pub fn verify(curve: Curve, raw_vk: &[u8], proof: &[u8], inputs: &[U256]) -> Result<(), Reject> {
    match curve {
        Curve::Bn254 => bn254::verify(raw_vk, proof, inputs),
        Curve::Bls12381 => bls12381::verify(raw_vk, proof, inputs),
    }
}

/// Run the checks `register` runs (via `prepare`). Returns nPublic.
pub fn check_vk(curve: Curve, raw_vk: &[u8]) -> Result<usize, Reject> {
    match curve {
        Curve::Bn254 => bn254::Vk::parse(raw_vk).map(|v| v.ic.len() - 1),
        Curve::Bls12381 => bls12381::Vk::parse(raw_vk).map(|v| v.ic.len() - 1),
    }
}

/// The registry stores VKs PREPARED (beta, gamma, delta negated); `vkOf`
/// returns that form. Negating again gives the raw VK (and its circuit id).
pub fn unprepare_vk(curve: Curve, prepared: &[u8]) -> Result<Vec<u8>, Reject> {
    match curve {
        Curve::Bn254 => bn254::negate_g2s(prepared),
        Curve::Bls12381 => bls12381::negate_g2s(prepared),
    }
}

/// Re-randomize a valid proof: (A/s, s·B, C) satisfies the same equation.
/// Useful to see that proof bytes are not unique per statement (which is
/// why the registry dedupes on the inputs, not on the proof).
pub fn rerandomize(curve: Curve, proof: &[u8], seed: u64) -> Result<Vec<u8>, Reject> {
    match curve {
        Curve::Bn254 => bn254::rerandomize(proof, seed),
        Curve::Bls12381 => bls12381::rerandomize(proof, seed),
    }
}

macro_rules! curve_impl {
    ($m:ident, $ark:ident, $Engine:ident, $FP:expr, $imag_first:expr) => {
        /// Arkworks-level helpers for this curve. Use these to turn your
        /// prover's affine points into the on-chain encoding.
        pub mod $m {
            use super::Reject;
            use alloy_primitives::U256;
            use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
            use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
            pub use $ark::{$Engine as Engine, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};

            /// Wire width of one Fp element.
            pub const FP: usize = $FP;
            pub const G1: usize = 2 * FP;
            pub const G2: usize = 4 * FP;
            pub const PROOF: usize = 2 * G1 + G2;
            const HEADER: usize = G1 + 3 * G2;

            fn fq(b: &[u8], point: &'static str) -> Result<Fq, Reject> {
                let n = (Fq::MODULUS_BIT_SIZE as usize).div_ceil(64) * 8;
                let (pad, body) = b.split_at(FP - n);
                let v = Fq::from_be_bytes_mod_order(body);
                if pad.iter().any(|&x| x != 0) || v.into_bigint().to_bytes_be() != body {
                    return Err(Reject::NonCanonical { point });
                }
                Ok(v)
            }

            fn put_fq(out: &mut Vec<u8>, v: &Fq) {
                let b = v.into_bigint().to_bytes_be();
                out.extend(std::iter::repeat_n(0u8, FP - b.len()));
                out.extend_from_slice(&b);
            }

            /// Wire bytes -> G1 point, with the precompile's checks.
            pub fn decode_g1(b: &[u8], point: &'static str) -> Result<G1Affine, Reject> {
                debug_assert_eq!(b.len(), G1);
                if b.iter().all(|&x| x == 0) {
                    return Ok(G1Affine::zero());
                }
                let p = G1Affine::new_unchecked(fq(&b[..FP], point)?, fq(&b[FP..], point)?);
                if !p.is_on_curve() {
                    return Err(Reject::NotOnCurve { point });
                }
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(Reject::NotInSubgroup { point });
                }
                Ok(p)
            }

            /// Wire bytes -> G2 point, with the precompile's checks.
            pub fn decode_g2(b: &[u8], point: &'static str) -> Result<G2Affine, Reject> {
                debug_assert_eq!(b.len(), G2);
                if b.iter().all(|&x| x == 0) {
                    return Ok(G2Affine::zero());
                }
                let f: Vec<Fq> = (0..4).map(|i| fq(&b[i * FP..(i + 1) * FP], point)).collect::<Result<_, _>>()?;
                let (x, y) = if $imag_first {
                    (Fq2::new(f[1], f[0]), Fq2::new(f[3], f[2]))
                } else {
                    (Fq2::new(f[0], f[1]), Fq2::new(f[2], f[3]))
                };
                let p = G2Affine::new_unchecked(x, y);
                if !p.is_on_curve() {
                    return Err(Reject::NotOnCurve { point });
                }
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(Reject::NotInSubgroup { point });
                }
                Ok(p)
            }

            pub fn encode_g1(p: &G1Affine) -> Vec<u8> {
                let mut out = Vec::with_capacity(G1);
                match p.xy() {
                    None => out.resize(G1, 0),
                    Some((x, y)) => {
                        put_fq(&mut out, &x);
                        put_fq(&mut out, &y);
                    }
                }
                out
            }

            pub fn encode_g2(p: &G2Affine) -> Vec<u8> {
                let mut out = Vec::with_capacity(G2);
                match p.xy() {
                    None => out.resize(G2, 0),
                    Some((x, y)) => {
                        let limbs = if $imag_first { [x.c1, x.c0, y.c1, y.c0] } else { [x.c0, x.c1, y.c0, y.c1] };
                        for l in &limbs {
                            put_fq(&mut out, l);
                        }
                    }
                }
                out
            }

            /// (A, B, C) -> proof bytes for `verify` / `submit`. With
            /// ark-groth16: `proof_bytes(&p.a, &p.b, &p.c)`.
            pub fn proof_bytes(a: &G1Affine, b: &G2Affine, c: &G1Affine) -> Vec<u8> {
                [encode_g1(a), encode_g2(b), encode_g1(c)].concat()
            }

            /// Raw VK bytes for `register`. With ark-groth16's
            /// `VerifyingKey`: `vk_bytes(&vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2, &vk.gamma_abc_g1)`.
            pub fn vk_bytes(alpha: &G1Affine, beta: &G2Affine, gamma: &G2Affine, delta: &G2Affine, ic: &[G1Affine]) -> Vec<u8> {
                let mut out = [encode_g1(alpha), encode_g2(beta), encode_g2(gamma), encode_g2(delta)].concat();
                for p in ic {
                    out.extend(encode_g1(p));
                }
                out
            }

            /// Public input -> scalar, rejecting values >= r (as the contract does).
            pub fn decode_input(x: &U256, index: usize) -> Result<Fr, Reject> {
                let b = x.to_be_bytes::<32>();
                let v = Fr::from_be_bytes_mod_order(&b);
                let back = v.into_bigint().to_bytes_be();
                if back[..] != b[32 - back.len()..] || b[..32 - back.len()].iter().any(|&z| z != 0) {
                    return Err(Reject::InputNotInField { index });
                }
                Ok(v)
            }

            /// A parsed, validated raw VK.
            #[derive(Clone, Debug)]
            pub struct Vk {
                pub alpha: G1Affine,
                pub beta: G2Affine,
                pub gamma: G2Affine,
                pub delta: G2Affine,
                pub ic: Vec<G1Affine>,
            }

            impl Vk {
                /// Same checks as `prepare()` in the Solidity library.
                pub fn parse(raw: &[u8]) -> Result<Self, Reject> {
                    if raw.len() < HEADER + G1 || (raw.len() - HEADER) % G1 != 0 {
                        return Err(Reject::BadVkLength);
                    }
                    let zero = |r: std::ops::Range<usize>| raw[r].iter().all(|&x| x == 0);
                    if zero(0..G1) {
                        return Err(Reject::InvalidVk { why: "alpha is identity".into() });
                    }
                    for g in 0..3 {
                        if zero(G1 + g * G2..G1 + (g + 1) * G2) {
                            return Err(Reject::InvalidVk { why: "G2 point is identity".into() });
                        }
                    }
                    if raw[G1 + G2..G1 + 2 * G2] == raw[G1 + 2 * G2..G1 + 3 * G2] {
                        return Err(Reject::InvalidVk { why: "gamma == delta".into() });
                    }
                    let bad = |_| Reject::InvalidVk { why: "point not on curve / not in subgroup / non-canonical".into() };
                    let n_ic = (raw.len() - HEADER) / G1;
                    Ok(Vk {
                        alpha: decode_g1(&raw[..G1], "vk.alpha").map_err(bad)?,
                        beta: decode_g2(&raw[G1..G1 + G2], "vk.beta").map_err(bad)?,
                        gamma: decode_g2(&raw[G1 + G2..G1 + 2 * G2], "vk.gamma").map_err(bad)?,
                        delta: decode_g2(&raw[G1 + 2 * G2..HEADER], "vk.delta").map_err(bad)?,
                        ic: (0..n_ic)
                            .map(|i| decode_g1(&raw[HEADER + i * G1..HEADER + (i + 1) * G1], "vk.IC").map_err(bad))
                            .collect::<Result<_, _>>()?,
                    })
                }

                pub fn n_public(&self) -> usize {
                    self.ic.len() - 1
                }

                /// Verify against this VK. Use this in hot loops to skip re-parsing.
                pub fn verify(&self, proof: &[u8], inputs: &[U256]) -> Result<(), Reject> {
                    if proof.len() != PROOF {
                        return Err(Reject::BadProofLength { expected: PROOF, got: proof.len() });
                    }
                    if inputs.len() != self.n_public() {
                        return Err(Reject::InputCountMismatch { expected: self.n_public(), got: inputs.len() });
                    }
                    let xs: Vec<Fr> = inputs.iter().enumerate().map(|(i, x)| decode_input(x, i)).collect::<Result<_, _>>()?;
                    let a = decode_g1(&proof[..G1], "proof.A")?;
                    let b = decode_g2(&proof[G1..G1 + G2], "proof.B")?;
                    let c = decode_g1(&proof[G1 + G2..], "proof.C")?;
                    let mut vk_x: G1Projective = self.ic[0].into_group();
                    for (x, p) in xs.iter().zip(&self.ic[1..]) {
                        vk_x += *p * x;
                    }
                    let out = Engine::multi_pairing(
                        [a, self.alpha, vk_x.into_affine(), c],
                        [b, -self.beta, -self.gamma, -self.delta],
                    );
                    if out.0.is_one() { Ok(()) } else { Err(Reject::Pairing) }
                }
            }

            pub fn verify(raw_vk: &[u8], proof: &[u8], inputs: &[U256]) -> Result<(), Reject> {
                Vk::parse(raw_vk)?.verify(proof, inputs)
            }

            pub(super) fn negate_g2s(vk: &[u8]) -> Result<Vec<u8>, Reject> {
                if vk.len() < HEADER + G1 || (vk.len() - HEADER) % G1 != 0 {
                    return Err(Reject::BadVkLength);
                }
                let mut out = vk.to_vec();
                for g in 0..3 {
                    let r = G1 + g * G2..G1 + (g + 1) * G2;
                    let p = decode_g2(&vk[r.clone()], "vk.G2")?;
                    out[r].copy_from_slice(&encode_g2(&-p));
                }
                Ok(out)
            }

            pub(super) fn rerandomize(proof: &[u8], seed: u64) -> Result<Vec<u8>, Reject> {
                if proof.len() != PROOF {
                    return Err(Reject::BadProofLength { expected: PROOF, got: proof.len() });
                }
                let a = decode_g1(&proof[..G1], "proof.A")?;
                let b = decode_g2(&proof[G1..G1 + G2], "proof.B")?;
                let s = Fr::from(seed.max(2));
                let s_inv = s.inverse().expect("s != 0");
                let a2 = (a * s_inv).into_affine();
                let b2 = (b * s).into_affine();
                Ok([encode_g1(&a2), encode_g2(&b2), proof[G1 + G2..].to_vec()].concat())
            }

            #[allow(dead_code)]
            fn _assert_traits() {
                let _ = Fq::zero();
            }
        }
    };
}

curve_impl!(bn254, ark_bn254, Bn254, 32, true);
curve_impl!(bls12381, ark_bls12_381, Bls12_381, 64, false);
