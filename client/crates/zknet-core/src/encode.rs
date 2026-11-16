//! On-chain byte layouts. These must match `tools/zk.mjs` and the Solidity
//! libraries exactly.
//!
//! ```text
//! BN254  proof (256 B):  A.x A.y | B.x_im B.x_re B.y_im B.y_re | C.x C.y      (EIP-197)
//!        vk:             alpha | beta | gamma | delta | IC[0..n]              (32-byte words)
//! BLS    proof (512 B):  A (128) | B = x.c0 x.c1 y.c0 y.c1 (256) | C (128)     (EIP-2537)
//!        vk:             alpha 128 | beta 256 | gamma 256 | delta 256 | IC 128 each
//! ```
//! The point at infinity is encoded as all zeros.

use crate::snarkjs::{SnarkjsProof, SnarkjsVk};
use alloy_primitives::{B256, U256, keccak256};
use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Curve {
    Bn254,
    Bls12381,
}

impl Curve {
    /// `ZKVerifierRegistry.Curve` enum value.
    pub fn id(self) -> u8 {
        match self {
            Curve::Bn254 => 0,
            Curve::Bls12381 => 1,
        }
    }
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Curve::Bn254),
            1 => Some(Curve::Bls12381),
            _ => None,
        }
    }
    /// Accepts snarkjs names (`bn128`, `bls12381`) and the usual aliases.
    pub fn parse(s: &str) -> Result<Self, EncodeError> {
        let n: String = s.to_ascii_lowercase().chars().filter(|c| *c != '-' && *c != '_').collect();
        match n.as_str() {
            "bn128" | "bn254" | "altbn128" => Ok(Curve::Bn254),
            "bls12381" => Ok(Curve::Bls12381),
            _ => Err(EncodeError::UnknownCurve(s.to_string())),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Curve::Bn254 => "bn254",
            Curve::Bls12381 => "bls12381",
        }
    }
    /// What snarkjs writes in the `curve` field.
    pub fn snarkjs_name(self) -> &'static str {
        match self {
            Curve::Bn254 => "bn128",
            Curve::Bls12381 => "bls12381",
        }
    }
    /// Width of one base-field element on the wire (EIP-197: 32, EIP-2537: 64).
    pub fn fp_bytes(self) -> usize {
        match self {
            Curve::Bn254 => 32,
            Curve::Bls12381 => 64,
        }
    }
    pub fn g1_bytes(self) -> usize {
        2 * self.fp_bytes()
    }
    pub fn g2_bytes(self) -> usize {
        4 * self.fp_bytes()
    }
    pub fn proof_bytes(self) -> usize {
        8 * self.fp_bytes()
    }
    pub fn vk_bytes(self, n_public: usize) -> usize {
        self.g1_bytes() + 3 * self.g2_bytes() + (n_public + 1) * self.g1_bytes()
    }
    /// Inverse of [`Curve::vk_bytes`]; `None` if the length is not a valid VK length.
    pub fn n_public_for_vk_len(self, len: usize) -> Option<usize> {
        let header = self.g1_bytes() + 3 * self.g2_bytes();
        if len < header + self.g1_bytes() || !(len - header).is_multiple_of(self.g1_bytes()) {
            return None;
        }
        Some((len - header) / self.g1_bytes() - 1)
    }
}

impl std::fmt::Display for Curve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl Serialize for Curve {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

impl<'de> Deserialize<'de> for Curve {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = serde_json::Value::deserialize(d)?;
        match &v {
            serde_json::Value::String(s) => Curve::parse(s).map_err(serde::de::Error::custom),
            serde_json::Value::Number(n) => n
                .as_u64()
                .and_then(|i| Curve::from_id(i as u8))
                .ok_or_else(|| serde::de::Error::custom(format!("unknown curve id {n}"))),
            _ => Err(serde::de::Error::custom("curve must be a string or 0/1")),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EncodeError {
    #[error("unsupported curve {0}")]
    UnknownCurve(String),
    #[error("bad number {0:?}")]
    BadNumber(String),
    #[error("value {0} does not fit in {1} bytes")]
    TooLarge(String, usize),
    #[error("malformed point: {0}")]
    Shape(&'static str),
    #[error("expected {expected} bytes, got {got}")]
    Length { expected: usize, got: usize },
}

/// Decimal or `0x` hex string -> big integer.
pub fn parse_big(s: &str) -> Result<BigUint, EncodeError> {
    let t = s.trim();
    let r = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some("") => Some(BigUint::default()),
        Some(h) => BigUint::parse_bytes(h.as_bytes(), 16),
        None => BigUint::parse_bytes(t.as_bytes(), 10),
    };
    r.ok_or_else(|| EncodeError::BadNumber(s.to_string()))
}

/// Decimal or `0x` hex string -> U256 (public inputs, which are uint256 on chain).
pub fn parse_u256(s: &str) -> Result<U256, EncodeError> {
    let b = parse_big(s)?;
    let bytes = b.to_bytes_be();
    if bytes.len() > 32 {
        return Err(EncodeError::TooLarge(s.to_string(), 32));
    }
    Ok(U256::from_be_slice(&bytes))
}

fn put(out: &mut Vec<u8>, s: &str, width: usize) -> Result<(), EncodeError> {
    let b = parse_big(s)?.to_bytes_be();
    let b: &[u8] = if b == [0] { &[] } else { &b };
    if b.len() > width {
        return Err(EncodeError::TooLarge(s.to_string(), width));
    }
    out.extend(std::iter::repeat_n(0u8, width - b.len()));
    out.extend_from_slice(b);
    Ok(())
}

fn is_zero(s: &str) -> Result<bool, EncodeError> {
    Ok(parse_big(s)? == BigUint::default())
}

fn enc_g1(c: Curve, out: &mut Vec<u8>, j: &[String]) -> Result<(), EncodeError> {
    if j.len() < 2 {
        return Err(EncodeError::Shape("G1 needs [x, y, z?]"));
    }
    let w = c.fp_bytes();
    if j.get(2).map(|z| is_zero(z)).transpose()?.unwrap_or(false) {
        out.extend(std::iter::repeat_n(0u8, 2 * w));
        return Ok(());
    }
    put(out, &j[0], w)?;
    put(out, &j[1], w)
}

fn enc_g2(c: Curve, out: &mut Vec<u8>, j: &[Vec<String>]) -> Result<(), EncodeError> {
    if j.len() < 2 || j[0].len() != 2 || j[1].len() != 2 {
        return Err(EncodeError::Shape("G2 needs [[x0, x1], [y0, y1], z?]"));
    }
    let w = c.fp_bytes();
    if let Some(z) = j.get(2)
        && z.len() == 2 && is_zero(&z[0])? && is_zero(&z[1])? {
            out.extend(std::iter::repeat_n(0u8, 4 * w));
            return Ok(());
        }
    let (x, y) = (&j[0], &j[1]);
    match c {
        // EIP-197: imaginary part first
        Curve::Bn254 => {
            for s in [&x[1], &x[0], &y[1], &y[0]] {
                put(out, s, w)?;
            }
        }
        // EIP-2537: real part first
        Curve::Bls12381 => {
            for s in [&x[0], &x[1], &y[0], &y[1]] {
                put(out, s, w)?;
            }
        }
    }
    Ok(())
}

/// snarkjs VK -> raw (unprepared) VK bytes, as `register` expects.
pub fn encode_vk(vk: &SnarkjsVk) -> Result<(Curve, Vec<u8>), EncodeError> {
    let c = Curve::parse(&vk.curve)?;
    let mut out = Vec::with_capacity(c.vk_bytes(vk.ic.len().saturating_sub(1)));
    enc_g1(c, &mut out, &vk.vk_alpha_1)?;
    enc_g2(c, &mut out, &vk.vk_beta_2)?;
    enc_g2(c, &mut out, &vk.vk_gamma_2)?;
    enc_g2(c, &mut out, &vk.vk_delta_2)?;
    for p in &vk.ic {
        enc_g1(c, &mut out, p)?;
    }
    Ok((c, out))
}

/// snarkjs proof -> proof bytes for `verify` / `submit`.
pub fn encode_proof(proof: &SnarkjsProof, curve: Curve) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::with_capacity(curve.proof_bytes());
    enc_g1(curve, &mut out, &proof.pi_a)?;
    enc_g2(curve, &mut out, &proof.pi_b)?;
    enc_g1(curve, &mut out, &proof.pi_c)?;
    Ok(out)
}

/// Proof bytes -> snarkjs JSON (the inverse of [`encode_proof`]).
pub fn decode_proof(bytes: &[u8], curve: Curve) -> Result<SnarkjsProof, EncodeError> {
    if bytes.len() != curve.proof_bytes() {
        return Err(EncodeError::Length { expected: curve.proof_bytes(), got: bytes.len() });
    }
    let w = curve.fp_bytes();
    let f = |i: usize| BigUint::from_bytes_be(&bytes[i * w..(i + 1) * w]).to_string();
    let zero = |r: std::ops::Range<usize>| r.into_iter().all(|i| f(i) == "0");
    let g1 = |o: usize| if zero(o..o + 2) { vec!["0".into(), "1".into(), "0".into()] } else { vec![f(o), f(o + 1), "1".into()] };
    let pi_b = if zero(2..6) {
        vec![vec!["0".into(), "0".into()], vec!["1".into(), "0".into()], vec!["0".into(), "0".into()]]
    } else {
        let (x, y) = match curve {
            Curve::Bn254 => (vec![f(3), f(2)], vec![f(5), f(4)]),
            Curve::Bls12381 => (vec![f(2), f(3)], vec![f(4), f(5)]),
        };
        vec![x, y, vec!["1".into(), "0".into()]]
    };
    Ok(SnarkjsProof {
        pi_a: g1(0),
        pi_b,
        pi_c: g1(6),
        protocol: Some("groth16".into()),
        curve: Some(curve.snarkjs_name().into()),
    })
}

/// The registry's content address: `keccak256(abi.encode(uint8 curve, bytes rawVk))`.
pub fn circuit_id(curve: Curve, raw_vk: &[u8]) -> B256 {
    let mut buf = Vec::with_capacity(96 + raw_vk.len().div_ceil(32) * 32);
    buf.extend_from_slice(&U256::from(curve.id()).to_be_bytes::<32>());
    buf.extend_from_slice(&U256::from(64).to_be_bytes::<32>());
    buf.extend_from_slice(&U256::from(raw_vk.len()).to_be_bytes::<32>());
    buf.extend_from_slice(raw_vk);
    buf.resize(96 + raw_vk.len().div_ceil(32) * 32, 0);
    keccak256(buf)
}

/// `keccak256(abi.encodePacked(inputs))`, the registry's replay key.
pub fn inputs_hash(inputs: &[U256]) -> B256 {
    let mut buf = Vec::with_capacity(32 * inputs.len());
    for x in inputs {
        buf.extend_from_slice(&x.to_be_bytes::<32>());
    }
    keccak256(buf)
}
