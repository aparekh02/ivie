//! snarkjs JSON shapes (`verification_key.json`, `proof.json`).
//!
//! G1 is `[x, y, z]` and G2 is `[[x.c0, x.c1], [y.c0, y.c1], [z.c0, z.c1]]`,
//! with decimal strings and Fp2 elements written `c0 + c1*u`. A `z` of 0 means
//! the point at infinity. Coordinates are kept as strings so that test inputs
//! that are deliberately non-canonical (for example `y + p`) survive.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnarkjsVk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    pub curve: String,
    #[serde(rename = "nPublic", default, skip_serializing_if = "Option::is_none")]
    pub n_public: Option<usize>,
    pub vk_alpha_1: Vec<String>,
    pub vk_beta_2: Vec<Vec<String>>,
    pub vk_gamma_2: Vec<Vec<String>>,
    pub vk_delta_2: Vec<Vec<String>>,
    #[serde(rename = "IC")]
    pub ic: Vec<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnarkjsProof {
    pub pi_a: Vec<String>,
    pub pi_b: Vec<Vec<String>>,
    pub pi_c: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<String>,
}

impl SnarkjsVk {
    pub fn from_file(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
}

impl SnarkjsProof {
    pub fn from_file(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
}

/// Reads a snarkjs `public.json` (array of decimal strings).
pub fn public_from_file(path: impl AsRef<std::path::Path>) -> std::io::Result<Vec<String>> {
    let v: Vec<serde_json::Value> = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(v.into_iter()
        .map(|x| match x {
            serde_json::Value::String(s) => s,
            other => other.to_string(),
        })
        .collect())
}
