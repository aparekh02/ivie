//! # Quantum attack lab for the zknet STARK verifier
//!
//! Baseline layer: a real Grover amplitude-amplification simulation against the
//! *keccak* crypto floors (Merkle truncation and Fiat-Shamir grinding) that the
//! verifier rests on. Keccak has no low-degree structure, so it admits no
//! algebraic shortcut — only a Grover quadratic speedup or a BHT collision.
//! These floors are the comparison baseline for the algebraic attack on the
//! arithmetization-friendly in-AIR hash, added on top of this layer.

pub mod grover;
pub mod groebner;
pub mod oracle;
pub mod poseidon;
