//! # Quantum algebraic attack lab for the in-AIR Poseidon hash
//!
//! The arithmetization-friendly hash that commits the STARK state tree
//! (`zknet_core::stark::hash`: a width-3, x³-S-box Poseidon) is *algebraic by
//! design* — and that is the one place a structured attack bites. This crate
//! builds that attack, measures where it dies, and renders the result.
//!
//! ## The headline attack — break the hash with math, not search
//!
//! * [`poseidon`] models the reduced-round permutation both numerically (reusing
//!   the real round map) and symbolically over `F_p[b]`.
//! * [`groebner`] **eliminates** the round system to one univariate polynomial
//!   and root-finds it over `F_p` (`gcd(f, x^p-x)` + Cantor–Zassenhaus),
//!   recovering a *verified* reduced-round preimage in `~3^r` field ops.
//! * [`xl`] keeps the interior state variables and solves the degree-3 system by
//!   **XL / Macaulay linearization**, reporting the *solving degree* `D*` — the
//!   Gröbner-family security metric a round count is chosen to inflate.
//! * [`qaoa`] runs an exact statevector QAOA over a Hamming-distance cost on the
//!   same preimage problem — a variational quantum read of the structure.
//! * [`attack`] chains it end to end (second preimage → tamperable leaf) and
//!   produces the **margin curve**: `3^r` vs the crypto floors and the full
//!   127-round wall. Feeds the visual-memory page in `viz/`.
//!
//! ## The crypto-floor baseline (for comparison)
//!
//! [`grover`]/[`oracle`] simulate Grover against the *keccak* floors (Merkle
//! truncation, Fiat-Shamir grind) that the margin curve compares against. Keccak
//! has no low-degree structure, so it has **no algebraic shortcut** — only
//! Poseidon does. (The earlier AIR constraint-level attack modules were removed
//! in the cleanup for this algorithm.)
//!
//! ## The one governing fact
//!
//! The verifier is hash-based: no discrete log, no pairing, no trapdoor, so
//! **Shor is inert**. Every quantum speedup is at best Grover-quadratic. The
//! algebraic attack is the only route that is *better* than Grover — and it is
//! better only while `3^r` stays small. At `ROUNDS = 127` (`3^127 ≈ 2^201`) the
//! elimination polynomial cannot even be written down; the margin is sized right.

pub mod grover;
pub mod groebner;
pub mod oracle;
pub mod poseidon;
pub mod xl;
pub mod qaoa;
pub mod attack;
