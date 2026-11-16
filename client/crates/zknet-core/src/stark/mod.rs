//! A STARK for rollup blocks: "applying this batch of transfers moves the L2
//! state root from prevRoot to newRoot". The L1 contract `ZKRollup.sol` checks
//! this proof before it finalizes a batch, the way zk-rollups validate proposed
//! blocks.
//!
//! * [`field`]: p = 2^251 + 17·2^192 + 1 (one EVM word, no extension field)
//! * [`hash`]: the in-AIR Poseidon-style permutation; the state tree uses it
//! * [`state`]: L2 accounts, Merkle state tree, tx encoding (L1 calldata = DA)
//! * [`air`]: trace layout, transition and boundary constraints, zerofiers
//! * [`merkle`], [`channel`], [`fri`]: masked-keccak multi-proof commitments,
//!   the StarkWare-style Fiat-Shamir channel, and FRI folding by 8
//! * [`prover`]: trace → LDE (bit-reversed) → composition → DEEP → FRI → grinding → queries
//! * [`verifier`]: the same checks as `StarkVerifier.sol`, in the same order
//! * [`proof`]: parameters (blowup 16, 18 queries, 24-bit grinding) and the ABI

pub mod air;
pub mod channel;
pub mod deploy;
pub mod field;
pub mod fri;
pub mod hash;
pub mod merkle;
pub mod proof;
pub mod prover;
pub mod solgen;
pub mod state;
pub mod verifier;

pub use field::F;
pub use proof::{Proof, StarkProof};
pub use prover::{Options, Proven, prove, prove_with};
pub use state::{State, Tx};
pub use verifier::{StarkReject, verify};
