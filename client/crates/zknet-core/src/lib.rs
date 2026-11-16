//! zknet-core: the rollup's STARK proof system and the zknetd wire types,
//! with no networking.
//!
//! * [`stark`]: field, in-AIR hash, L2 state tree, AIR, prover (honest and
//!   adversarial), and a native verifier that matches `StarkVerifier.sol`
//!   check for check
//! * [`api`]: request, response and event types for the `zknetd` socket.
//!   The daemon and the SDK share them.

pub mod api;
pub mod stark;

pub use alloy_primitives::{Address, B256, Bytes, U256};

/// The canonical CREATE2 deployer (same address on every chain). The rollup
/// contracts are deployed through it, so their addresses are deterministic.
pub const CREATE2_DEPLOYER: Address = alloy_primitives::address!("4e59b44847b379578588920cA78FbF26c0B4956C");
