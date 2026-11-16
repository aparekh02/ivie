//! zknet-core: everything a prover needs to talk to the zknet verifier,
//! with no networking.
//!
//! * [`encode`]: snarkjs JSON into the exact on-chain byte layouts, circuit
//!   ids and input hashes. These match `tools/zk.mjs` byte for byte.
//! * [`verify`]: a native Groth16 verifier (arkworks) that applies the same
//!   rules as `Groth16BN254.sol` / `Groth16BLS12381.sol`: canonical
//!   coordinates, on-curve and subgroup checks, inputs `< r`, VK hygiene.
//!   It runs in microseconds, so a prover can check every proof before
//!   sending it to the chain.
//! * [`api`]: request and response types for the `zknetd` socket. The daemon
//!   and the SDK share them.

pub mod api;
pub mod encode;
pub mod snarkjs;
pub mod verify;

pub use encode::{Curve, circuit_id, encode_proof, encode_vk, inputs_hash, parse_u256};
pub use snarkjs::{SnarkjsProof, SnarkjsVk};
pub use verify::{Reject, check_vk, verify};

pub use alloy_primitives::{Address, B256, Bytes, U256};
pub use ark_bls12_381;
pub use ark_bn254;

/// The address the registry gets from the canonical CREATE2 deployer. It is the
/// same on every chain (see `e2e/run.mjs`).
pub const CREATE2_DEPLOYER: Address = alloy_primitives::address!("4e59b44847b379578588920cA78FbF26c0B4956C");

/// CREATE2 salt used by `e2e/run.mjs`: the ASCII string, right-padded to 32 bytes.
pub fn registry_salt() -> B256 {
    let mut s = [0u8; 32];
    let tag = b"zknet.registry.v1";
    s[..tag.len()].copy_from_slice(tag);
    B256::from(s)
}

/// Registry address for a given init code (the `bytecode.object` of
/// `contracts/out/ZKVerifierRegistry.sol/ZKVerifierRegistry.json`).
pub fn registry_address(initcode: &[u8]) -> Address {
    CREATE2_DEPLOYER.create2_from_code(registry_salt(), initcode)
}
