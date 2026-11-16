//! ZKVerifierRegistry ABI (including the library errors it can bubble up).

use alloy::primitives::Bytes;
use alloy::sol;
use alloy::sol_types::{SolInterface, decode_revert_reason};

sol! {
    interface IZKVerifierRegistry {
        event CircuitRegistered(bytes32 indexed id, uint8 curve, uint256 nPublic, address indexed registrant, string label);
        event ProofVerified(bytes32 indexed id, bytes32 indexed inputsHash, address indexed submitter, uint256[] inputs);

        error AlreadyRegistered(bytes32 id);
        error UnknownCircuit(bytes32 id);
        error InvalidProof();
        error AlreadyConsumed(bytes32 id, bytes32 inputsHash);
        error StoreFailed();
        // Groth16BN254 / Groth16BLS12381
        error BadVKLength();
        error BadProofLength();
        error InputCountMismatch(uint256 expected, uint256 got);
        error InvalidVK(string why);
        error InsufficientGas();

        function register(uint8 curve, bytes rawVk, string label) external returns (bytes32 id);
        function verify(bytes32 id, bytes proof, uint256[] inputs) external view returns (bool);
        function submit(bytes32 id, bytes proof, uint256[] inputs) external returns (bytes32 inputsHash);
        function vkOf(bytes32 id) external view returns (bytes);
        function circuits(bytes32 id) external view returns (uint8 curve, uint32 nPublic, address vk, address registrant);
        function consumed(bytes32 id, bytes32 inputsHash) external view returns (bool);
    }
}

use IZKVerifierRegistry::IZKVerifierRegistryErrors as E;

/// Revert data -> readable reason, e.g. `InputCountMismatch(expected=1, got=2)`.
pub fn revert_reason(data: &[u8]) -> String {
    if data.is_empty() {
        return "reverted without data (out of gas?)".into();
    }
    if let Ok(e) = E::abi_decode(data) {
        return match e {
            E::AlreadyRegistered(e) => format!("AlreadyRegistered({})", e.id),
            E::UnknownCircuit(e) => format!("UnknownCircuit({}): register the VK first", e.id),
            E::InvalidProof(_) => "InvalidProof".into(),
            E::AlreadyConsumed(e) => format!("AlreadyConsumed(id={}, inputsHash={})", e.id, e.inputsHash),
            E::StoreFailed(_) => "StoreFailed (VK too large for one contract?)".into(),
            E::BadVKLength(_) => "BadVKLength".into(),
            E::BadProofLength(_) => "BadProofLength".into(),
            E::InputCountMismatch(e) => format!("InputCountMismatch(expected={}, got={})", e.expected, e.got),
            E::InvalidVK(e) => format!("InvalidVK({})", e.why),
            E::InsufficientGas(_) => "InsufficientGas (raise the gas limit; the verdict is unknown)".into(),
        };
    }
    decode_revert_reason(data).unwrap_or_else(|| format!("revert 0x{}", alloy::hex::encode(data)))
}

/// Pulls revert data out of an RPC error, if it is an execution revert.
pub fn revert_data(err: &alloy::transports::TransportError) -> Option<Bytes> {
    err.as_error_resp().and_then(|e| e.as_revert_data())
}
