// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Groth16BN254} from "./Groth16BN254.sol";
import {Groth16BLS12381} from "./Groth16BLS12381.sol";

/// @title ZKVerifierRegistry: content-addressed Groth16 verification keys.
///
/// Anyone can register a VK. Its id is keccak256(abi.encode(curve, rawVk)),
/// so a prover can compute the id off-chain and no admin is involved. A VK
/// says nothing about which circuit it belongs to, so consumers must pin the
/// circuit ids they trust.
///
/// VKs are validated once, prepared (G2 points negated) and stored as contract
/// bytecode (SSTORE2). Loading the VK for a proof then costs an EXTCODECOPY,
/// not 16+ cold SLOADs.
contract ZKVerifierRegistry {
    enum Curve {
        BN254,
        BLS12_381
    }

    struct Circuit {
        Curve curve;
        uint32 nPublic;
        address vk; // SSTORE2 pointer to the prepared VK
        address registrant;
    }

    mapping(bytes32 => Circuit) public circuits;
    /// circuitId => keccak256(publicInputs) => already submitted
    mapping(bytes32 => mapping(bytes32 => bool)) public consumed;

    event CircuitRegistered(bytes32 indexed id, Curve curve, uint256 nPublic, address indexed registrant, string label);
    event ProofVerified(bytes32 indexed id, bytes32 indexed inputsHash, address indexed submitter, uint256[] inputs);

    error AlreadyRegistered(bytes32 id);
    error UnknownCircuit(bytes32 id);
    error InvalidProof();
    error AlreadyConsumed(bytes32 id, bytes32 inputsHash);
    error StoreFailed();

    function circuitId(Curve curve, bytes calldata rawVk) public pure returns (bytes32) {
        return keccak256(abi.encode(curve, rawVk));
    }

    function register(Curve curve, bytes calldata rawVk, string calldata label) external returns (bytes32 id) {
        id = circuitId(curve, rawVk);
        if (circuits[id].vk != address(0)) revert AlreadyRegistered(id);
        bytes memory prepared;
        uint256 n;
        if (curve == Curve.BN254) {
            prepared = Groth16BN254.prepare(rawVk);
            n = (prepared.length / 32 - 16) / 2;
        } else {
            prepared = Groth16BLS12381.prepare(rawVk);
            n = (prepared.length - Groth16BLS12381.HEADER_BYTES) / 128 - 1;
        }
        // n <= ~760 for BN254 / ~184 for BLS: the VK must fit in 24576 bytes of code
        // forge-lint: disable-next-line(unsafe-typecast)
        circuits[id] = Circuit(curve, uint32(n), _store(prepared), msg.sender);
        emit CircuitRegistered(id, curve, n, msg.sender, label);
    }

    /// @notice Pure check. Returns false for invalid proofs; reverts for an
    ///         unknown circuit or wrong input count / proof length.
    function verify(bytes32 id, bytes calldata proof, uint256[] calldata inputs) public view returns (bool) {
        Circuit memory c = circuits[id];
        if (c.vk == address(0)) revert UnknownCircuit(id);
        bytes memory vk = _load(c.vk);
        return c.curve == Curve.BN254
            ? Groth16BN254.verify(vk, proof, inputs)
            : Groth16BLS12381.verify(vk, proof, inputs);
    }

    /// @notice Verify and record. Each public-input vector is accepted once
    ///         per circuit. Replay protection is keyed on the INPUTS, not the
    ///         proof: Groth16 proofs can be re-randomized, so (A, B, C) is
    ///         not unique for a statement. Put a nullifier in the public inputs
    ///         if a statement should be provable only once.
    function submit(bytes32 id, bytes calldata proof, uint256[] calldata inputs) external returns (bytes32 inputsHash) {
        if (!verify(id, proof, inputs)) revert InvalidProof();
        inputsHash = keccak256(abi.encodePacked(inputs));
        if (consumed[id][inputsHash]) revert AlreadyConsumed(id, inputsHash);
        consumed[id][inputsHash] = true;
        emit ProofVerified(id, inputsHash, msg.sender, inputs);
    }

    function vkOf(bytes32 id) external view returns (bytes memory) {
        Circuit memory c = circuits[id];
        if (c.vk == address(0)) revert UnknownCircuit(id);
        return _load(c.vk);
    }

    // ---- SSTORE2: data stored as the runtime code of a contract, prefixed
    // with a STOP byte so the "contract" can never be executed meaningfully.
    function _store(bytes memory data) private returns (address ptr) {
        bytes memory runtime = abi.encodePacked(hex"00", data);
        // EIP-170: runtime code is capped at 24576 bytes on mainnet.
        if (runtime.length > 24576) revert StoreFailed();
        // initcode (10 bytes): PUSH2 len, DUP1, PUSH1 0x0a, PUSH0, CODECOPY, PUSH0, RETURN | runtime
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory init = abi.encodePacked(hex"61", uint16(runtime.length), hex"80600a5f395ff3", runtime);
        assembly ("memory-safe") {
            ptr := create(0, add(init, 0x20), mload(init))
        }
        if (ptr == address(0)) revert StoreFailed();
    }

    function _load(address ptr) private view returns (bytes memory data) {
        uint256 len = ptr.code.length - 1;
        data = new bytes(len);
        assembly ("memory-safe") {
            extcodecopy(ptr, add(data, 0x20), 1, len)
        }
    }
}
