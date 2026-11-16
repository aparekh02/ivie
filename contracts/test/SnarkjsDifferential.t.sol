// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";
import {Vectors} from "./Vectors.sol";
import {ZKVerifierRegistry} from "../src/ZKVerifierRegistry.sol";
import {SnarkjsMultiplierVerifier} from "./snarkjs/multiplier.sol";
import {SnarkjsSumOfSquaresVerifier} from "./snarkjs/sum_of_squares.sol";
import {SnarkjsNullifierVerifier} from "./snarkjs/nullifier.sol";

/// Differential test against the verifier snarkjs generates
/// (`snarkjs zkey export solidityverifier`), the contract most circom
/// projects deploy. Both verifiers must agree on every vector, with one
/// documented exception: snarkjs negates A as mod(sub(q, A.y), q) in 256-bit
/// arithmetic. A.y + q is rejected (the subtraction wraps to 2^256 - y), but
/// A.y' = ((y + 2^256) mod q) + q wraps to exactly q - y and is ACCEPTED.
/// That gives a second byte string for the same proof, which matters to
/// anyone deduplicating on proof bytes. Ours rejects it.
contract SnarkjsDifferentialTest is Vectors {
    ZKVerifierRegistry reg;

    function setUp() public {
        reg = new ZKVerifierRegistry();
    }

    function test_agreesWithSnarkjs_multiplier() public {
        _diff("circom_multiplier_bn128", address(new SnarkjsMultiplierVerifier()));
    }

    function test_agreesWithSnarkjs_sumOfSquares() public {
        _diff("circom_sum_of_squares_bn128", address(new SnarkjsSumOfSquaresVerifier()));
    }

    function test_agreesWithSnarkjs_nullifier() public {
        _diff("circom_nullifier_bn128", address(new SnarkjsNullifierVerifier()));
    }

    function _diff(string memory name, address snark) internal {
        Fixture memory f = load(name);
        bytes32 id = reg.register(ZKVerifierRegistry.Curve.BN254, f.rawVk, f.name);
        uint256 disagreements;
        for (uint256 i = 0; i < f.valid.length; i++) {
            assertTrue(reg.verify(id, f.valid[i].proof, f.valid[i].inputs));
            assertTrue(_snarkjs(snark, f.nPublic, f.valid[i]), string.concat("snarkjs rejected ", f.valid[i].name));
        }
        for (uint256 i = 0; i < f.invalid.length; i++) {
            Case memory c = f.invalid[i];
            bool ours = reg.verify(id, c.proof, c.inputs);
            bool theirs = _snarkjs(snark, f.nPublic, c);
            assertFalse(ours);
            if (theirs) {
                disagreements++;
                console.log(string.concat("snarkjs ACCEPTS: ", c.name));
                assertEq(keccak256(bytes(c.name)), keccak256("A.y wrap-malleable (((y + 2^256) mod q) + q)"), "unexpected disagreement");
            }
        }
        assertEq(disagreements, 1, "expected exactly the A.y wrap malleability");
    }

    /// snarkjs ABI: verifyProof(uint[2] a, uint[2][2] b, uint[2] c, uint[N] pub).
    /// The registry's proof bytes are this same word sequence (B in EIP-197
    /// order), so the calldata is selector || proof || inputs.
    function _snarkjs(address v, uint256 n, Case memory c) internal view returns (bool) {
        string memory sig = string.concat("verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[", vm.toString(n), "])");
        bytes memory data = abi.encodePacked(bytes4(keccak256(bytes(sig))), c.proof, c.inputs);
        (bool ok, bytes memory ret) = v.staticcall{gas: 2_000_000}(data); // snarkjs burns all gas on bad points
        return ok && ret.length == 32 && abi.decode(ret, (bool));
    }

    /// Bounded burn: an invalid proof whose points fail precompile validation
    /// must not consume the caller's whole gas limit (snarkjs forwards gas()).
    function test_invalidProofGasIsBounded() public {
        Fixture memory f = load("circom_multiplier_bn128");
        bytes32 id = reg.register(ZKVerifierRegistry.Curve.BN254, f.rawVk, f.name);
        address snark = address(new SnarkjsMultiplierVerifier());
        Case memory bad = _find(f, "A off curve");
        uint256 limit = 16_777_216; // EIP-7825 per-tx cap

        uint256 g0 = gasleft();
        bool ours = reg.verify{gas: limit}(id, bad.proof, bad.inputs);
        uint256 oursGas = g0 - gasleft();

        string memory sig = "verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[1])";
        bytes memory data = abi.encodePacked(bytes4(keccak256(bytes(sig))), bad.proof, bad.inputs);
        g0 = gasleft();
        (bool ok, bytes memory ret) = snark.staticcall{gas: limit}(data);
        uint256 theirGas = g0 - gasleft();

        assertFalse(ours);
        assertFalse(ok && abi.decode(ret, (bool)));
        console.log("invalid proof gas: ours", oursGas);
        console.log("invalid proof gas: snarkjs", theirGas);
        assertLt(oursGas, 1_000_000);
    }

    function _find(Fixture memory f, string memory name) internal pure returns (Case memory) {
        for (uint256 i = 0; i < f.invalid.length; i++) {
            if (keccak256(bytes(f.invalid[i].name)) == keccak256(bytes(name))) return f.invalid[i];
        }
        revert("not found");
    }
}
