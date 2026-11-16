// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";
import {Vectors} from "./Vectors.sol";
import {ZKVerifierRegistry} from "../src/ZKVerifierRegistry.sol";
import {Groth16BN254} from "../src/Groth16BN254.sol";
import {Groth16BLS12381} from "../src/Groth16BLS12381.sol";

contract RegistryTest is Vectors {
    ZKVerifierRegistry reg;

    function setUp() public {
        reg = new ZKVerifierRegistry();
    }

    function _register(Fixture memory f) internal returns (bytes32 id) {
        id = reg.register(ZKVerifierRegistry.Curve(f.curve), f.rawVk, f.name);
    }

    // ---------------------------------------------------------------- vectors

    /// Every fixture: valid cases verify, every adversarial case returns false
    /// (no revert), and the on-chain id equals the id computed in JS.
    function test_allFixtures() public {
        string[] memory names = allFixtureNames();
        uint256 nValid;
        uint256 nInvalid;
        for (uint256 k = 0; k < names.length; k++) {
            Fixture memory f = load(names[k]);
            bytes32 id = _register(f);
            assertEq(id, f.circuitId, string.concat(f.name, ": circuit id mismatch vs tools/zk.mjs"));
            for (uint256 i = 0; i < f.valid.length; i++) {
                assertTrue(reg.verify(id, f.valid[i].proof, f.valid[i].inputs), string.concat(f.name, " rejected valid: ", f.valid[i].name));
            }
            for (uint256 i = 0; i < f.invalid.length; i++) {
                assertFalse(reg.verify(id, f.invalid[i].proof, f.invalid[i].inputs), string.concat(f.name, " accepted invalid: ", f.invalid[i].name));
            }
            nValid += f.valid.length;
            nInvalid += f.invalid.length;
        }
        console.log("fixtures", names.length);
        console.log("valid accepted", nValid);
        console.log("invalid rejected", nInvalid);
    }

    // ------------------------------------------------------- trusted-setup bugs

    /// zkeys exported before the phase-2 contribution have delta == gamma.
    /// Proofs are forgeable under such a VK, so registration must fail.
    function test_rejectsVkWithoutPhase2() public {
        string[] memory names = fixtureNames("circom_index.json");
        for (uint256 k = 0; k < names.length; k++) {
            Fixture memory f = load(names[k]);
            vm.expectRevert();
            reg.register(ZKVerifierRegistry.Curve(f.curve), f.unsafeVk, "no-phase2");
        }
    }

    /// Demonstrates WHY: with gamma == delta, put vk_x's contribution into C.
    /// Forgery: A = alpha, B = beta, C = -vk_x satisfies
    /// e(A,B) = e(alpha,beta) e(vk_x,gamma) e(C,delta) for ANY inputs.
    function test_gammaEqualsDeltaIsForgeable_libraryLevel() public view {
        Fixture memory f = load("circom_multiplier_bn128");
        bytes memory raw = f.unsafeVk;
        // prepare() refuses; bypass it to show the attack would work
        bytes memory vk = _prepareUnchecked(raw);
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = 42; // "42 has a non-trivial factorization" - with no witness at all
        uint256[2] memory vkx = _vkx(raw, inputs);
        bytes memory proof = abi.encodePacked(
            _w(raw, 0), _w(raw, 1), // A = alpha
            _w(raw, 2), _w(raw, 3), _w(raw, 4), _w(raw, 5), // B = beta
            vkx[0], (Groth16BN254.Q - vkx[1]) % Groth16BN254.Q // C = -vk_x
        );
        assertTrue(Groth16BN254.verify(vk, proof, inputs), "forgery should verify under gamma == delta");
    }

    // --------------------------------------------------------- VK validation

    function test_register_rejectsMalformedVks() public {
        Fixture memory bn = load("sim_bn254_n2");
        Fixture memory bls = load("sim_bls12381_n2");

        // identity alpha
        _expectBad(0, _setWords(bn.rawVk, 0, 0, 0));
        // alpha off curve
        _expectBad(0, _setWord(bn.rawVk, 1, _w(bn.rawVk, 1) + 1));
        // non-canonical alpha.y (+q)
        _expectBad(0, _setWord(bn.rawVk, 1, _w(bn.rawVk, 1) + Groth16BN254.Q));
        // IC[2] off curve (last word)
        _expectBad(0, _setWord(bn.rawVk, bn.rawVk.length / 32 - 1, 7));
        // delta off curve
        _expectBad(0, _setWord(bn.rawVk, 13, _w(bn.rawVk, 13) ^ 1));
        // delta = identity
        _expectBad(0, _setWords(_setWords(bn.rawVk, 10, 0, 0), 12, 0, 0));
        // bad length
        _expectBad(0, abi.encodePacked(bn.rawVk, uint256(1)));
        _expectBad(0, new bytes(17 * 32));

        // BLS: alpha off curve, delta limb flipped, bad length
        bytes memory b1 = _copy(bls.rawVk);
        b1[127] = bytes1(uint8(b1[127]) ^ 1);
        _expectBad(1, b1);
        bytes memory b2 = _copy(bls.rawVk);
        b2[640 + 255] = bytes1(uint8(b2[640 + 255]) ^ 1);
        _expectBad(1, b2);
        _expectBad(1, abi.encodePacked(bls.rawVk, bytes32(0)));
        // BLS: gamma copied over delta
        bytes memory b3 = _copy(bls.rawVk);
        for (uint256 i = 0; i < 256; i++) b3[640 + i] = b3[384 + i];
        _expectBad(1, b3);

        // duplicate registration
        bytes32 id = reg.register(ZKVerifierRegistry.Curve.BN254, bn.rawVk, "a");
        vm.expectRevert(abi.encodeWithSelector(ZKVerifierRegistry.AlreadyRegistered.selector, id));
        reg.register(ZKVerifierRegistry.Curve.BN254, bn.rawVk, "b");
    }

    function test_prepareRoundTrip_storedVkIsNegatedForm() public {
        Fixture memory f = load("sim_bn254_n1");
        bytes32 id = _register(f);
        bytes memory stored = reg.vkOf(id);
        assertEq(stored.length, f.rawVk.length);
        // beta.y negated, beta.x untouched
        assertEq(_w(stored, 2), _w(f.rawVk, 2));
        assertEq(_w(stored, 4), Groth16BN254.Q - _w(f.rawVk, 4));
        (, uint32 n,,) = reg.circuits(id);
        assertEq(n, 1);
    }

    // ------------------------------------------------------------- API errors

    function test_reverts_onStructuralMisuse() public {
        Fixture memory f = load("sim_bn254_n2");
        bytes32 id = _register(f);
        Case memory c = f.valid[0];

        uint256[] memory short = new uint256[](1);
        short[0] = c.inputs[0];
        vm.expectRevert(abi.encodeWithSelector(Groth16BN254.InputCountMismatch.selector, 2, 1));
        reg.verify(id, c.proof, short);

        vm.expectRevert(Groth16BN254.BadProofLength.selector);
        reg.verify(id, abi.encodePacked(c.proof, bytes1(0)), c.inputs);

        vm.expectRevert(abi.encodeWithSelector(ZKVerifierRegistry.UnknownCircuit.selector, bytes32(uint256(1))));
        reg.verify(bytes32(uint256(1)), c.proof, c.inputs);

        Fixture memory g = load("sim_bls12381_n1");
        bytes32 gid = _register(g);
        vm.expectRevert(Groth16BLS12381.BadProofLength.selector);
        reg.verify(gid, f.valid[0].proof, g.valid[0].inputs); // 256-byte BN proof to BLS circuit
    }

    // ---------------------------------------------------------------- submit

    function test_submit_recordsAndBlocksReplay_evenReRandomized() public {
        Fixture memory f = load("circom_nullifier_bn128");
        bytes32 id = _register(f);
        Case memory c = f.valid[0];
        bytes32 h = keccak256(abi.encodePacked(c.inputs));

        vm.expectEmit(true, true, true, true);
        emit ZKVerifierRegistry.ProofVerified(id, h, address(this), c.inputs);
        assertEq(reg.submit(id, c.proof, c.inputs), h);
        assertTrue(reg.consumed(id, h));

        // the re-randomized proof is a DIFFERENT valid proof of the same statement
        Case memory rr = _findValid(f, "re-randomized");
        assertTrue(keccak256(rr.proof) != keccak256(c.proof));
        assertTrue(reg.verify(id, rr.proof, rr.inputs));
        vm.expectRevert(abi.encodeWithSelector(ZKVerifierRegistry.AlreadyConsumed.selector, id, h));
        reg.submit(id, rr.proof, rr.inputs);

        // a different statement (new topic -> new nullifier) is accepted
        reg.submit(id, f.valid[1].proof, f.valid[1].inputs);

        vm.expectRevert(ZKVerifierRegistry.InvalidProof.selector);
        reg.submit(id, f.invalid[0].proof, f.invalid[0].inputs);
    }

    // ------------------------------------------------------------------ fuzz

    /// Random bytes in a well-formed envelope never verify and never revert.
    function testFuzz_randomProofNeverVerifies_bn254(bytes32 s0, bytes32 s1, uint256 x) public {
        Fixture memory f = load("sim_bn254_n1");
        bytes32 id = _register(f);
        bytes memory proof = abi.encodePacked(
            keccak256(abi.encode(s0, 0)), keccak256(abi.encode(s0, 1)), keccak256(abi.encode(s0, 2)), keccak256(abi.encode(s0, 3)),
            keccak256(abi.encode(s1, 4)), keccak256(abi.encode(s1, 5)), keccak256(abi.encode(s1, 6)), keccak256(abi.encode(s1, 7))
        );
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = x;
        assertFalse(reg.verify(id, proof, inputs));
    }

    function testFuzz_randomProofNeverVerifies_bls(bytes32 seed, uint256 x) public {
        Fixture memory f = load("sim_bls12381_n1");
        bytes32 id = _register(f);
        bytes memory proof = new bytes(512);
        for (uint256 i = 0; i < 16; i++) {
            bytes32 w = keccak256(abi.encode(seed, i));
            assembly {
                mstore(add(add(proof, 0x20), mul(i, 32)), w)
            }
        }
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = x;
        assertFalse(reg.verify(id, proof, inputs));
    }

    /// Valid proof, any other input value -> rejected.
    /// Includes values >= r, in particular original + r, which is the same
    /// scalar mod r and must still be refused.
    function testFuzz_perturbedInputRejected(uint256 v, uint256 j, bool bls, bool plusR) public {
        Fixture memory f = load(bls ? "circom_sum_of_squares_bls12381" : "circom_sum_of_squares_bn128");
        bytes32 id = _register(f);
        Case memory c = f.valid[0];
        j = bound(j, 0, c.inputs.length - 1);
        uint256 r = bls ? Groth16BLS12381.R : Groth16BN254.R;
        if (plusR) v = c.inputs[j] + r;
        vm.assume(v != c.inputs[j]);
        c.inputs[j] = v;
        assertFalse(reg.verify(id, c.proof, c.inputs));
    }

    /// Flip any single bit of a valid proof -> rejected.
    function testFuzz_bitFlipRejected(uint256 bit, uint8 which) public {
        string[4] memory pick = ["circom_multiplier_bn128", "circom_multiplier_bls12381", "sim_bn254_n5", "sim_bls12381_n5"];
        Fixture memory f = load(pick[which % 4]);
        bytes32 id = _register(f);
        Case memory c = f.valid[0];
        bit = bound(bit, 0, c.proof.length * 8 - 1);
        c.proof[bit / 8] = bytes1(uint8(c.proof[bit / 8]) ^ uint8(1 << (7 - (bit % 8))));
        assertFalse(reg.verify(id, c.proof, c.inputs));
    }

    // ---------------------------------------------------------- gas griefing

    /// For ANY gas budget, a valid proof either verifies or the call reverts.
    /// It never returns false. (A false verdict from a starved precompile call
    /// would let a relayer make valid proofs look invalid.)
    function testFuzz_validProofNeverFalseUnderGasStarvation(uint256 gasBudget, bool bls) public {
        Fixture memory f = load(bls ? "circom_sum_of_squares_bls12381" : "circom_sum_of_squares_bn128");
        bytes32 id = _register(f);
        Case memory c = f.valid[0];
        gasBudget = bound(gasBudget, 5_000, 1_500_000);
        (bool ok, bytes memory ret) = address(reg).staticcall{gas: gasBudget}(abi.encodeCall(reg.verify, (id, c.proof, c.inputs)));
        if (ok) assertTrue(abi.decode(ret, (bool)), "valid proof returned false under gas pressure");
    }

    /// And with enough gas, invalid proofs still get a clean `false`.
    function test_invalidProofStillFalseWithAmpleGas() public {
        Fixture memory f = load("circom_multiplier_bn128");
        bytes32 id = _register(f);
        for (uint256 i = 0; i < f.invalid.length; i++) {
            (bool ok, bytes memory ret) = address(reg).staticcall{gas: 3_000_000}(abi.encodeCall(reg.verify, (id, f.invalid[i].proof, f.invalid[i].inputs)));
            assertTrue(ok, f.invalid[i].name);
            assertFalse(abi.decode(ret, (bool)));
        }
    }

    // ------------------------------------------------------------------- gas

    function test_gasReport() public {
        string[] memory names = allFixtureNames();
        console.log("fixture | nPublic | verify gas (registry, incl. VK load)");
        for (uint256 k = 0; k < names.length; k++) {
            Fixture memory f = load(names[k]);
            bytes32 id = _register(f);
            Case memory c = f.valid[0];
            uint256 g0 = gasleft();
            bool ok = reg.verify(id, c.proof, c.inputs);
            uint256 used = g0 - gasleft();
            assertTrue(ok);
            console.log(string.concat(f.name, " | ", vm.toString(f.nPublic), " | ", vm.toString(used)));
        }
    }

    // --------------------------------------------------------------- helpers

    function _expectBad(uint8 curve, bytes memory raw) internal {
        vm.expectRevert();
        reg.register(ZKVerifierRegistry.Curve(curve), raw, "bad");
    }

    function _findValid(Fixture memory f, string memory prefix) internal pure returns (Case memory) {
        for (uint256 i = 0; i < f.valid.length; i++) {
            bytes memory n = bytes(f.valid[i].name);
            bytes memory p = bytes(prefix);
            if (n.length < p.length) continue;
            bool m = true;
            for (uint256 k = 0; k < p.length; k++) if (n[k] != p[k]) m = false;
            if (m) return f.valid[i];
        }
        revert("case not found");
    }

    function _w(bytes memory b, uint256 i) internal pure returns (uint256 v) {
        assembly {
            v := mload(add(add(b, 0x20), mul(i, 0x20)))
        }
    }

    function _copy(bytes memory b) internal pure returns (bytes memory) {
        return abi.encodePacked(b);
    }

    function _setWord(bytes memory b, uint256 i, uint256 v) internal pure returns (bytes memory out) {
        out = _copy(b);
        assembly {
            mstore(add(add(out, 0x20), mul(i, 0x20)), v)
        }
    }

    function _setWords(bytes memory b, uint256 i, uint256 v0, uint256 v1) internal pure returns (bytes memory) {
        return _setWord(_setWord(b, i, v0), i + 1, v1);
    }

    function _prepareUnchecked(bytes memory raw) internal pure returns (bytes memory vk) {
        vk = _copy(raw);
        for (uint256 g = 0; g < 3; g++) {
            uint256 o = 2 + 4 * g;
            vk = _setWord(vk, o + 2, (Groth16BN254.Q - _w(vk, o + 2)) % Groth16BN254.Q);
            vk = _setWord(vk, o + 3, (Groth16BN254.Q - _w(vk, o + 3)) % Groth16BN254.Q);
        }
    }

    function _vkx(bytes memory raw, uint256[] memory inputs) internal view returns (uint256[2] memory acc) {
        acc = [_w(raw, 14), _w(raw, 15)];
        for (uint256 i = 0; i < inputs.length; i++) {
            (bool ok1, bytes memory m) = address(7).staticcall(abi.encode(_w(raw, 16 + 2 * i), _w(raw, 17 + 2 * i), inputs[i]));
            require(ok1);
            (uint256 mx, uint256 my) = abi.decode(m, (uint256, uint256));
            (bool ok2, bytes memory s) = address(6).staticcall(abi.encode(acc[0], acc[1], mx, my));
            require(ok2);
            (acc[0], acc[1]) = abi.decode(s, (uint256, uint256));
        }
    }
}
