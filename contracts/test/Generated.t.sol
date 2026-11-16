// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";
import {Vectors} from "./Vectors.sol";
import {ZKVerifierRegistry} from "../src/ZKVerifierRegistry.sol";
import {MultiplierVerifierBN254} from "../src/generated/MultiplierVerifierBN254.sol";
import {NullifierVerifierBN254} from "../src/generated/NullifierVerifierBN254.sol";
import {SumOfSquaresVerifierBLS12381} from "../src/generated/SumOfSquaresVerifierBLS12381.sol";

interface IGen {
    function verify(bytes calldata proof, uint256[] calldata inputs) external view returns (bool);
    function CIRCUIT_ID() external view returns (bytes32);
    function preparedVk() external pure returns (bytes memory);
}

/// Generated standalone verifiers must agree with the registry on every
/// vector, embed exactly the registry's prepared VK (JS negation == Solidity
/// negation), and expose a working snarkjs ABI.
contract GeneratedTest is Vectors {
    ZKVerifierRegistry reg;

    function setUp() public {
        reg = new ZKVerifierRegistry();
    }

    function test_multiplierBN254() public {
        _check("circom_multiplier_bn128", address(new MultiplierVerifierBN254()));
    }

    function test_nullifierBN254() public {
        _check("circom_nullifier_bn128", address(new NullifierVerifierBN254()));
    }

    function test_sumOfSquaresBLS() public {
        _check("circom_sum_of_squares_bls12381", address(new SumOfSquaresVerifierBLS12381()));
    }

    function test_snarkjsAbi() public {
        MultiplierVerifierBN254 v = new MultiplierVerifierBN254();
        Fixture memory f = load("circom_multiplier_bn128");
        bytes memory p = f.valid[0].proof;
        uint256[8] memory w = abi.decode(p, (uint256[8]));
        uint256[1] memory pub = [f.valid[0].inputs[0]];
        assertTrue(v.verifyProof([w[0], w[1]], [[w[2], w[3]], [w[4], w[5]]], [w[6], w[7]], pub));
        pub[0] += 1;
        assertFalse(v.verifyProof([w[0], w[1]], [[w[2], w[3]], [w[4], w[5]]], [w[6], w[7]], pub));
    }

    function _check(string memory name, address gen) internal {
        Fixture memory f = load(name);
        bytes32 id = reg.register(ZKVerifierRegistry.Curve(f.curve), f.rawVk, f.name);
        assertEq(IGen(gen).CIRCUIT_ID(), id, "generated CIRCUIT_ID != registry id");
        assertEq(IGen(gen).preparedVk(), reg.vkOf(id), "JS-prepared VK != Solidity-prepared VK");
        for (uint256 i = 0; i < f.valid.length; i++) assertTrue(IGen(gen).verify(f.valid[i].proof, f.valid[i].inputs));
        for (uint256 i = 0; i < f.invalid.length; i++) assertFalse(IGen(gen).verify(f.invalid[i].proof, f.invalid[i].inputs), f.invalid[i].name);

        Case memory c = f.valid[0];
        uint256 g0 = gasleft();
        IGen(gen).verify(c.proof, c.inputs);
        uint256 standalone = g0 - gasleft();
        g0 = gasleft();
        reg.verify(id, c.proof, c.inputs);
        uint256 viaRegistry = g0 - gasleft();
        console.log(string.concat(name, ": standalone ", vm.toString(standalone), " gas, registry ", vm.toString(viaRegistry)));
    }
}
