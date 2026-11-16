// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

/// Loads fixtures written by tools/gen-vectors.mjs and circuits/build.mjs.
abstract contract Vectors is Test {
    struct Case {
        string name;
        bytes proof;
        uint256[] inputs;
    }

    struct Fixture {
        string name;
        uint8 curve;
        uint256 nPublic;
        bytes rawVk;
        bytes32 circuitId;
        bytes unsafeVk;
        Case[] valid;
        Case[] invalid;
    }

    string internal constant DIR = "test/vectors/";

    function fixtureNames(string memory index) internal view returns (string[] memory) {
        string memory j = vm.readFile(string.concat(DIR, index));
        return vm.parseJsonStringArray(j, ".fixtures");
    }

    function allFixtureNames() internal view returns (string[] memory out) {
        string[] memory a = fixtureNames("sim_index.json");
        string[] memory b = fixtureNames("circom_index.json");
        out = new string[](a.length + b.length);
        for (uint256 i = 0; i < a.length; i++) out[i] = a[i];
        for (uint256 i = 0; i < b.length; i++) out[a.length + i] = b[i];
    }

    function load(string memory name) internal view returns (Fixture memory f) {
        string memory j = vm.readFile(string.concat(DIR, name, ".json"));
        f.name = name;
        f.curve = uint8(vm.parseJsonUint(j, ".curve"));
        f.nPublic = vm.parseJsonUint(j, ".nPublic");
        f.rawVk = vm.parseJsonBytes(j, ".rawVk");
        f.circuitId = vm.parseJsonBytes32(j, ".circuitId");
        f.unsafeVk = vm.parseJsonBytes(j, ".unsafeVk");
        f.valid = _cases(j, ".valid", vm.parseJsonUint(j, ".nValid"), f.nPublic);
        f.invalid = _cases(j, ".invalid", vm.parseJsonUint(j, ".nInvalid"), f.nPublic);
    }

    function _cases(string memory j, string memory key, uint256 n, uint256 nPublic) private pure returns (Case[] memory cs) {
        cs = new Case[](n);
        for (uint256 i = 0; i < n; i++) {
            string memory p = string.concat(key, "[", vm.toString(i), "]");
            cs[i].name = vm.parseJsonString(j, string.concat(p, ".name"));
            cs[i].proof = vm.parseJsonBytes(j, string.concat(p, ".proof"));
            cs[i].inputs = nPublic == 0 ? new uint256[](0) : vm.parseJsonUintArray(j, string.concat(p, ".inputs"));
        }
    }
}
