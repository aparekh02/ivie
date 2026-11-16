// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {RollupPeriodic} from "../src/stark/generated/RollupPeriodic.sol";
import {StarkVerifier} from "../src/stark/StarkVerifier.sol";
import {ZKRollup} from "../src/stark/ZKRollup.sol";

/// Fixtures come from `zkrollup fixture` (Rust prover): batch_1 proves 1 tx
/// from the genesis state, batch_4 proves 4 txs on top of batch_1.
contract StarkTest is Test {
    StarkVerifier v;
    ZKRollup rollup;

    struct Fx {
        bytes32 prevRoot;
        bytes32 newRoot;
        bytes txs;
        bytes calldata_;
    }

    function _fx(string memory name) internal view returns (Fx memory f) {
        string memory j = vm.readFile(string.concat(vm.projectRoot(), "/test/vectors/stark/", name, ".json"));
        f.prevRoot = vm.parseJsonBytes32(j, ".prevRoot");
        f.newRoot = vm.parseJsonBytes32(j, ".newRoot");
        f.txs = vm.parseJsonBytes(j, ".txs");
        f.calldata_ = vm.parseJsonBytes(j, ".calldata");
    }

    function _proof(Fx memory f) internal pure returns (StarkVerifier.StarkProof memory p) {
        bytes memory cd = f.calldata_;
        bytes memory args = new bytes(cd.length - 4);
        for (uint256 i = 0; i < args.length; i++) {
            args[i] = cd[i + 4];
        }
        (,,, p) = abi.decode(args, (bytes32, bytes32, bytes, StarkVerifier.StarkProof));
    }

    function setUp() public {
        v = new StarkVerifier(new RollupPeriodic());
        rollup = new ZKRollup(v, address(this), _fx("batch_1").prevRoot);
    }

    function test_verify_fixtures() public {
        for (uint256 i = 0; i < 2; i++) {
            Fx memory f = _fx(i == 0 ? "batch_1" : "batch_4");
            uint256 g = gasleft();
            (bool ok, bytes memory ret) = address(v).staticcall(f.calldata_);
            g -= gasleft();
            assertTrue(ok, "honest proof rejected");
            assertTrue(abi.decode(ret, (bool)));
            console.log("verify gas", g, "calldata bytes", f.calldata_.length);
        }
    }

    /// Flipping any proof byte (after the statement) must make verify revert.
    function test_tamper_every_region() public view {
        Fx memory f = _fx("batch_1");
        bytes memory cd = f.calldata_;
        uint256 start = 4 + 4 * 32 + 32 + ((f.txs.length + 31) / 32) * 32;
        uint256 n;
        for (uint256 off = start; off < cd.length; off += 97) {
            cd[off] = cd[off] ^ 0x01;
            (bool ok,) = address(v).staticcall(cd);
            assertFalse(ok, "tampered proof accepted");
            cd[off] = cd[off] ^ 0x01;
            n++;
        }
        console.log("tampered offsets rejected:", n);
    }

    function test_rejects_wrong_statement() public {
        Fx memory f = _fx("batch_1");
        StarkVerifier.StarkProof memory p = _proof(f);
        vm.expectRevert(StarkVerifier.Pow.selector); // a different statement re-seeds the transcript
        v.verify(f.prevRoot, f.prevRoot, f.txs, p);
        bytes memory t = f.txs;
        t[0] = bytes1(uint8(200));
        vm.expectRevert(abi.encodeWithSelector(StarkVerifier.BadAccount.selector, 0));
        v.verify(f.prevRoot, f.newRoot, t, p);
    }

    function test_rollup_flow() public {
        Fx memory a = _fx("batch_1");
        Fx memory b = _fx("batch_4");
        assertEq(rollup.stateRoot(), a.prevRoot);

        vm.prank(address(0xBEEF));
        vm.expectRevert(ZKRollup.NotSequencer.selector);
        rollup.commitBatch(a.txs, a.newRoot);

        rollup.commitBatch(a.txs, a.newRoot);
        rollup.commitBatch(b.txs, b.newRoot);
        assertEq(rollup.headRoot(), b.newRoot);
        assertEq(rollup.stateRoot(), a.prevRoot, "nothing final before a proof");

        StarkVerifier.StarkProof memory pa = _proof(a);
        StarkVerifier.StarkProof memory pb = _proof(b);
        vm.expectRevert(abi.encodeWithSelector(ZKRollup.OutOfOrder.selector, 1));
        rollup.finalizeBatch(2, b.txs, pb);
        vm.expectRevert(); // batch 2's proof for batch 1
        rollup.finalizeBatch(1, a.txs, pb);

        uint256 g = gasleft();
        rollup.finalizeBatch(1, a.txs, pa);
        console.log("finalizeBatch(1 tx) gas", g - gasleft());
        assertEq(rollup.stateRoot(), a.newRoot);
        rollup.finalizeBatch(2, b.txs, pb);
        assertEq(rollup.stateRoot(), b.newRoot);
        assertEq(rollup.finalized(), 2);
    }

    function test_sequencer_cannot_lie_about_root() public {
        Fx memory a = _fx("batch_1");
        bytes32 lie = bytes32(uint256(a.newRoot) ^ 1);
        rollup.commitBatch(a.txs, lie);
        vm.expectRevert(StarkVerifier.Pow.selector);
        rollup.finalizeBatch(1, a.txs, _proof(a));
        rollup.revertBatches(1);
        rollup.commitBatch(a.txs, a.newRoot);
        rollup.finalizeBatch(1, a.txs, _proof(a));
        assertEq(rollup.stateRoot(), a.newRoot);
    }
}
