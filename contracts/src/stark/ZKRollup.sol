// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {StarkVerifier} from "./StarkVerifier.sol";

/// @title ZKRollup: L1 contract of a validity rollup.
///
/// The flow follows production zk-rollups (Scroll's commit/finalize, zkSync's
/// commit/prove/execute):
///
///   1. commitBatch   the sequencer posts the batch's transactions as calldata
///                    (data availability) together with the post-state root it
///                    claims. Nothing is trusted yet.
///   2. finalizeBatch anyone submits a STARK proof that applying exactly those
///                    transactions to the last FINALIZED root yields the
///                    claimed root. Only then does `stateRoot` move.
///   3. revertBatches the sequencer can drop committed but unproven batches.
///
/// Batches finalize strictly in order, and each proof is bound to the
/// finalized root, the committed tx data (keccak), and the claimed new root,
/// so a proof for one batch can't be replayed for another.
contract ZKRollup {
    StarkVerifier public immutable verifier;
    address public immutable sequencer;
    bytes32 public immutable genesisRoot;

    struct Batch {
        bytes32 txHash; // keccak256 of the tx calldata
        bytes32 newRoot; // post-state root claimed by the sequencer
        uint64 committedAt; // L1 block
        uint32 nTx;
    }

    /// batch index (1-based) => batch
    mapping(uint256 => Batch) public batches;
    uint256 public committed;
    uint256 public finalized;
    /// last finalized L2 state root
    bytes32 public stateRoot;

    event BatchCommitted(uint256 indexed index, bytes32 indexed newRoot, bytes32 txHash, bytes txs);
    event BatchFinalized(uint256 indexed index, bytes32 indexed newRoot, address indexed prover);
    event BatchesReverted(uint256 fromIndex, uint256 toIndex);

    error NotSequencer();
    error BadTxData();
    error UnknownBatch(uint256 index);
    error OutOfOrder(uint256 expected);
    error TxDataMismatch(bytes32 committed, bytes32 given);
    error CannotRevert(uint256 index);

    constructor(StarkVerifier verifier_, address sequencer_, bytes32 genesisRoot_) {
        verifier = verifier_;
        sequencer = sequencer_;
        genesisRoot = genesisRoot_;
        stateRoot = genesisRoot_;
    }

    /// @notice Root the next committed batch must build on.
    function headRoot() public view returns (bytes32) {
        return committed == finalized ? stateRoot : batches[committed].newRoot;
    }

    function commitBatch(bytes calldata txs, bytes32 newRoot) external returns (uint256 index) {
        if (msg.sender != sequencer) revert NotSequencer();
        if (txs.length == 0 || txs.length % 10 != 0) revert BadTxData();
        index = ++committed;
        bytes32 h = keccak256(txs);
        // forge-lint: disable-next-line(unsafe-typecast)
        batches[index] = Batch(h, newRoot, uint64(block.number), uint32(txs.length / 10));
        emit BatchCommitted(index, newRoot, h, txs);
    }

    /// @notice Permissionless: anyone holding a valid proof can finalize.
    function finalizeBatch(uint256 index, bytes calldata txs, StarkVerifier.StarkProof calldata proof) external {
        if (index != finalized + 1) revert OutOfOrder(finalized + 1);
        if (index > committed) revert UnknownBatch(index);
        Batch memory b = batches[index];
        bytes32 h = keccak256(txs);
        if (h != b.txHash) revert TxDataMismatch(b.txHash, h);
        // reverts with the verifier's reason if the proof is invalid
        verifier.verify(stateRoot, b.newRoot, txs, proof);
        stateRoot = b.newRoot;
        finalized = index;
        emit BatchFinalized(index, b.newRoot, msg.sender);
    }

    function revertBatches(uint256 fromIndex) external {
        if (msg.sender != sequencer) revert NotSequencer();
        if (fromIndex <= finalized || fromIndex > committed) revert CannotRevert(fromIndex);
        uint256 to = committed;
        for (uint256 i = fromIndex; i <= to; i++) {
            delete batches[i];
        }
        committed = fromIndex - 1;
        emit BatchesReverted(fromIndex, to);
    }
}
