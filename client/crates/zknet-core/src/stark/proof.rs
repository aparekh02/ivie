//! Proof object, parameters, and the ABI layout `StarkVerifier.sol` takes.

use super::field::{F, to_b256, to_u256};
use alloy_primitives::{B256, U256};

/// LDE blowup (log 4 = 16 cosets, as in typical Stone parameter files).
pub const BLOWUP: usize = 16;
/// FRI queries (before dedup). Conjectured security ≈ QUERIES·log2(BLOWUP) + POW_BITS = 96 bits.
pub const QUERIES: usize = 18;
/// Proof-of-work bits before the queries are drawn.
pub const POW_BITS: u8 = 24;

/// Native proof object (field elements, decommitments).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub log_t: u32,
    pub trace_root: B256,
    pub comp_root: B256,
    /// trace(z)[W] ‖ trace(gz)[W] ‖ H_s(z)[3]
    pub ood: Vec<F>,
    pub fri_roots: Vec<B256>,
    pub last_layer: Vec<F>,
    pub pow_nonce: u64,
    /// per unique query (sorted): the trace row and composition row
    pub trace_vals: Vec<F>,
    pub trace_decommit: Vec<B256>,
    pub comp_vals: Vec<F>,
    pub comp_decommit: Vec<B256>,
    /// per layer, per queried coset (sorted): its 8 values
    pub fri_vals: Vec<F>,
    pub fri_decommit: Vec<Vec<B256>>,
}

alloy_sol_types::sol! {
    /// Flattened proof (see `StarkVerifier.sol`).
    #[derive(Debug, PartialEq, Eq)]
    struct StarkProof {
        bytes32 traceRoot;
        bytes32 compRoot;
        uint256[] ood;
        bytes32[] friRoots;
        uint256[] lastLayer;
        uint256 powNonce;
        uint256[] traceVals;
        bytes32[] traceDecommit;
        uint256[] compVals;
        bytes32[] compDecommit;
        uint256[] friVals;
        bytes32[] friDecommit;
        uint256[] friDecommitLen;
    }

    #[derive(Debug, PartialEq, Eq)]
    interface IStarkVerifier {
        error BatchSize(uint256 n);
        error BadAccount(uint256 index);
        error Shape(uint8 what);
        error NonCanonical(uint8 what);
        error Pow();
        error Ood();
        error Degenerate();
        error TraceMerkle();
        error CompMerkle();
        error FriMerkle(uint256 layer);
        error Deep(uint256 q);
        error Fold(uint256 layer, uint256 q);
        error LastLayer(uint256 q);

        function verify(bytes32 prevRoot, bytes32 newRoot, bytes txs, StarkProof proof) external view returns (bool);
    }

    #[derive(Debug, PartialEq, Eq)]
    interface IZKRollup {
        event BatchCommitted(uint256 indexed index, bytes32 indexed newRoot, bytes32 txHash, bytes txs);
        event BatchFinalized(uint256 indexed index, bytes32 indexed newRoot, address indexed prover);
        event BatchesReverted(uint256 fromIndex, uint256 toIndex);

        error NotSequencer();
        error BadTxData();
        error UnknownBatch(uint256 index);
        error OutOfOrder(uint256 expected);
        error TxDataMismatch(bytes32 committed, bytes32 given);
        error CannotRevert(uint256 index);

        function commitBatch(bytes txs, bytes32 newRoot) external returns (uint256 index);
        function finalizeBatch(uint256 index, bytes txs, StarkProof proof) external;
        function revertBatches(uint256 fromIndex) external;
        function stateRoot() external view returns (bytes32);
        function genesisRoot() external view returns (bytes32);
        function headRoot() external view returns (bytes32);
        function committed() external view returns (uint256);
        function finalized() external view returns (uint256);
        function sequencer() external view returns (address);
        function verifier() external view returns (address);
    }
}

pub use IStarkVerifier::verifyCall;

/// Maps a `StarkVerifier` revert to the native reject reason.
pub fn reject_from_revert(data: &[u8]) -> Option<super::StarkReject> {
    use super::StarkReject as R;
    use IStarkVerifier::IStarkVerifierErrors as E;
    use alloy_sol_types::SolInterface;
    let u = |x: alloy_primitives::U256| x.to::<usize>();
    Some(match E::abi_decode(data).ok()? {
        E::BatchSize(e) => R::BatchSize { n: u(e.n) },
        E::BadAccount(e) => R::BadAccount { index: u(e.index) },
        E::Shape(e) => R::Shape { what: R::SHAPES.get(e.what as usize)? },
        E::NonCanonical(e) => R::NonCanonical { what: R::CANON.get(e.what as usize)? },
        E::Pow(_) => R::Pow,
        E::Ood(_) => R::Ood,
        E::Degenerate(_) => R::Degenerate,
        E::TraceMerkle(_) => R::TraceMerkle,
        E::CompMerkle(_) => R::CompMerkle,
        E::FriMerkle(e) => R::FriMerkle { layer: u(e.layer) },
        E::Deep(e) => R::Deep { q: u(e.q) },
        E::Fold(e) => R::Fold { layer: u(e.layer), q: u(e.q) },
        E::LastLayer(e) => R::LastLayer { q: u(e.q) },
    })
}

impl Proof {
    pub fn to_abi(&self) -> StarkProof {
        let f = |v: &[F]| v.iter().map(to_u256).collect::<Vec<U256>>();
        StarkProof {
            traceRoot: self.trace_root,
            compRoot: self.comp_root,
            ood: f(&self.ood),
            friRoots: self.fri_roots.clone(),
            lastLayer: f(&self.last_layer),
            powNonce: U256::from(self.pow_nonce),
            traceVals: f(&self.trace_vals),
            traceDecommit: self.trace_decommit.clone(),
            compVals: f(&self.comp_vals),
            compDecommit: self.comp_decommit.clone(),
            friVals: f(&self.fri_vals),
            friDecommit: self.fri_decommit.concat(),
            friDecommitLen: self.fri_decommit.iter().map(|d| U256::from(d.len())).collect(),
        }
    }

    /// Calldata for `StarkVerifier.verify(prevRoot, newRoot, txs, proof)`.
    pub fn calldata(&self, prev: &F, new: &F, txs: &[u8]) -> Vec<u8> {
        use alloy_sol_types::SolCall;
        verifyCall { prevRoot: to_b256(prev), newRoot: to_b256(new), txs: txs.to_vec().into(), proof: self.to_abi() }.abi_encode()
    }

    /// Bytes of calldata the proof costs on L1.
    pub fn size(&self) -> usize {
        use alloy_sol_types::SolValue;
        self.to_abi().abi_encode().len()
    }
}
