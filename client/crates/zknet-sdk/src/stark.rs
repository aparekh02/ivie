//! The rollup's STARK verifier as a raw oracle.
//!
//!   O(prevRoot, newRoot, txs, proof) -> Ok | Err(reason)
//!
//! The reason is the first check that failed (Pow, Ood, TraceMerkle, Fold, ...).
//! [`Native`] and [`Chain`] give the same reason for the same input; that is
//! what `tests/stark_oracle.rs` checks.
//!
//! Everything in `zknet_core::stark` is re-exported: the field, the in-AIR
//! hash, the state tree, the AIR (trace layout and constraints), the
//! prover (with adversarial [`Options`]), the channel, Merkle and FRI.

pub use zknet_core::stark::*;

use crate::{Error, Zknet};
use zknet_core::{Address, B256};
use serde_json::{Value, json};

/// One statement + proof, in the verifier's raw ABI form.
#[derive(Clone, Debug)]
pub struct Claim {
    pub prev: B256,
    pub new: B256,
    pub txs: Vec<u8>,
    pub proof: StarkProof,
}

impl Claim {
    pub fn from_proven(p: &Proven) -> Self {
        Claim {
            prev: field::to_b256(&p.public.prev_root),
            new: field::to_b256(&p.public.new_root),
            txs: state::encode_txs(&p.public.txs),
            proof: p.proof.to_abi(),
        }
    }

    pub fn calldata(&self) -> Vec<u8> {
        use alloy_sol_types::SolCall;
        proof::verifyCall { prevRoot: self.prev, newRoot: self.new, txs: self.txs.clone().into(), proof: self.proof.clone() }.abi_encode()
    }
}

pub type Verdict = std::result::Result<(), StarkReject>;

pub trait Oracle {
    fn ask(&mut self, c: &Claim) -> Verdict;
    fn queries(&self) -> u64;
}

/// In-process verifier (`zknet_core::stark::verify`).
#[derive(Default)]
pub struct Native {
    n: u64,
    /// Challenges of the last accepted query (α, z, γ, β_i, positions).
    pub last: Option<verifier::Challenges>,
}

impl Oracle for Native {
    fn ask(&mut self, c: &Claim) -> Verdict {
        self.n += 1;
        let r = verify(c.prev, c.new, &c.txs, &c.proof);
        self.last = r.as_ref().ok().cloned();
        r.map(|_| ())
    }
    fn queries(&self) -> u64 {
        self.n
    }
}

/// The deployed `StarkVerifier`, by `eth_call` through zknetd.
pub struct Chain {
    pub conn: Zknet,
    pub verifier: Address,
    pub gas: u64,
    n: u64,
}

impl Chain {
    /// Uses the CREATE2 address from `contracts/out` (deploy with `zkrollup deploy`).
    pub fn new(conn: Zknet) -> std::io::Result<Self> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        Ok(Chain { conn, verifier: deploy::addresses(&root)?.verifier.0, gas: 16_000_000, n: 0 })
    }

    /// Raw eth_call: Ok(return data) or the revert decoded as a reject reason.
    pub fn call(&mut self, c: &Claim) -> crate::Result<std::result::Result<Vec<u8>, Option<StarkReject>>> {
        let data = zknet_core::Bytes::from(c.calldata());
        let req = json!([{ "to": self.verifier, "data": data, "gas": format!("0x{:x}", self.gas) }, "latest"]);
        match self.conn.eth::<zknet_core::Bytes>("eth_call", req) {
            Ok(b) => Ok(Ok(b.to_vec())),
            Err(Error::Rpc { data: Some(Value::String(d)), .. }) => {
                let bytes: zknet_core::Bytes = d.parse().unwrap_or_default();
                Ok(Err(proof::reject_from_revert(&bytes)))
            }
            Err(e) => Err(e),
        }
    }
}

impl Oracle for Chain {
    fn ask(&mut self, c: &Claim) -> Verdict {
        self.n += 1;
        match self.call(c).expect("eth_call") {
            Ok(_) => Ok(()),
            Err(Some(r)) => Err(r),
            Err(None) => panic!("verifier reverted without a StarkVerifier error (out of gas?)"),
        }
    }
    fn queries(&self) -> u64 {
        self.n
    }
}
