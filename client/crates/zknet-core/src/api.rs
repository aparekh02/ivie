//! Wire types of the zknetd socket (newline-delimited JSON-RPC 2.0).

use crate::stark::StarkReject;
use alloy_primitives::{Address, B256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Head {
    pub number: u64,
    pub hash: B256,
    pub timestamp: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_fee: Option<u64>,
    pub tx_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    pub name: String,
    pub url: String,
    pub up: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardfork: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<Head>,
    pub rollup_deployed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub version: String,
    pub socket: String,
    pub default_node: String,
    pub rollup: Address,
    pub verifier: Address,
    pub nodes: Vec<NodeStatus>,
}

/// `zk_rollup`: the L1 contract's view.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RollupView {
    pub node: String,
    pub committed: u64,
    pub finalized: u64,
    pub state_root: B256,
    pub head_root: B256,
}

/// One verifier's answer to `zk_verify`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Verdict {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<StarkRejectWire>,
    /// Native: verify time. On-chain: gas of the eth_call (if estimated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub micros: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas: Option<u64>,
}

/// A reject reason as it travels on the wire (the `Display` text plus the variant).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StarkRejectWire {
    pub kind: serde_json::Value,
    pub message: String,
}

impl From<&StarkReject> for StarkRejectWire {
    fn from(r: &StarkReject) -> Self {
        StarkRejectWire { kind: serde_json::to_value(r).unwrap_or_default(), message: r.to_string() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResult {
    pub native: Verdict,
    pub onchain: Verdict,
    /// Both accepted, or both rejected for the same reason.
    pub agree: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ChainEvent {
    #[serde(rename_all = "camelCase")]
    Head { node: String, head: Head },
    #[serde(rename_all = "camelCase")]
    BatchCommitted { node: String, block: u64, tx: B256, index: u64, new_root: B256, tx_hash: B256, n_txs: usize },
    #[serde(rename_all = "camelCase")]
    BatchFinalized { node: String, block: u64, tx: B256, index: u64, new_root: B256, prover: Address },
    #[serde(rename_all = "camelCase")]
    BatchesReverted { node: String, block: u64, tx: B256, from: u64, to: u64 },
}

impl ChainEvent {
    pub fn node(&self) -> &str {
        match self {
            ChainEvent::Head { node, .. }
            | ChainEvent::BatchCommitted { node, .. }
            | ChainEvent::BatchFinalized { node, .. }
            | ChainEvent::BatchesReverted { node, .. } => node,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    pub subscription: String,
    pub result: ChainEvent,
}
