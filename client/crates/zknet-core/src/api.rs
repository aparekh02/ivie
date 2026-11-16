//! Wire types for the `zknetd` socket protocol.
//!
//! Transport: a Unix domain socket carrying newline-delimited JSON-RPC 2.0.
//! Each request is one JSON object on one line, and so is each response.
//! Any language can connect (`nc -U`, `socat`, Python's `socket`).
//!
//! Methods (params are a JSON object unless noted):
//!
//! | method | what it does |
//! |---|---|
//! | `zk_status` | nodes, heads, registry address, signer |
//! | `zk_circuitId` | `{vk}` or `{rawVk, curve}`: id, raw VK, nPublic (no chain) |
//! | `zk_encode` | `{proof, curve}`: proof bytes (no chain) |
//! | `zk_verifyLocal` | [`VerifyParams`] checked by the native verifier only (no chain) |
//! | `zk_circuit` | `{circuitId}`: on-chain registration |
//! | `zk_register` | [`RegisterParams`]: register a VK (signed tx) |
//! | `zk_verify` | [`VerifyParams`]: native + `eth_call verify` + gas, and whether they agree |
//! | `zk_submit` | [`VerifyParams`]: `submit()` tx (pre-simulated; `force` sends anyway) |
//! | `zk_subscribe` | `["heads" \| "events"]`: pushes `zk_subscription` notifications |
//! | `eth_*`, `net_*`, `web3_*`, `anvil_*`, `evm_*`, `debug_*`, `trace_*`, `txpool_*` | forwarded to the node unchanged (params: JSON array) |
//!
//! Every method takes an optional `node` (a name such as `"fast"`/`"strict"`).
//! For forwarded methods, pick the node with `"node"` at the top level of
//! the request, next to `"method"`.

use crate::encode::Curve;
use crate::snarkjs::{SnarkjsProof, SnarkjsVk};
use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};

/// A proof as snarkjs JSON or as the on-chain hex bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProofArg {
    Hex(Bytes),
    Snarkjs(SnarkjsProof),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Name the circuit in one of three ways: a snarkjs VK, raw VK bytes plus
    /// a curve, or the id of an already-registered circuit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vk: Option<SnarkjsVk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_vk: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<Curve>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_id: Option<B256>,
    pub proof: ProofArg,
    /// Decimal or 0x-hex strings. Values >= r are allowed here on purpose, so
    /// you can watch the verifier reject them.
    #[serde(alias = "inputs")]
    pub public_signals: Vec<String>,
    /// Register the VK first if the registry doesn't know it.
    #[serde(default)]
    pub register: bool,
    /// zk_submit only: send the tx even if simulation says it reverts.
    #[serde(default)]
    pub force: bool,
    /// Gas limit for the eth_call / tx (default: 2^24, the EIP-7825 cap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vk: Option<SnarkjsVk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_vk: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<Curve>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Send even if the native VK check or simulation says it will revert.
    #[serde(default)]
    pub force: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LocalVerdict {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The contract would revert on this input rather than return false.
    pub reverts: bool,
    pub micros: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OnchainVerdict {
    /// `None` when the call reverted.
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas: Option<u64>,
    pub block: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TxInfo {
    pub hash: B256,
    pub block: u64,
    pub gas_used: u64,
    pub success: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResult {
    pub node: String,
    pub circuit_id: B256,
    pub curve: Curve,
    pub n_public: usize,
    pub proof: Bytes,
    pub inputs: Vec<U256>,
    pub local: LocalVerdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onchain: Option<OnchainVerdict>,
    /// The native verdict matches the chain's (both accept, both reject, or
    /// both revert).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agree: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<TxInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitResult {
    pub node: String,
    pub circuit_id: B256,
    pub inputs_hash: B256,
    pub local: LocalVerdict,
    /// Revert reason from simulation (or from the mined tx).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx: Option<TxInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<TxInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResult {
    pub node: String,
    pub circuit_id: B256,
    pub curve: Curve,
    pub n_public: usize,
    pub already_registered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx: Option<TxInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitIdResult {
    pub circuit_id: B256,
    pub curve: Curve,
    pub n_public: usize,
    pub raw_vk: Bytes,
    /// Native `prepare()` check: `None` if the registry would accept the VK.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vk_problem: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CircuitInfo {
    pub node: String,
    pub circuit_id: B256,
    pub registered: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub curve: Option<Curve>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n_public: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vk_pointer: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registrant: Option<Address>,
    /// Raw VK recovered from the stored prepared VK (its id matches `circuit_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_vk: Option<Bytes>,
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
    pub registry: Address,
    pub registry_deployed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub version: String,
    pub socket: String,
    pub default_node: String,
    pub signer: Address,
    pub nodes: Vec<NodeStatus>,
}

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

/// Payload of a `zk_subscription` notification.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ChainEvent {
    #[serde(rename_all = "camelCase")]
    Head { node: String, head: Head },
    #[serde(rename_all = "camelCase")]
    CircuitRegistered { node: String, block: u64, tx: B256, circuit_id: B256, curve: Curve, n_public: U256, registrant: Address, label: String },
    #[serde(rename_all = "camelCase")]
    ProofVerified { node: String, block: u64, tx: B256, circuit_id: B256, inputs_hash: B256, submitter: Address, inputs: Vec<U256> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    pub subscription: String,
    pub result: ChainEvent,
}
