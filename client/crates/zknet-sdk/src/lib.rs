//! Blocking client for the `zknetd` socket.
//!
//! ```no_run
//! use zknet_sdk::{Zknet, Req};
//! use zknet_sdk::core::{SnarkjsVk, SnarkjsProof};
//!
//! let vk = SnarkjsVk::from_file("vk.json")?;
//! let proof = SnarkjsProof::from_file("proof.json")?;
//! let mut zk = Zknet::connect()?;
//! let r = zk.verify(Req::snarkjs(&vk, &proof, &["33"]).register(true))?;
//! assert!(r.local.ok && r.onchain.unwrap().ok == Some(true));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! No async runtime is needed. Each [`Zknet`] is one socket connection.
//! Open several if you want concurrency (the daemon serves them in parallel).

pub use zknet_core as core;
pub use zknet_core::api::{
    ChainEvent, CircuitIdResult, CircuitInfo, Head, LocalVerdict, OnchainVerdict, ProofArg, RegisterParams, RegisterResult, Status,
    SubmitResult, TxInfo, VerifyParams, VerifyResult,
};
use zknet_core::{B256, Bytes, Curve, SnarkjsProof, SnarkjsVk, U256};

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("socket {path}: {source} (is zknetd running? `cargo run --release -p zknetd`)")]
    Connect { path: PathBuf, source: std::io::Error },
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("rpc error {code}: {message}")]
    Rpc { code: i64, message: String, data: Option<Value> },
    #[error("zknetd closed the connection")]
    Closed,
}
pub type Result<T> = std::result::Result<T, Error>;

/// `$ZKNETD_SOCKET`, else `<repo>/chain/.run/zknetd.sock`.
pub fn default_socket() -> PathBuf {
    std::env::var_os("ZKNETD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../chain/.run/zknetd.sock"))
}

pub struct Zknet {
    w: UnixStream,
    r: BufReader<UnixStream>,
    next_id: u64,
    node: Option<String>,
}

impl Zknet {
    pub fn connect() -> Result<Self> {
        Self::connect_to(default_socket())
    }

    pub fn connect_to(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let w = UnixStream::connect(path).map_err(|source| Error::Connect { path: path.into(), source })?;
        let r = BufReader::new(w.try_clone()?);
        Ok(Zknet { w, r, next_id: 1, node: None })
    }

    /// Send requests to this node by default (e.g. `"strict"` for 12 s slots).
    pub fn on(mut self, node: &str) -> Self {
        self.node = Some(node.into());
        self
    }

    /// Any method, raw. `params` is an object for `zk_*`, an array for `eth_*` etc.
    pub fn request<T: DeserializeOwned>(&mut self, method: &str, params: Value) -> Result<T> {
        let id = self.next_id;
        self.next_id += 1;
        let mut req = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        if let Some(n) = &self.node {
            req["node"] = json!(n);
        }
        let mut line = req.to_string();
        line.push('\n');
        self.w.write_all(line.as_bytes())?;
        loop {
            let v = self.read_msg()?;
            if v.get("id").and_then(Value::as_u64) != Some(id) {
                continue; // a stray notification
            }
            if let Some(e) = v.get("error") {
                return Err(Error::Rpc {
                    code: e["code"].as_i64().unwrap_or(-32000),
                    message: e["message"].as_str().unwrap_or_default().to_string(),
                    data: e.get("data").cloned(),
                });
            }
            return Ok(serde_json::from_value(v.get("result").cloned().unwrap_or(Value::Null))?);
        }
    }

    fn read_msg(&mut self) -> Result<Value> {
        let mut line = String::new();
        if self.r.read_line(&mut line)? == 0 {
            return Err(Error::Closed);
        }
        Ok(serde_json::from_str(&line)?)
    }

    fn zk<T: DeserializeOwned, P: serde::Serialize>(&mut self, method: &str, p: P) -> Result<T> {
        let mut v = serde_json::to_value(p)?;
        if let (Some(n), Some(o)) = (&self.node, v.as_object_mut()) {
            o.entry("node").or_insert(json!(n));
        }
        self.request(method, v)
    }

    pub fn status(&mut self) -> Result<Status> {
        self.request("zk_status", json!({}))
    }

    /// Native verifier only. Doesn't touch the chain unless the request names a circuit by id.
    pub fn verify_local(&mut self, req: Req) -> Result<LocalVerdict> {
        self.zk("zk_verifyLocal", req.0)
    }

    /// Native verifier and `eth_call verify` (plus gas), and whether they agree.
    pub fn verify(&mut self, req: Req) -> Result<VerifyResult> {
        self.zk("zk_verify", req.0)
    }

    /// `submit()` as a signed tx. It is simulated first, and a tx that would
    /// revert is not sent unless `.force(true)`.
    pub fn submit(&mut self, req: Req) -> Result<SubmitResult> {
        self.zk("zk_submit", req.0)
    }

    pub fn register(&mut self, vk: &SnarkjsVk, label: &str) -> Result<RegisterResult> {
        self.zk("zk_register", RegisterParams { vk: Some(vk.clone()), label: Some(label.into()), ..Default::default() })
    }

    pub fn register_raw(&mut self, curve: Curve, raw_vk: &[u8], label: &str) -> Result<RegisterResult> {
        self.zk("zk_register", RegisterParams { raw_vk: Some(raw_vk.to_vec().into()), curve: Some(curve), label: Some(label.into()), ..Default::default() })
    }

    pub fn circuit(&mut self, id: B256) -> Result<CircuitInfo> {
        self.zk("zk_circuit", json!({ "circuitId": id }))
    }

    /// Forwarded JSON-RPC (`eth_*`, `anvil_*`, `evm_*`, `debug_*`, ...).
    pub fn eth<T: DeserializeOwned>(&mut self, method: &str, params: Value) -> Result<T> {
        self.request(method, params)
    }

    pub fn block_number(&mut self) -> Result<u64> {
        let h: String = self.eth("eth_blockNumber", json!([]))?;
        Ok(u64::from_str_radix(h.trim_start_matches("0x"), 16).unwrap_or_default())
    }

    /// `evm_snapshot`. Pair it with [`Zknet::revert`] to try state-changing
    /// things (submit, register) and roll the chain back afterwards.
    pub fn snapshot(&mut self) -> Result<String> {
        self.eth("evm_snapshot", json!([]))
    }

    pub fn revert(&mut self, snapshot: &str) -> Result<bool> {
        self.eth("evm_revert", json!([snapshot]))
    }

    /// Mine `n` blocks now (anvil_mine).
    pub fn mine(&mut self, n: u64) -> Result<()> {
        let _: Value = self.eth("anvil_mine", json!([format!("0x{n:x}")]))?;
        Ok(())
    }

    /// Turns this connection into an event stream. `topic` is `"heads"`,
    /// `"events"` (registry CircuitRegistered / ProofVerified), or `"all"`.
    pub fn subscribe(mut self, topic: &str) -> Result<Subscription> {
        let params = match &self.node {
            Some(n) => json!([topic, { "node": n }]),
            None => json!([topic]),
        };
        let id: String = self.request("zk_subscribe", params)?;
        Ok(Subscription { conn: self, id })
    }
}

/// Blocking iterator over `zk_subscription` notifications.
pub struct Subscription {
    conn: Zknet,
    pub id: String,
}

impl Iterator for Subscription {
    type Item = Result<ChainEvent>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let v = match self.conn.read_msg() {
                Ok(v) => v,
                Err(Error::Closed) => return None,
                Err(e) => return Some(Err(e)),
            };
            if v.get("method").and_then(Value::as_str) == Some("zk_subscription") && v["params"]["subscription"] == self.id {
                return Some(serde_json::from_value(v["params"]["result"].clone()).map_err(Error::from));
            }
        }
    }
}

/// Builder for verify / submit requests.
#[derive(Clone, Debug)]
pub struct Req(pub VerifyParams);

impl Req {
    fn base(proof: ProofArg, inputs: Vec<String>) -> Self {
        Req(VerifyParams {
            node: None,
            vk: None,
            raw_vk: None,
            curve: None,
            circuit_id: None,
            proof,
            public_signals: inputs,
            register: false,
            force: false,
            gas: None,
        })
    }

    /// snarkjs-format VK + proof + public signals.
    pub fn snarkjs(vk: &SnarkjsVk, proof: &SnarkjsProof, public: &[impl AsRef<str>]) -> Self {
        let mut r = Self::base(ProofArg::Snarkjs(proof.clone()), public.iter().map(|s| s.as_ref().to_string()).collect());
        r.0.vk = Some(vk.clone());
        r
    }

    /// On-chain bytes, straight from your prover (see `core::verify::bn254::proof_bytes`).
    pub fn raw(curve: Curve, raw_vk: &[u8], proof: &[u8], inputs: &[U256]) -> Self {
        let mut r = Self::base(ProofArg::Hex(Bytes::from(proof.to_vec())), inputs.iter().map(|x| format!("{x:#x}")).collect());
        r.0.raw_vk = Some(raw_vk.to_vec().into());
        r.0.curve = Some(curve);
        r
    }

    /// An already-registered circuit, by id. The daemon fetches the VK from chain.
    pub fn by_id(circuit_id: B256, proof: &[u8], inputs: &[U256]) -> Self {
        let mut r = Self::base(ProofArg::Hex(Bytes::from(proof.to_vec())), inputs.iter().map(|x| format!("{x:#x}")).collect());
        r.0.circuit_id = Some(circuit_id);
        r
    }

    /// Replace the public inputs (strings, so out-of-range values can be sent on purpose).
    pub fn inputs(mut self, inputs: &[impl AsRef<str>]) -> Self {
        self.0.public_signals = inputs.iter().map(|s| s.as_ref().to_string()).collect();
        self
    }
    pub fn proof_bytes(mut self, proof: &[u8]) -> Self {
        self.0.proof = ProofArg::Hex(proof.to_vec().into());
        self
    }
    /// Register the VK first if needed.
    pub fn register(mut self, yes: bool) -> Self {
        self.0.register = yes;
        self
    }
    /// zk_submit: send the tx even if simulation reverts (to see it mined).
    pub fn force(mut self, yes: bool) -> Self {
        self.0.force = yes;
        self
    }
    pub fn gas(mut self, gas: u64) -> Self {
        self.0.gas = Some(gas);
        self
    }
    pub fn node(mut self, node: &str) -> Self {
        self.0.node = Some(node.into());
        self
    }
}
