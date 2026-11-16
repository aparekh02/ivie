//! zknet-sdk: the rollup's STARK verifier as a raw oracle, and the zknetd socket.
//!
//!   O(prevRoot, newRoot, txs, proof) -> Ok | Err(first failed check)
//!
//! * [`stark`]: [`stark::Native`] (in process) and [`stark::Chain`] (the
//!   deployed `StarkVerifier`, by eth_call through zknetd) give the same
//!   reason for the same input. Everything in `zknet_core::stark` (field,
//!   hash, state tree, AIR, prover with adversarial options, channel,
//!   Merkle, FRI) is re-exported there.
//! * [`Zknet`]: the bare socket (any method, raw JSON) and event subscriptions.

pub mod stark;

pub use zknet_core as core;

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

// ------------------------------------------------------------------ socket

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("socket {path}: {source} (is zknetd running? `npm run zknetd`)")]
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

/// The bare socket: one JSON-RPC line out, one line back.
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

    /// Route requests to this node (`"fast"` / `"strict"`).
    pub fn on(mut self, node: &str) -> Self {
        self.node = Some(node.into());
        self
    }

    pub fn request<T: DeserializeOwned>(&mut self, method: &str, mut params: Value) -> Result<T> {
        let id = self.next_id;
        self.next_id += 1;
        if let (Some(n), Some(o)) = (&self.node, params.as_object_mut()) {
            o.entry("node").or_insert(json!(n));
        }
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
                continue;
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

    /// Forwarded JSON-RPC (`eth_*`, `anvil_*`, `evm_*`, `debug_*`, ...).
    pub fn eth<T: DeserializeOwned>(&mut self, method: &str, params: Value) -> Result<T> {
        self.request(method, params)
    }

    pub fn snapshot(&mut self) -> Result<String> {
        self.eth("evm_snapshot", json!([]))
    }

    pub fn revert(&mut self, snapshot: &str) -> Result<bool> {
        self.eth("evm_revert", json!([snapshot]))
    }

    /// Turns this connection into a stream of `zk_subscription` payloads
    /// (`"heads"`, `"events"`, `"all"`).
    pub fn subscribe(mut self, topic: &str) -> Result<Subscription> {
        let params = match &self.node {
            Some(n) => json!([topic, { "node": n }]),
            None => json!([topic]),
        };
        let id: String = self.request("zk_subscribe", params)?;
        Ok(Subscription { conn: self, id })
    }
}

pub struct Subscription {
    conn: Zknet,
    pub id: String,
}

impl Iterator for Subscription {
    type Item = Result<zknet_core::api::ChainEvent>;
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
