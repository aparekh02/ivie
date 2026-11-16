//! The plug-in socket: newline-delimited JSON-RPC 2.0 over a Unix domain socket.
//!
//!   zk_status                    nodes, heads, contract addresses
//!   zk_rollup                    committed / finalized batches, roots (L1 view)
//!   zk_verify {calldata}         StarkVerifier.verify calldata, checked natively
//!                                and by eth_call; reports both reasons + agree
//!   zk_subscribe [topic, {node}] heads | events | all -> zk_subscription notifications
//!   eth_* net_* web3_* anvil_* evm_* debug_* trace_* txpool_*   forwarded

use crate::node::Node;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};
use zknet_core::api::*;
use zknet_core::stark::proof::{IZKRollup, reject_from_revert, verifyCall};

/// EIP-7825 per-tx gas cap; eth_calls use it too.
const GAS_CAP: u64 = 1 << 24;

pub struct Server {
    pub nodes: Vec<Arc<Node>>,
    pub rollup: Address,
    pub verifier: Address,
    pub socket: String,
    pub events: broadcast::Sender<ChainEvent>,
    next_sub: AtomicU64,
}

/// A JSON-RPC error.
pub struct RpcErr {
    code: i64,
    message: String,
    data: Option<Value>,
}
impl RpcErr {
    fn params(m: impl std::fmt::Display) -> Self {
        RpcErr { code: -32602, message: m.to_string(), data: None }
    }
}
impl<E: Into<anyhow::Error>> From<E> for RpcErr {
    fn from(e: E) -> Self {
        RpcErr { code: -32000, message: format!("{:#}", e.into()), data: None }
    }
}
type Res<T = Value> = Result<T, RpcErr>;

const FORWARD: &[&str] = &["eth_", "net_", "web3_", "anvil_", "evm_", "debug_", "trace_", "txpool_"];

impl Server {
    pub fn new(nodes: Vec<Arc<Node>>, rollup: Address, verifier: Address, socket: String, events: broadcast::Sender<ChainEvent>) -> Arc<Self> {
        Arc::new(Server { nodes, rollup, verifier, socket, events, next_sub: AtomicU64::new(1) })
    }

    pub async fn serve(self: Arc<Self>, listener: UnixListener) -> anyhow::Result<()> {
        loop {
            let (stream, _) = listener.accept().await?;
            let me = self.clone();
            tokio::spawn(async move {
                if let Err(e) = me.connection(stream).await {
                    tracing::debug!(error = %e, "connection closed");
                }
            });
        }
    }

    async fn connection(self: Arc<Self>, stream: UnixStream) -> anyhow::Result<()> {
        let (rd, mut wr) = stream.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let writer = tokio::spawn(async move {
            while let Some(mut line) = rx.recv().await {
                line.push('\n');
                if wr.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        let subs: Arc<std::sync::Mutex<HashMap<String, tokio::task::JoinHandle<()>>>> = Arc::default();
        let mut lines = BufReader::new(rd).lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let (me, tx, subs) = (self.clone(), tx.clone(), subs.clone());
            // each request runs on its own task, so a slow tx doesn't block the connection
            tokio::spawn(async move {
                let reply = me.handle_line(&line, &tx, &subs).await;
                let _ = tx.send(reply.to_string());
            });
        }
        for (_, h) in subs.lock().unwrap().drain() {
            h.abort();
        }
        drop(tx);
        let _ = writer.await;
        Ok(())
    }

    async fn handle_line(
        self: &Arc<Self>,
        line: &str,
        out: &mpsc::UnboundedSender<String>,
        subs: &Arc<std::sync::Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
    ) -> Value {
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => return json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("parse error: {e}")}}),
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(Value::as_str).unwrap_or_default().to_string();
        let params = req.get("params").cloned().unwrap_or(Value::Null);
        let node = req.get("node").and_then(Value::as_str).map(String::from);
        let t0 = Instant::now();
        let res = match method.as_str() {
            "zk_subscribe" => self.subscribe(&params, out, subs),
            "zk_unsubscribe" => {
                let sid = params.get(0).and_then(Value::as_str).unwrap_or_default();
                let found = subs.lock().unwrap().remove(sid).map(|h| h.abort()).is_some();
                Ok(json!(found))
            }
            _ => self.dispatch(&method, params, node).await,
        };
        tracing::debug!(%method, ms = t0.elapsed().as_millis() as u64, ok = res.is_ok(), "request");
        match res {
            Ok(v) => json!({"jsonrpc":"2.0","id":id,"result":v}),
            Err(e) => {
                let mut err = json!({"code":e.code,"message":e.message});
                if let Some(d) = e.data {
                    err["data"] = d;
                }
                json!({"jsonrpc":"2.0","id":id,"error":err})
            }
        }
    }

    async fn dispatch(&self, method: &str, params: Value, node: Option<String>) -> Res {
        let pick = params.get("node").and_then(Value::as_str).map(String::from).or(node);
        match method {
            "zk_status" => Ok(serde_json::to_value(self.status().await)?),
            "zk_rollup" => Ok(serde_json::to_value(self.rollup_view(self.node(pick.as_deref())?).await?)?),
            "zk_verify" => Ok(serde_json::to_value(self.verify(self.node(pick.as_deref())?, &params).await?)?),
            m if FORWARD.iter().any(|pre| m.starts_with(pre)) => self.forward(m, params, pick.as_deref()).await,
            m => Err(RpcErr { code: -32601, message: format!("method not found: {m}"), data: None }),
        }
    }

    fn node(&self, name: Option<&str>) -> Res<&Arc<Node>> {
        match name {
            None => Ok(&self.nodes[0]),
            Some(n) => self.nodes.iter().find(|x| x.name == n || x.url == n).ok_or_else(|| {
                RpcErr::params(format!("unknown node {n:?} (have: {})", self.nodes.iter().map(|x| x.name.as_str()).collect::<Vec<_>>().join(", ")))
            }),
        }
    }

    async fn status(&self) -> Status {
        let mut nodes = Vec::with_capacity(self.nodes.len());
        for n in &self.nodes {
            nodes.push(n.status().await);
        }
        Status {
            version: env!("CARGO_PKG_VERSION").into(),
            socket: self.socket.clone(),
            default_node: self.nodes[0].name.clone(),
            rollup: self.rollup,
            verifier: self.verifier,
            nodes,
        }
    }

    async fn view<C: SolCall>(&self, node: &Node, to: Address, c: C) -> anyhow::Result<C::Return> {
        let tx = TransactionRequest::default().with_to(to).with_input(c.abi_encode());
        Ok(C::abi_decode_returns(&node.provider.call(tx).await?)?)
    }

    async fn rollup_view(&self, node: &Node) -> Res<RollupView> {
        node.ready().await?;
        let r = self.rollup;
        Ok(RollupView {
            node: node.name.clone(),
            committed: self.view(node, r, IZKRollup::committedCall {}).await?.to(),
            finalized: self.view(node, r, IZKRollup::finalizedCall {}).await?.to(),
            state_root: self.view(node, r, IZKRollup::stateRootCall {}).await?,
            head_root: self.view(node, r, IZKRollup::headRootCall {}).await?,
        })
    }

    /// Runs the native verifier and the deployed StarkVerifier (eth_call) on
    /// the same `verify(prevRoot, newRoot, txs, proof)` calldata.
    async fn verify(&self, node: &Node, params: &Value) -> Res<VerifyResult> {
        let cd: Bytes = from(params.get("calldata").cloned().ok_or_else(|| RpcErr::params("pass {calldata}"))?)?;
        let call = verifyCall::abi_decode(&cd).map_err(RpcErr::params)?;
        node.ready().await?;
        let t = Instant::now();
        let n = zknet_core::stark::verify(call.prevRoot, call.newRoot, &call.txs, &call.proof);
        let native = Verdict {
            ok: n.is_ok(),
            reason: n.as_ref().err().map(StarkRejectWire::from),
            micros: Some(t.elapsed().as_micros() as u64),
            gas: None,
        };
        let tx = TransactionRequest::default().with_to(self.verifier).with_input(cd.to_vec()).with_gas_limit(GAS_CAP);
        let onchain = match node.provider.call(tx.clone()).await {
            Ok(_) => Verdict { ok: true, reason: None, micros: None, gas: node.provider.estimate_gas(tx).await.ok() },
            Err(e) => {
                let data = e.as_error_resp().and_then(|r| r.as_revert_data()).ok_or_else(|| RpcErr::from(e))?;
                let r = reject_from_revert(&data).ok_or_else(|| RpcErr::params(format!("unrecognized revert 0x{}", alloy::hex::encode(&data))))?;
                Verdict { ok: false, reason: Some(StarkRejectWire::from(&r)), micros: None, gas: None }
            }
        };
        let agree = native.ok == onchain.ok && native.reason == onchain.reason;
        if !agree {
            tracing::warn!(?native, ?onchain, "native and on-chain STARK verifiers disagree");
        }
        Ok(VerifyResult { native, onchain, agree })
    }

    async fn forward(&self, method: &str, params: Value, node: Option<&str>) -> Res {
        let node = self.node(node)?;
        let params = if params.is_null() { json!([]) } else { params };
        match node.provider.raw_request::<Value, Value>(method.to_string().into(), params).await {
            Ok(v) => Ok(v),
            Err(e) => match e.as_error_resp() {
                Some(p) => Err(RpcErr { code: p.code, message: p.message.to_string(), data: p.data.as_ref().and_then(|d| serde_json::from_str(d.get()).ok()) }),
                None => Err(e.into()),
            },
        }
    }

    fn subscribe(
        self: &Arc<Self>,
        params: &Value,
        out: &mpsc::UnboundedSender<String>,
        subs: &Arc<std::sync::Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
    ) -> Res {
        let topic = params.get(0).and_then(Value::as_str).unwrap_or("events").to_string();
        let only_node = params.get(1).and_then(|v| v.get("node")).and_then(Value::as_str).map(String::from);
        if !["heads", "events", "all"].contains(&topic.as_str()) {
            return Err(RpcErr::params("topic must be heads, events, or all"));
        }
        let sid = format!("0x{:x}", self.next_sub.fetch_add(1, Ordering::Relaxed));
        let mut rx = self.events.subscribe();
        let (out, s2) = (out.clone(), sid.clone());
        let h = tokio::spawn(async move {
            loop {
                let ev = match rx.recv().await {
                    Ok(ev) => ev,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                };
                let is_head = matches!(ev, ChainEvent::Head { .. });
                if only_node.as_ref().is_some_and(|n| n != ev.node()) || (topic == "heads" && !is_head) || (topic == "events" && is_head) {
                    continue;
                }
                let msg = json!({"jsonrpc":"2.0","method":"zk_subscription","params":Notification { subscription: s2.clone(), result: ev }});
                if out.send(msg.to_string()).is_err() {
                    break;
                }
            }
        });
        subs.lock().unwrap().insert(sid.clone(), h);
        Ok(json!(sid))
    }
}

fn from<T: serde::de::DeserializeOwned>(v: Value) -> Res<T> {
    serde_json::from_value(v).map_err(RpcErr::params)
}
