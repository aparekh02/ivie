//! The plug-in socket: newline-delimited JSON-RPC 2.0 over a Unix domain socket.

use crate::node::{DEFAULT_GAS, Node, call_req};
use crate::registry::{IZKVerifierRegistry as R, revert_data, revert_reason};
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{RwLock, broadcast, mpsc};
use zknet_core::api::*;
use zknet_core::{Curve, encode_proof, encode_vk, parse_u256};

pub struct Server {
    pub nodes: Vec<Arc<Node>>,
    pub signer: Address,
    pub socket: String,
    pub events: broadcast::Sender<ChainEvent>,
    /// circuit id -> (curve, raw vk). Content-addressed, so valid on every node.
    vk_cache: RwLock<HashMap<B256, (Curve, Vec<u8>)>>,
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

struct Circuit {
    id: B256,
    curve: Curve,
    raw_vk: Vec<u8>,
}

impl Server {
    pub fn new(nodes: Vec<Arc<Node>>, signer: Address, socket: String, events: broadcast::Sender<ChainEvent>) -> Arc<Self> {
        Arc::new(Server { nodes, signer, socket, events, vk_cache: RwLock::default(), next_sub: AtomicU64::new(1) })
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
        let p = |v: Value| -> Res<Value> { Ok(v) };
        match method {
            "zk_status" => p(serde_json::to_value(self.status().await)?),
            "zk_circuitId" => p(serde_json::to_value(self.circuit_id(params)?)?),
            "zk_encode" => self.encode(params),
            "zk_verifyLocal" => {
                let vp: VerifyParams = from(params)?;
                let node = self.node(vp.node.as_deref())?;
                let c = self.resolve(node, &vp).await?;
                let (proof, inputs) = proof_and_inputs(&c, &vp)?;
                p(serde_json::to_value(local(&c, &proof, &inputs))?)
            }
            "zk_circuit" => {
                let id: B256 = from(params.get("circuitId").cloned().unwrap_or(Value::Null))?;
                let node = self.node(params.get("node").and_then(Value::as_str).or(node.as_deref()))?;
                p(serde_json::to_value(self.circuit(node, id).await?)?)
            }
            "zk_register" => p(serde_json::to_value(self.register(from(params)?).await?)?),
            "zk_verify" => p(serde_json::to_value(self.verify(from(params)?).await?)?),
            "zk_submit" => p(serde_json::to_value(self.submit(from(params)?).await?)?),
            m if FORWARD.iter().any(|pre| m.starts_with(pre)) => self.forward(m, params, node.as_deref()).await,
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

    pub async fn status(&self) -> Status {
        let mut nodes = Vec::new();
        for n in &self.nodes {
            nodes.push(n.status().await);
        }
        Status { version: env!("CARGO_PKG_VERSION").into(), socket: self.socket.clone(), default_node: self.nodes[0].name.clone(), signer: self.signer, nodes }
    }

    // ------------------------------------------------------------- pure helpers

    fn circuit_id(&self, params: Value) -> Res<CircuitIdResult> {
        let (curve, raw) = vk_from(&params)?;
        let check = zknet_core::check_vk(curve, &raw);
        Ok(CircuitIdResult {
            circuit_id: zknet_core::circuit_id(curve, &raw),
            curve,
            n_public: curve.n_public_for_vk_len(raw.len()).unwrap_or_default(),
            raw_vk: raw.into(),
            vk_problem: check.err().map(|e| e.to_string()),
        })
    }

    fn encode(&self, params: Value) -> Res {
        let curve: Curve = from(params.get("curve").cloned().unwrap_or(json!("bn254")))?;
        let proof: ProofArg = from(params.get("proof").cloned().unwrap_or(Value::Null))?;
        let bytes = match proof {
            ProofArg::Hex(b) => b.to_vec(),
            ProofArg::Snarkjs(p) => encode_proof(&p, curve).map_err(RpcErr::params)?,
        };
        Ok(json!({ "curve": curve, "proof": Bytes::from(bytes) }))
    }

    /// Work out which circuit the request is about, fetching the VK from the
    /// chain when only an id is given.
    async fn resolve(&self, node: &Node, vp: &VerifyParams) -> Res<Circuit> {
        let given = match (&vp.vk, &vp.raw_vk, vp.curve) {
            (Some(vk), _, _) => Some(encode_vk(vk).map_err(RpcErr::params)?),
            (None, Some(raw), Some(c)) => Some((c, raw.to_vec())),
            (None, Some(_), None) => return Err(RpcErr::params("rawVk needs curve")),
            _ => None,
        };
        if let Some((curve, raw_vk)) = given {
            let id = zknet_core::circuit_id(curve, &raw_vk);
            if let Some(want) = vp.circuit_id
                && want != id {
                    return Err(RpcErr::params(format!("circuitId {want} does not match the VK (its id is {id})")));
                }
            return Ok(Circuit { id, curve, raw_vk });
        }
        let id = vp.circuit_id.ok_or_else(|| RpcErr::params("pass vk, rawVk+curve, or circuitId"))?;
        if let Some((curve, raw_vk)) = self.vk_cache.read().await.get(&id).cloned() {
            return Ok(Circuit { id, curve, raw_vk });
        }
        let info = self.circuit(node, id).await?;
        let raw_vk = info.raw_vk.ok_or_else(|| RpcErr::params(format!("circuit {id} is not registered on {}", node.name)))?.to_vec();
        let curve = info.curve.expect("registered circuit has a curve");
        self.vk_cache.write().await.insert(id, (curve, raw_vk.clone()));
        Ok(Circuit { id, curve, raw_vk })
    }

    async fn circuit(&self, node: &Node, id: B256) -> Res<CircuitInfo> {
        node.ready_for_reads().await?;
        let call = |data: Vec<u8>| node.provider.call(call_req(self.signer, node.registry, data, DEFAULT_GAS));
        let ret = call(R::circuitsCall { id }.abi_encode()).await?;
        let c = R::circuitsCall::abi_decode_returns(&ret).map_err(anyhow::Error::from)?;
        let mut info = CircuitInfo { node: node.name.clone(), circuit_id: id, registered: c.vk != Address::ZERO, curve: None, n_public: None, vk_pointer: None, registrant: None, raw_vk: None };
        if info.registered {
            let curve = Curve::from_id(c.curve).ok_or_else(|| anyhow::anyhow!("unknown curve id {}", c.curve))?;
            let prepared = R::vkOfCall::abi_decode_returns(&call(R::vkOfCall { id }.abi_encode()).await?).map_err(anyhow::Error::from)?;
            let raw = zknet_core::verify::unprepare_vk(curve, &prepared).map_err(|e| anyhow::anyhow!("stored VK: {e}"))?;
            debug_assert_eq!(zknet_core::circuit_id(curve, &raw), id);
            info = CircuitInfo { curve: Some(curve), n_public: Some(c.nPublic), vk_pointer: Some(c.vk), registrant: Some(c.registrant), raw_vk: Some(raw.into()), ..info };
        }
        Ok(info)
    }

    // ------------------------------------------------------------- chain methods

    async fn is_registered(&self, node: &Node, id: B256) -> Res<bool> {
        let ret = node.provider.call(call_req(self.signer, node.registry, R::circuitsCall { id }.abi_encode(), DEFAULT_GAS)).await?;
        Ok(R::circuitsCall::abi_decode_returns(&ret).map_err(anyhow::Error::from)?.vk != Address::ZERO)
    }

    /// eth_call, returning Ok(return data) or Err(revert reason).
    async fn simulate(&self, node: &Node, data: Vec<u8>, gas: u64) -> Res<Result<Bytes, String>> {
        match node.provider.call(call_req(self.signer, node.registry, data, gas)).await {
            Ok(b) => Ok(Ok(b)),
            Err(e) => match revert_data(&e) {
                Some(d) => Ok(Err(revert_reason(&d))),
                None if e.as_error_resp().is_some() => Ok(Err(e.to_string())),
                None => Err(e.into()),
            },
        }
    }

    async fn send(&self, node: &Node, data: Vec<u8>, gas: Option<u64>) -> Res<TxInfo> {
        node.ready_for_writes().await?;
        let _g = node.tx_lock.lock().await;
        let mut tx = alloy::rpc::types::TransactionRequest::default().with_to(node.registry).with_input(data);
        if let Some(g) = gas {
            tx = tx.with_gas_limit(g);
        }
        let r = node.send_and_wait(tx).await?;
        Ok(TxInfo { hash: r.transaction_hash, block: r.block_number.unwrap_or_default(), gas_used: r.gas_used, success: r.status() })
    }

    async fn register(&self, rp: RegisterParams) -> Res<RegisterResult> {
        let node = self.node(rp.node.as_deref())?;
        let (curve, raw) = match (&rp.vk, &rp.raw_vk, rp.curve) {
            (Some(vk), _, _) => encode_vk(vk).map_err(RpcErr::params)?,
            (None, Some(raw), Some(c)) => (c, raw.to_vec()),
            _ => return Err(RpcErr::params("pass vk, or rawVk + curve")),
        };
        let id = zknet_core::circuit_id(curve, &raw);
        let n_public = curve.n_public_for_vk_len(raw.len()).unwrap_or_default();
        let mut out = RegisterResult { node: node.name.clone(), circuit_id: id, curve, n_public, already_registered: false, revert: None, tx: None };
        node.ready_for_writes().await?;
        if self.is_registered(node, id).await? {
            out.already_registered = true;
            return Ok(out);
        }
        if let (Err(e), false) = (zknet_core::check_vk(curve, &raw), rp.force) {
            out.revert = Some(format!("native check: {e} (pass force: true to send anyway)"));
            return Ok(out);
        }
        let data = R::registerCall { curve: curve.id(), rawVk: raw.clone().into(), label: rp.label.unwrap_or_else(|| "zknetd".into()) }.abi_encode();
        let sim = self.simulate(node, data.clone(), DEFAULT_GAS).await?;
        if let Err(reason) = &sim {
            out.revert = Some(reason.clone());
            if !rp.force {
                return Ok(out);
            }
        }
        out.tx = Some(self.send(node, data, sim.is_err().then_some(DEFAULT_GAS)).await?);
        self.vk_cache.write().await.insert(id, (curve, raw));
        Ok(out)
    }

    async fn ensure_registered(&self, node: &Node, c: &Circuit, vp: &VerifyParams) -> Res<Option<TxInfo>> {
        if !vp.register || self.is_registered(node, c.id).await? {
            return Ok(None);
        }
        let r = self
            .register(RegisterParams { node: Some(node.name.clone()), raw_vk: Some(c.raw_vk.clone().into()), curve: Some(c.curve), label: Some("zknetd".into()), ..Default::default() })
            .await?;
        match (r.tx, r.revert) {
            (Some(tx), _) if tx.success => Ok(Some(tx)),
            (_, Some(why)) => Err(RpcErr::from(anyhow::anyhow!("register failed: {why}"))),
            _ => Err(RpcErr::from(anyhow::anyhow!("register tx reverted"))),
        }
    }

    async fn verify(&self, vp: VerifyParams) -> Res<VerifyResult> {
        let node = self.node(vp.node.as_deref())?;
        node.ready_for_reads().await?;
        let c = self.resolve(node, &vp).await?;
        let (proof, inputs) = proof_and_inputs(&c, &vp)?;
        let local = local(&c, &proof, &inputs);
        let registered = self.ensure_registered(node, &c, &vp).await?;
        let gas = vp.gas.unwrap_or(DEFAULT_GAS);
        let data = R::verifyCall { id: c.id, proof: proof.clone().into(), inputs: inputs.clone() }.abi_encode();
        let block = node.head_number().await;
        let onchain = match self.simulate(node, data.clone(), gas).await? {
            Ok(ret) => {
                let ok = R::verifyCall::abi_decode_returns(&ret).map_err(anyhow::Error::from)?;
                let est = node.provider.estimate_gas(call_req(self.signer, node.registry, data, gas)).await.ok();
                OnchainVerdict { ok: Some(ok), revert: None, gas: est, block }
            }
            Err(reason) => OnchainVerdict { ok: None, revert: Some(reason), gas: None, block },
        };
        // UnknownCircuit / InsufficientGas say nothing about the proof itself
        let comparable = !onchain.revert.as_deref().is_some_and(|r| r.starts_with("UnknownCircuit") || r.starts_with("InsufficientGas"));
        let agree = comparable.then_some(match onchain.ok {
            Some(ok) => ok == local.ok && !local.reverts,
            None => local.reverts,
        });
        if agree == Some(false) {
            tracing::warn!(circuit = %c.id, local = ?local, onchain = ?onchain, "native and on-chain verifiers DISAGREE");
        }
        Ok(VerifyResult { node: node.name.clone(), circuit_id: c.id, curve: c.curve, n_public: c.curve.n_public_for_vk_len(c.raw_vk.len()).unwrap_or_default(), proof: proof.into(), inputs, local, onchain: Some(onchain), agree, registered })
    }

    async fn submit(&self, vp: VerifyParams) -> Res<SubmitResult> {
        let node = self.node(vp.node.as_deref())?;
        node.ready_for_writes().await?;
        let c = self.resolve(node, &vp).await?;
        let (proof, inputs) = proof_and_inputs(&c, &vp)?;
        let local = local(&c, &proof, &inputs);
        let registered = self.ensure_registered(node, &c, &vp).await?;
        let data = R::submitCall { id: c.id, proof: proof.into(), inputs: inputs.clone() }.abi_encode();
        let gas = vp.gas.unwrap_or(DEFAULT_GAS);
        let mut out = SubmitResult { node: node.name.clone(), circuit_id: c.id, inputs_hash: zknet_core::inputs_hash(&inputs), local, revert: None, tx: None, registered };
        let sim = self.simulate(node, data.clone(), gas).await?;
        if let Err(reason) = &sim {
            out.revert = Some(reason.clone());
            if !vp.force {
                return Ok(out);
            }
        }
        out.tx = Some(self.send(node, data, (sim.is_err() || vp.gas.is_some()).then_some(gas)).await?);
        Ok(out)
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
                let (is_head, node) = match &ev {
                    ChainEvent::Head { node, .. } => (true, node),
                    ChainEvent::CircuitRegistered { node, .. } | ChainEvent::ProofVerified { node, .. } => (false, node),
                };
                if only_node.as_ref().is_some_and(|n| n != node) || (topic == "heads" && !is_head) || (topic == "events" && is_head) {
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

fn vk_from(params: &Value) -> Res<(Curve, Vec<u8>)> {
    if let Some(vk) = params.get("vk") {
        return encode_vk(&from(vk.clone())?).map_err(RpcErr::params);
    }
    let raw: Bytes = from(params.get("rawVk").cloned().ok_or_else(|| RpcErr::params("pass vk or rawVk + curve"))?)?;
    let curve: Curve = from(params.get("curve").cloned().ok_or_else(|| RpcErr::params("rawVk needs curve"))?)?;
    Ok((curve, raw.to_vec()))
}

fn proof_and_inputs(c: &Circuit, vp: &VerifyParams) -> Res<(Vec<u8>, Vec<U256>)> {
    let proof = match &vp.proof {
        ProofArg::Hex(b) => b.to_vec(),
        ProofArg::Snarkjs(p) => encode_proof(p, c.curve).map_err(RpcErr::params)?,
    };
    let inputs = vp.public_signals.iter().map(|s| parse_u256(s)).collect::<Result<_, _>>().map_err(RpcErr::params)?;
    Ok((proof, inputs))
}

fn local(c: &Circuit, proof: &[u8], inputs: &[U256]) -> LocalVerdict {
    let t = Instant::now();
    let r = zknet_core::verify(c.curve, &c.raw_vk, proof, inputs);
    let micros = t.elapsed().as_micros() as u64;
    match r {
        Ok(()) => LocalVerdict { ok: true, reason: None, reverts: false, micros },
        Err(e) => LocalVerdict { ok: false, reverts: e.reverts_on_chain(), reason: Some(e.to_string()), micros },
    }
}
