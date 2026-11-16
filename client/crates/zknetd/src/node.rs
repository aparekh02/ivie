//! One anvil endpoint: an alloy provider, a head follower, and the registry
//! event watcher.

use crate::registry::IZKVerifierRegistry as R;
use alloy::eips::BlockNumberOrTag;
use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, TransactionReceipt, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, broadcast};
use zknet_core::api::{ChainEvent, Head, NodeStatus};

#[derive(Default, Clone)]
pub struct NodeState {
    pub up: bool,
    pub chain_id: Option<u64>,
    pub hardfork: Option<String>,
    /// `anvil_nodeInfo` answered: this is a local dev node, safe to sign for.
    pub is_anvil: bool,
    pub head: Option<Head>,
    pub registry_deployed: bool,
    pub last_error: Option<String>,
}

pub struct Node {
    pub name: String,
    pub url: String,
    pub provider: DynProvider<Ethereum>,
    pub registry: Address,
    pub state: RwLock<NodeState>,
    /// Serializes this daemon's own transactions so nonces never race.
    pub tx_lock: Mutex<()>,
    events: broadcast::Sender<ChainEvent>,
}

impl Node {
    pub fn new(name: String, url: String, signer: PrivateKeySigner, registry: Address, events: broadcast::Sender<ChainEvent>) -> anyhow::Result<Arc<Self>> {
        // Nonces are fetched per tx, never cached: evm_revert / anvil restarts
        // move the account nonce backwards, and a cached nonce would then park
        // every later tx in the queue forever. Our own sends are serialized by
        // `tx_lock`, so there is no race.
        let provider = ProviderBuilder::default()
            .with_gas_estimation()
            .with_simple_nonce_management()
            .fetch_chain_id()
            .wallet(EthereumWallet::from(signer))
            .connect_http(url.parse()?)
            .erased();
        Ok(Arc::new(Node { name, url, provider, registry, state: RwLock::default(), tx_lock: Mutex::new(()), events }))
    }

    pub async fn status(&self) -> NodeStatus {
        let s = self.state.read().await.clone();
        NodeStatus {
            name: self.name.clone(),
            url: self.url.clone(),
            up: s.up,
            chain_id: s.chain_id,
            hardfork: s.hardfork,
            head: s.head,
            registry: self.registry,
            registry_deployed: s.registry_deployed,
            last_error: s.last_error,
        }
    }

    /// Refuses unless the node is up, is anvil, and has the registry.
    pub async fn ready_for_writes(&self) -> anyhow::Result<()> {
        let s = self.state.read().await;
        anyhow::ensure!(s.up, "node {} ({}) is down", self.name, self.url);
        anyhow::ensure!(s.is_anvil, "node {} is not anvil: zknetd only signs with dev keys against a local anvil", self.name);
        anyhow::ensure!(s.registry_deployed, "no registry at {} on {} (start zknetd without --no-deploy, or run npm run e2e)", self.registry, self.name);
        Ok(())
    }

    pub async fn ready_for_reads(&self) -> anyhow::Result<()> {
        let s = self.state.read().await;
        anyhow::ensure!(s.up, "node {} ({}) is down", self.name, self.url);
        anyhow::ensure!(s.registry_deployed, "no registry at {} on {}", self.registry, self.name);
        Ok(())
    }

    async fn probe(&self) -> anyhow::Result<()> {
        let chain_id = self.provider.get_chain_id().await?;
        let info: Option<serde_json::Value> = self.provider.raw_request("anvil_nodeInfo".into(), ()).await.ok();
        let mut s = self.state.write().await;
        s.up = true;
        s.chain_id = Some(chain_id);
        s.is_anvil = info.is_some();
        s.hardfork = info.and_then(|i| i["hardFork"].as_str().map(String::from));
        s.last_error = None;
        Ok(())
    }

    async fn check_registry(&self) -> anyhow::Result<bool> {
        let code = self.provider.get_code_at(self.registry).await?;
        let deployed = !code.is_empty();
        self.state.write().await.registry_deployed = deployed;
        Ok(deployed)
    }

    /// Deploy the registry through the canonical CREATE2 deployer, exactly as
    /// e2e/run.mjs does, so the address is the same everywhere.
    async fn deploy_registry(&self, initcode: &Bytes) -> anyhow::Result<()> {
        let _g = self.tx_lock.lock().await;
        let mut data = zknet_core::registry_salt().to_vec();
        data.extend_from_slice(initcode);
        let tx = TransactionRequest::default().with_to(zknet_core::CREATE2_DEPLOYER).with_input(data);
        let r = self.send_and_wait(tx).await?;
        anyhow::ensure!(r.status(), "registry deploy reverted");
        tracing::info!(node = %self.name, registry = %self.registry, block = ?r.block_number, gas = r.gas_used, "deployed registry");
        Ok(())
    }

    /// Follow the chain forever: probe, deploy the registry if asked, then
    /// publish every new head and every registry event.
    pub async fn follow(self: Arc<Self>, initcode: Option<Bytes>, poll: Duration) {
        let mut last: Option<u64> = None;
        loop {
            if let Err(e) = self.tick(&mut last, initcode.as_ref()).await {
                // A node that still answers is not down: the usual cause is an
                // evm_revert landing between reading the tip and fetching its
                // blocks. Keep `last`; the next tick sees the rewind and resyncs.
                if last.is_some() && self.provider.get_chain_id().await.is_ok() {
                    tracing::debug!(node = %self.name, error = %e, "transient follower error");
                    tokio::time::sleep(poll).await;
                    continue;
                }
                let mut s = self.state.write().await;
                if s.up {
                    tracing::warn!(node = %self.name, error = %e, "node went down");
                }
                *s = NodeState { last_error: Some(e.to_string()), ..Default::default() };
                last = None;
                drop(s);
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            tokio::time::sleep(poll).await;
        }
    }

    async fn tick(&self, last: &mut Option<u64>, initcode: Option<&Bytes>) -> anyhow::Result<()> {
        if last.is_none() {
            self.probe().await?;
            let mut deployed = self.check_registry().await?;
            if !deployed
                && let (Some(code), true) = (initcode, self.state.read().await.is_anvil) {
                    self.deploy_registry(code).await?;
                    deployed = self.check_registry().await?;
                }
            let s = self.state.read().await.clone();
            tracing::info!(node = %self.name, url = %self.url, chain_id = ?s.chain_id, hardfork = ?s.hardfork, anvil = s.is_anvil, registry_deployed = deployed, "node up");
        }
        let tip = self.provider.get_block_number().await?;
        // anvil_revert / --fresh can move the tip backwards: resync
        let from = match *last {
            Some(l) if tip < l => {
                tracing::info!(node = %self.name, from = l, to = tip, "chain rewound (evm_revert or restart)");
                tip
            }
            Some(l) if tip == l => return Ok(()),
            Some(l) => l + 1,
            None => tip,
        };
        let from = from.max(tip.saturating_sub(63));
        for n in from..=tip {
            if let Some(b) = self.provider.get_block_by_number(BlockNumberOrTag::Number(n)).await? {
                let head = Head {
                    number: b.header.number,
                    hash: b.header.hash,
                    timestamp: b.header.timestamp,
                    base_fee: b.header.base_fee_per_gas,
                    tx_count: b.transactions.len(),
                };
                self.state.write().await.head = Some(head.clone());
                let _ = self.events.send(ChainEvent::Head { node: self.name.clone(), head });
            }
        }
        if !self.state.read().await.registry_deployed {
            self.check_registry().await?;
        }
        if self.state.read().await.registry_deployed && last.is_some() {
            self.publish_logs(from, tip).await?;
        }
        *last = Some(tip);
        Ok(())
    }

    async fn publish_logs(&self, from: u64, to: u64) -> anyhow::Result<()> {
        let filter = Filter::new().address(self.registry).from_block(from).to_block(to);
        for log in self.provider.get_logs(&filter).await? {
            let (block, tx) = (log.block_number.unwrap_or_default(), log.transaction_hash.unwrap_or_default());
            let topic0 = log.topic0().copied();
            let ev = if topic0 == Some(R::ProofVerified::SIGNATURE_HASH) {
                let e = log.log_decode::<R::ProofVerified>()?.inner.data;
                ChainEvent::ProofVerified { node: self.name.clone(), block, tx, circuit_id: e.id, inputs_hash: e.inputsHash, submitter: e.submitter, inputs: e.inputs }
            } else if topic0 == Some(R::CircuitRegistered::SIGNATURE_HASH) {
                let e = log.log_decode::<R::CircuitRegistered>()?.inner.data;
                let Some(curve) = zknet_core::Curve::from_id(e.curve) else { continue };
                ChainEvent::CircuitRegistered { node: self.name.clone(), block, tx, circuit_id: e.id, curve, n_public: e.nPublic, registrant: e.registrant, label: e.label }
            } else {
                continue;
            };
            let _ = self.events.send(ev);
        }
        Ok(())
    }

    /// Send and poll for the receipt ourselves. alloy's block watcher is not
    /// used on purpose: after evm_revert, a resent tx has the same hash as the
    /// rolled-back one, and the watcher reports it confirmed at once.
    pub async fn send_and_wait(&self, tx: TransactionRequest) -> anyhow::Result<TransactionReceipt> {
        let hash = *self.provider.send_transaction(tx).await?.tx_hash();
        let deadline = tokio::time::Instant::now() + RECEIPT_TIMEOUT;
        loop {
            if let Some(r) = self.provider.get_transaction_receipt(hash).await? {
                return Ok(r);
            }
            anyhow::ensure!(tokio::time::Instant::now() < deadline, "no receipt for {hash} after {RECEIPT_TIMEOUT:?}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn head_number(&self) -> u64 {
        match self.state.read().await.head.as_ref() {
            Some(h) => h.number,
            None => self.provider.get_block_number().await.unwrap_or_default(),
        }
    }
}

/// Longest wait for a receipt (strict mode mines every 12 s).
pub const RECEIPT_TIMEOUT: Duration = Duration::from_secs(90);

pub const DEFAULT_GAS: u64 = 1 << 24; // EIP-7825 per-tx cap

pub fn call_req(from: Address, to: Address, data: Vec<u8>, gas: u64) -> TransactionRequest {
    TransactionRequest::default().with_from(from).with_to(to).with_input(data).with_gas_limit(gas).with_value(U256::ZERO)
}
