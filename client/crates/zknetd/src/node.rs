//! One L1 endpoint: an alloy provider, a head follower, and the rollup event watcher.

use alloy::eips::BlockNumberOrTag;
use alloy::network::Ethereum;
use alloy::primitives::Address;
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use zknet_core::api::{ChainEvent, Head, NodeStatus};
use zknet_core::stark::proof::IZKRollup as R;

#[derive(Default, Clone)]
pub struct NodeState {
    pub up: bool,
    pub chain_id: Option<u64>,
    pub hardfork: Option<String>,
    pub head: Option<Head>,
    pub rollup_deployed: bool,
    pub last_error: Option<String>,
}

pub struct Node {
    pub name: String,
    pub url: String,
    pub provider: DynProvider<Ethereum>,
    pub rollup: Address,
    pub state: RwLock<NodeState>,
    events: broadcast::Sender<ChainEvent>,
}

impl Node {
    pub fn new(name: String, url: String, rollup: Address, events: broadcast::Sender<ChainEvent>) -> anyhow::Result<Arc<Self>> {
        let provider = ProviderBuilder::default().connect_http(url.parse()?).erased();
        Ok(Arc::new(Node { name, url, provider, rollup, state: RwLock::default(), events }))
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
            rollup_deployed: s.rollup_deployed,
            last_error: s.last_error,
        }
    }

    pub async fn ready(&self) -> anyhow::Result<()> {
        let s = self.state.read().await;
        anyhow::ensure!(s.up, "node {} ({}) is down", self.name, self.url);
        anyhow::ensure!(s.rollup_deployed, "no rollup at {} on {} (run `zkrollup deploy`)", self.rollup, self.name);
        Ok(())
    }

    async fn probe(&self) -> anyhow::Result<()> {
        let chain_id = self.provider.get_chain_id().await?;
        let info: Option<serde_json::Value> = self.provider.raw_request("anvil_nodeInfo".into(), ()).await.ok();
        let mut s = self.state.write().await;
        s.up = true;
        s.chain_id = Some(chain_id);
        s.hardfork = info.and_then(|i| i["hardFork"].as_str().map(String::from));
        s.last_error = None;
        Ok(())
    }

    async fn check_rollup(&self) -> anyhow::Result<bool> {
        let deployed = !self.provider.get_code_at(self.rollup).await?.is_empty();
        self.state.write().await.rollup_deployed = deployed;
        Ok(deployed)
    }

    /// Follow the chain forever: publish every new head and every rollup event.
    pub async fn follow(self: Arc<Self>, poll: Duration) {
        let mut last: Option<u64> = None;
        loop {
            if let Err(e) = self.tick(&mut last).await {
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

    async fn tick(&self, last: &mut Option<u64>) -> anyhow::Result<()> {
        if last.is_none() {
            self.probe().await?;
            let deployed = self.check_rollup().await?;
            let s = self.state.read().await.clone();
            tracing::info!(node = %self.name, url = %self.url, chain_id = ?s.chain_id, hardfork = ?s.hardfork, rollup_deployed = deployed, "node up");
        }
        let tip = self.provider.get_block_number().await?;
        // evm_revert / --fresh can move the tip backwards: resync
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
        if !self.state.read().await.rollup_deployed {
            self.check_rollup().await?;
        }
        if self.state.read().await.rollup_deployed && last.is_some() {
            self.publish_logs(from, tip).await?;
        }
        *last = Some(tip);
        Ok(())
    }

    async fn publish_logs(&self, from: u64, to: u64) -> anyhow::Result<()> {
        let filter = Filter::new().address(self.rollup).from_block(from).to_block(to);
        for log in self.provider.get_logs(&filter).await? {
            let (block, tx) = (log.block_number.unwrap_or_default(), log.transaction_hash.unwrap_or_default());
            let node = self.name.clone();
            let ev = match log.topic0().copied() {
                Some(t) if t == R::BatchCommitted::SIGNATURE_HASH => {
                    let e = log.log_decode::<R::BatchCommitted>()?.inner.data;
                    ChainEvent::BatchCommitted { node, block, tx, index: e.index.to(), new_root: e.newRoot, tx_hash: e.txHash, n_txs: e.txs.len() / 10 }
                }
                Some(t) if t == R::BatchFinalized::SIGNATURE_HASH => {
                    let e = log.log_decode::<R::BatchFinalized>()?.inner.data;
                    ChainEvent::BatchFinalized { node, block, tx, index: e.index.to(), new_root: e.newRoot, prover: e.prover }
                }
                Some(t) if t == R::BatchesReverted::SIGNATURE_HASH => {
                    let e = log.log_decode::<R::BatchesReverted>()?.inner.data;
                    ChainEvent::BatchesReverted { node, block, tx, from: e.fromIndex.to(), to: e.toIndex.to() }
                }
                _ => continue,
            };
            let _ = self.events.send(ev);
        }
        Ok(())
    }
}
