//! Stream L1 heads and rollup batch events from every node.
//!
//!   cargo run --release -p zknet-sdk --example watch [-- heads|events|all]

use zknet_sdk::Zknet;
use zknet_sdk::core::api::ChainEvent;

fn main() -> anyhow::Result<()> {
    let topic = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    let sub = Zknet::connect()?.subscribe(&topic)?;
    eprintln!("subscribed to {topic} ({})", sub.id);
    for ev in sub {
        match ev? {
            ChainEvent::Head { node, head } => println!("[{node}] block {} txs={} base_fee={:?}", head.number, head.tx_count, head.base_fee),
            ChainEvent::BatchCommitted { node, block, index, new_root, n_txs, .. } => {
                println!("[{node}] block {block} BatchCommitted #{index} {n_txs} txs, claimed root {new_root}")
            }
            ChainEvent::BatchFinalized { node, block, index, new_root, prover, .. } => {
                println!("[{node}] block {block} BatchFinalized #{index} root {new_root} by {prover}")
            }
            ChainEvent::BatchesReverted { node, block, from, to, .. } => println!("[{node}] block {block} BatchesReverted {from}..={to}"),
        }
    }
    Ok(())
}
