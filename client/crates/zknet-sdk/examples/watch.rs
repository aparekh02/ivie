//! Stream heads and registry events from every node.
//!
//!   cargo run --release -p zknet-sdk --example watch [-- heads|events|all]

use zknet_sdk::{ChainEvent, Zknet};

fn main() -> anyhow::Result<()> {
    let topic = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    let sub = Zknet::connect()?.subscribe(&topic)?;
    eprintln!("subscribed to {topic} ({})", sub.id);
    for ev in sub {
        match ev? {
            ChainEvent::Head { node, head } => println!("[{node}] block {} txs={} base_fee={:?}", head.number, head.tx_count, head.base_fee),
            ChainEvent::CircuitRegistered { node, block, circuit_id, curve, n_public, label, .. } => {
                println!("[{node}] block {block} CircuitRegistered {circuit_id} {curve} n={n_public} {label:?}")
            }
            ChainEvent::ProofVerified { node, block, circuit_id, inputs, submitter, .. } => {
                println!("[{node}] block {block} ProofVerified {circuit_id} by {submitter} inputs={inputs:?}")
            }
        }
    }
    Ok(())
}
