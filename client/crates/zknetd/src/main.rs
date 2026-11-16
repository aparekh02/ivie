//! zknetd: a light Rust client for the zknet rollup.
//!
//! It is not a full node. It connects to one or more anvil L1 nodes over
//! JSON-RPC (alloy, the library reth's RPC layer is built on), follows their
//! heads and the `ZKRollup` contract's batch events, and serves a Unix socket
//! for local programs:
//!
//!   cargo run --release -p zknetd
//!   echo '{"jsonrpc":"2.0","id":1,"method":"zk_status"}' | nc -U ../chain/.run/zknetd.sock
//!
//! It is read-only: it never signs. `zkrollup` is the sequencer and prover.

mod node;
mod server;

use clap::Parser;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use zknet_core::stark::deploy;

#[derive(Parser)]
#[command(version, about = "Light Rust client for the zknet rollup with a Unix-socket plug-in API")]
struct Args {
    /// Nodes as name=url (repeatable). The first is the default for requests without "node".
    #[arg(long = "node", env = "ZKNETD_NODES", value_delimiter = ',', default_value = "fast=http://127.0.0.1:9545,strict=http://127.0.0.1:9546")]
    nodes: Vec<String>,
    /// Socket path (default: <repo>/chain/.run/zknetd.sock).
    #[arg(long, env = "ZKNETD_SOCKET")]
    socket: Option<PathBuf>,
    /// Repo root (for contracts/out and chain/.run).
    #[arg(long, env = "ZKNET_ROOT")]
    root: Option<PathBuf>,
    /// Head polling interval.
    #[arg(long, default_value_t = 250)]
    poll_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "zknetd=info".into()))
        .init();
    let args = Args::parse();
    let root = args.root.unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")).canonicalize()?;
    let socket = args.socket.unwrap_or_else(|| root.join("chain/.run/zknetd.sock"));
    let a = deploy::addresses(&root).map_err(|e| anyhow::anyhow!("{e} (run `forge build` in contracts/)"))?;
    let (rollup, verifier) = (a.rollup.0, a.verifier.0);

    let (events, _) = broadcast::channel(4096);
    let mut nodes = Vec::new();
    for spec in &args.nodes {
        let (name, url) = spec.split_once('=').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or_else(|| (format!("node{}", nodes.len()), spec.clone()));
        nodes.push(node::Node::new(name, url, rollup, events.clone())?);
    }
    anyhow::ensure!(!nodes.is_empty(), "no nodes");

    // Socket: refuse to steal a live one, replace a stale one, owner-only perms.
    if socket.exists() {
        if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
            anyhow::bail!("another zknetd is already listening on {}", socket.display());
        }
        std::fs::remove_file(&socket)?;
    }
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;

    let poll = Duration::from_millis(args.poll_ms);
    for n in &nodes {
        tokio::spawn(n.clone().follow(poll));
    }
    let srv = server::Server::new(nodes, rollup, verifier, socket.display().to_string(), events);
    tracing::info!(socket = %socket.display(), %rollup, %verifier, "zknetd listening");

    tokio::select! {
        r = srv.serve(listener) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    let _ = std::fs::remove_file(&socket);
    Ok(())
}
