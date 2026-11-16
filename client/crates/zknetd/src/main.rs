//! zknetd: a light Rust client for zknet.
//!
//! It is not a full node. It connects to one or more anvil nodes over
//! JSON-RPC (alloy, the library reth's RPC layer is built on), follows their
//! heads, watches the verifier registry, and exposes everything on a Unix
//! socket for local programs (your prover) to call:
//!
//!   cargo run --release -p zknetd
//!   echo '{"jsonrpc":"2.0","id":1,"method":"zk_status"}' | nc -U ../chain/.run/zknetd.sock
//!
//! Transactions are signed locally with an anvil dev key, and only for nodes
//! that answer `anvil_nodeInfo`. zknet uses chain id 1, so this guard is what
//! keeps a misconfigured `--node` from ever signing for real mainnet.

mod node;
mod registry;
mod server;

use alloy::primitives::Bytes;
use alloy::signers::local::PrivateKeySigner;
use clap::Parser;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixListener;
use tokio::sync::broadcast;

/// anvil's default dev keys (public, test-only). Index 3 is the default here
/// so the daemon never shares a nonce with e2e/run.mjs or tools/submit.mjs (index 0).
const ANVIL_KEYS: [&str; 10] = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
];

#[derive(Parser)]
#[command(version, about = "Light Rust client for zknet with a Unix-socket plug-in API")]
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
    /// Which anvil dev key signs transactions.
    #[arg(long, default_value_t = 3)]
    key_index: usize,
    /// Don't deploy the registry on nodes that lack it.
    #[arg(long)]
    no_deploy: bool,
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

    let root = match args.root {
        Some(r) => r,
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.."),
    }
    .canonicalize()?;
    let socket = args.socket.unwrap_or_else(|| root.join("chain/.run/zknetd.sock"));

    // Registry: CREATE2 address derived from the compiled init code.
    let artifact = root.join("contracts/out/ZKVerifierRegistry.sol/ZKVerifierRegistry.json");
    let initcode: Option<Bytes> = match std::fs::read(&artifact) {
        Ok(b) => {
            let v: serde_json::Value = serde_json::from_slice(&b)?;
            Some(v["bytecode"]["object"].as_str().ok_or_else(|| anyhow::anyhow!("no bytecode in {}", artifact.display()))?.parse()?)
        }
        Err(_) => None,
    };
    let registry = match &initcode {
        Some(code) => zknet_core::registry_address(code),
        None => {
            tracing::warn!("{} missing (run `forge build` in contracts/); assuming the e2e registry address", artifact.display());
            "0x4740bc43d3B1eBb7Fa745df3De3Ab26014C31B9C".parse()?
        }
    };

    let key = ANVIL_KEYS.get(args.key_index).ok_or_else(|| anyhow::anyhow!("--key-index must be 0..9"))?;
    let signer: PrivateKeySigner = key.parse()?;
    let signer_addr = signer.address();

    let (events, _) = broadcast::channel(4096);
    let mut nodes = Vec::new();
    for spec in &args.nodes {
        let (name, url) = spec.split_once('=').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or_else(|| (format!("node{}", nodes.len()), spec.clone()));
        nodes.push(node::Node::new(name, url, signer.clone(), registry, events.clone())?);
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
        tokio::spawn(n.clone().follow((!args.no_deploy).then(|| initcode.clone()).flatten(), poll));
    }
    let srv = server::Server::new(nodes, signer_addr, socket.display().to_string(), events);
    tracing::info!(socket = %socket.display(), %registry, signer = %signer_addr, "zknetd listening");

    let sock = socket.clone();
    tokio::select! {
        r = srv.serve(listener) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    let _ = std::fs::remove_file(sock);
    Ok(())
}
