//! Where the rollup contracts live: CREATE2 addresses derived from the
//! compiled artifacts in `contracts/out`, through the canonical CREATE2 deployer.

use super::{State, field};
use alloy_primitives::{Address, B256, Bytes, address, keccak256};
use std::path::Path;

/// anvil dev account 4 (`zkrollup`'s sequencer key).
pub const SEQUENCER: Address = address!("15d34AAf54267DB7D7c367839AAf71A00a2C6A65");

pub fn salt() -> B256 {
    let mut s = [0u8; 32];
    s[..15].copy_from_slice(b"zknet.rollup.v1");
    B256::from(s)
}

fn artifact(root: &Path, name: &str) -> std::io::Result<Bytes> {
    let p = root.join(format!("contracts/out/{name}.sol/{name}.json"));
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p)?)?;
    v["bytecode"]["object"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| std::io::Error::other(format!("no bytecode in {}", p.display())))
}

/// (address, CREATE2 init code) of each contract.
pub struct Addrs {
    pub periodic: (Address, Bytes),
    pub verifier: (Address, Bytes),
    pub rollup: (Address, Bytes),
}

/// `root` is the repo root. Genesis is [`State::genesis`].
pub fn addresses(root: &Path) -> std::io::Result<Addrs> {
    let d = crate::CREATE2_DEPLOYER;
    let mk = |init: Bytes| (d.create2(salt(), keccak256(&init)), init);
    let periodic = mk(artifact(root, "RollupPeriodic")?);
    let mut vi = artifact(root, "StarkVerifier")?.to_vec();
    vi.extend_from_slice(&periodic.0.into_word().0);
    let verifier = mk(vi.into());
    let mut ri = artifact(root, "ZKRollup")?.to_vec();
    ri.extend_from_slice(&verifier.0.into_word().0);
    ri.extend_from_slice(&SEQUENCER.into_word().0);
    ri.extend_from_slice(field::to_b256(&State::genesis().root()).as_slice());
    let rollup = mk(ri.into());
    Ok(Addrs { periodic, verifier, rollup })
}
