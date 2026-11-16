//! zkrollup: the L2 side of the zknet validity rollup.
//!
//!   zkrollup gen-sol                  regenerate contracts/src/stark/generated/RollupPeriodic.sol
//!   zkrollup fixture                  write proof fixtures for `forge test`
//!   zkrollup deploy                   CREATE2-deploy RollupPeriodic, StarkVerifier, ZKRollup
//!   zkrollup status                   L1 view + L2 state rebuilt from L1 calldata
//!   zkrollup run [-n 3] [-b 4]        sequencer + prover: commit, prove, finalize
//!   zkrollup attack                   bad batches the L1 contract must refuse
//!
//! The sequencer uses anvil key 4, so its nonces never collide with zknetd (key 3).

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, TransactionReceipt, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::{SolCall, SolEvent, SolInterface};
use anyhow::{Context, bail, ensure};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use zknet_core::stark::proof::{IStarkVerifier, IZKRollup, reject_from_revert};
use zknet_core::stark::{self, Options, State, Tx, deploy, field, state};

const SEQUENCER_KEY: &str = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a";

#[derive(Parser)]
struct Args {
    #[arg(long, env = "ZKROLLUP_L1", default_value = "http://127.0.0.1:9545")]
    l1: String,
    #[arg(long, env = "ZKNET_ROOT")]
    root: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    GenSol,
    Fixture,
    Deploy,
    Status,
    Run {
        /// batches to produce
        #[arg(short = 'n', long, default_value_t = 3)]
        batches: usize,
        /// txs per batch (power of two, ≤ 16)
        #[arg(short = 'b', long, default_value_t = 4)]
        txs: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
    Attack,
}

fn repo(args: &Args) -> PathBuf {
    args.root.clone().unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.."))
}

struct L1 {
    p: DynProvider,
    me: Address,
}

impl L1 {
    async fn connect(url: &str) -> anyhow::Result<Self> {
        let signer: PrivateKeySigner = SEQUENCER_KEY.parse()?;
        let me = signer.address();
        ensure!(me == deploy::SEQUENCER);
        let p = ProviderBuilder::default()
            .with_gas_estimation()
            .with_simple_nonce_management()
            .fetch_chain_id()
            .wallet(EthereumWallet::from(signer))
            .connect_http(url.parse()?)
            .erased();
        let ver: String = p.raw_request("web3_clientVersion".into(), ()).await.with_context(|| format!("L1 at {url}"))?;
        ensure!(ver.to_lowercase().contains("anvil"), "refusing to sign for a non-anvil node ({ver})");
        Ok(L1 { p, me })
    }

    async fn send(&self, to: Address, data: Vec<u8>) -> anyhow::Result<TransactionReceipt> {
        let tx = TransactionRequest::default().with_to(to).with_input(data);
        let hash = *self.p.send_transaction(tx).await.map_err(|e| anyhow::anyhow!(decode_err(&e)))?.tx_hash();
        let end = Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(r) = self.p.get_transaction_receipt(hash).await? {
                return Ok(r);
            }
            ensure!(Instant::now() < end, "no receipt for {hash}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn call(&self, to: Address, data: Vec<u8>) -> Result<Bytes, String> {
        let tx = TransactionRequest::default().with_from(self.me).with_to(to).with_input(data).with_gas_limit(16_000_000);
        self.p.call(tx).await.map_err(|e| decode_err(&e))
    }

    async fn view<C: SolCall>(&self, to: Address, c: C) -> anyhow::Result<C::Return> {
        let out = self.call(to, c.abi_encode()).await.map_err(|e| anyhow::anyhow!(e))?;
        Ok(C::abi_decode_returns(&out)?)
    }

    async fn code(&self, a: Address) -> anyhow::Result<bool> {
        Ok(!self.p.get_code_at(a).await?.is_empty())
    }
}

fn decode_err(e: &alloy::transports::TransportError) -> String {
    let Some(data) = e.as_error_resp().and_then(|r| r.as_revert_data()) else { return e.to_string() };
    if let Some(r) = reject_from_revert(&data) {
        return format!("StarkVerifier: {r}");
    }
    if let Ok(r) = IZKRollup::IZKRollupErrors::abi_decode(&data) {
        return format!("ZKRollup: {r:?}");
    }
    format!("revert 0x{}", alloy::hex::encode(&data))
}

fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    }
}

/// Random transfers that are valid against `st` (applied in order).
fn random_batch(st: &State, n: usize, r: &mut impl FnMut() -> u64) -> Vec<Tx> {
    let mut s = st.clone();
    let mut out = vec![];
    while out.len() < n {
        let from = (r() % state::ACCOUNTS as u64) as u8;
        let to = (r() % state::ACCOUNTS as u64) as u8;
        let bal = s.balances[from as usize];
        let amount = if bal == 0 { 0 } else { r() % (bal / 10 + 1) };
        let t = Tx { from, to, amount };
        if s.apply(&[t]).is_ok() {
            out.push(t);
        }
    }
    out
}

/// Replays committed batches from L1 logs (the DA layer): (finalized state, head state).
async fn rebuild(l1: &L1, rollup: Address) -> anyhow::Result<(State, State, Vec<Vec<u8>>)> {
    let committed = l1.view(rollup, IZKRollup::committedCall {}).await?.to::<usize>();
    let finalized = l1.view(rollup, IZKRollup::finalizedCall {}).await?.to::<usize>();
    let logs = l1.p.get_logs(&Filter::new().address(rollup).event_signature(IZKRollup::BatchCommitted::SIGNATURE_HASH).from_block(0)).await?;
    let mut by_index: Vec<Option<Vec<u8>>> = vec![None; committed + 1];
    for l in logs {
        let ev = IZKRollup::BatchCommitted::decode_log(&l.inner)?;
        let i = ev.index.to::<usize>();
        if i <= committed {
            by_index[i] = Some(ev.txs.to_vec()); // later logs win (after revertBatches)
        }
    }
    let mut st = State::genesis();
    let mut fin = st.clone();
    let mut batches = vec![];
    for (i, b) in by_index.into_iter().enumerate().skip(1) {
        let b = b.with_context(|| format!("batch {i}: no BatchCommitted log"))?;
        st.apply(&state::decode_txs(&b).context("bad tx data")?)?;
        if i == finalized {
            fin = st.clone();
        }
        batches.push(b);
    }
    Ok((fin, st, batches))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let root = repo(&args);
    match &args.cmd {
        Cmd::GenSol => {
            let p = root.join("contracts/src/stark/generated/RollupPeriodic.sol");
            std::fs::create_dir_all(p.parent().unwrap())?;
            std::fs::write(&p, stark::solgen::rollup_periodic())?;
            println!("wrote {}", p.display());
        }
        Cmd::Fixture => {
            let dir = root.join("contracts/test/vectors/stark");
            std::fs::create_dir_all(&dir)?;
            let mut st = State::genesis();
            let mut r = rng(7);
            for b in [1usize, 4] {
                let txs = random_batch(&st, b, &mut r);
                let prev = st.root();
                let pv = stark::prove(&mut st, &txs)?;
                let j = serde_json::json!({
                    "prevRoot": field::to_b256(&prev),
                    "newRoot": field::to_b256(&pv.public.new_root),
                    "txs": Bytes::from(state::encode_txs(&txs)),
                    "calldata": Bytes::from(pv.calldata()),
                });
                let p = dir.join(format!("batch_{b}.json"));
                std::fs::write(&p, serde_json::to_string_pretty(&j)?)?;
                println!("wrote {} ({} B calldata)", p.display(), pv.calldata().len());
            }
        }
        Cmd::Deploy => {
            let l1 = L1::connect(&args.l1).await?;
            let a = deploy::addresses(&root)?;
            for (name, (addr, init)) in [("RollupPeriodic", &a.periodic), ("StarkVerifier", &a.verifier), ("ZKRollup", &a.rollup)] {
                if l1.code(*addr).await? {
                    println!("{name:>15} {addr} (already deployed)");
                    continue;
                }
                let mut data = deploy::salt().to_vec();
                data.extend_from_slice(init);
                let r = l1.send(zknet_core::CREATE2_DEPLOYER, data).await?;
                ensure!(r.status() && l1.code(*addr).await?, "{name} deploy failed");
                println!("{name:>15} {addr} gas={}", r.gas_used);
            }
        }
        Cmd::Status => {
            let l1 = L1::connect(&args.l1).await?;
            let a = deploy::addresses(&root)?;
            let ra = a.rollup.0;
            ensure!(l1.code(ra).await?, "no rollup at {ra}; run `zkrollup deploy`");
            let (fin, head, _) = rebuild(&l1, ra).await?;
            let sr = l1.view(ra, IZKRollup::stateRootCall {}).await?;
            println!("rollup      {ra}");
            println!("verifier    {}", a.verifier.0);
            println!("committed   {}", l1.view(ra, IZKRollup::committedCall {}).await?);
            println!("finalized   {}", l1.view(ra, IZKRollup::finalizedCall {}).await?);
            println!("stateRoot   {sr}  (L1, finalized)");
            println!("rebuilt     {}  (L2 replay of finalized batches) {}", field::to_b256(&fin.root()), if field::to_b256(&fin.root()) == sr { "ok" } else { "MISMATCH" });
            println!("head        {}  (incl. unfinalized)", field::to_b256(&head.root()));
            let total: u64 = head.balances.iter().sum();
            println!("supply      {total} across {} accounts", state::ACCOUNTS);
        }
        Cmd::Run { batches, txs, seed } => {
            let l1 = L1::connect(&args.l1).await?;
            let a = deploy::addresses(&root)?;
            let ra = a.rollup.0;
            ensure!(l1.code(ra).await?, "no rollup at {ra}; run `zkrollup deploy`");
            let (fin, mut head, mut pending) = rebuild(&l1, ra).await?;
            let finalized = l1.view(ra, IZKRollup::finalizedCall {}).await?.to::<usize>();
            pending.drain(..finalized);
            // finish anything committed but not yet proven
            let mut prover_state = fin;
            let mut next = finalized + 1;
            let mut r = rng(*seed ^ (next as u64) << 32);
            let mut todo: Vec<Vec<u8>> = pending;
            for _ in 0..*batches {
                let b = random_batch(&head, *txs, &mut r);
                head.apply(&b)?;
                let data = state::encode_txs(&b);
                // 1. sequencer: post tx data + claimed root
                let rc = l1.send(ra, IZKRollup::commitBatchCall { txs: data.clone().into(), newRoot: field::to_b256(&head.root()) }.abi_encode()).await?;
                ensure!(rc.status(), "commit reverted");
                println!("commit  batch {:>3}  {} txs  root {}  gas {}", next + todo.len(), b.len(), field::to_b256(&head.root()), rc.gas_used);
                todo.push(data);
            }
            // 2. prover: prove each committed batch in order, 3. finalize on L1
            for data in todo {
                let txv = state::decode_txs(&data).unwrap();
                let t0 = Instant::now();
                let pv = stark::prove(&mut prover_state, &txv)?;
                let prove_t = t0.elapsed();
                let call = IZKRollup::finalizeBatchCall { index: U256::from(next), txs: data.clone().into(), proof: pv.proof.to_abi() };
                let cd = call.abi_encode();
                let rf = l1.send(ra, cd.clone()).await?;
                ensure!(rf.status(), "finalize reverted");
                println!(
                    "final   batch {next:>3}  T={:<6} prove {:>6.0?}  proof {:>6} B  L1 gas {}",
                    1u64 << pv.proof.log_t,
                    prove_t,
                    cd.len(),
                    rf.gas_used
                );
                next += 1;
            }
            let sr = l1.view(ra, IZKRollup::stateRootCall {}).await?;
            ensure!(sr == field::to_b256(&prover_state.root()), "L1 root != L2 root");
            println!("stateRoot {sr} (L1 == L2)");
        }
        Cmd::Attack => attack(&args, &root).await?,
    }
    Ok(())
}

/// Each case is simulated with eth_call against the live contracts, so the
/// chain is left unchanged (the bad commit is rolled back with evm_revert).
async fn attack(args: &Args, root: &std::path::Path) -> anyhow::Result<()> {
    let l1 = L1::connect(&args.l1).await?;
    let a = deploy::addresses(root)?;
    let (ra, va) = (a.rollup.0, a.verifier.0);
    ensure!(l1.code(ra).await?, "no rollup at {ra}; run `zkrollup deploy`");
    let committed = l1.view(ra, IZKRollup::committedCall {}).await?.to::<usize>();
    let finalized = l1.view(ra, IZKRollup::finalizedCall {}).await?.to::<usize>();
    if committed != finalized {
        bail!("{} committed batches are unproven; run `zkrollup run -n 0` first", committed - finalized);
    }
    let (fin, _, _) = rebuild(&l1, ra).await?;
    let prev = field::to_b256(&fin.root());
    let mut r = rng(99);
    let txs = random_batch(&fin, 2, &mut r);
    let data = state::encode_txs(&txs);
    let mut st = fin.clone();
    let good = stark::prove(&mut st, &txs)?;
    let new = field::to_b256(&good.public.new_root);
    let abi = good.proof.to_abi();

    let check = |name: &str, res: Result<Bytes, String>, native: Result<(), String>| {
        let chain = match &res {
            Ok(_) => "ACCEPT".to_string(),
            Err(e) => e.clone(),
        };
        let nat = match &native {
            Ok(()) => "ACCEPT".to_string(),
            Err(e) => format!("StarkVerifier: {e}"),
        };
        let note = if chain == nat { String::new() } else { format!("   (native disagrees: {nat})") };
        println!("{name:<44} {chain}{note}");
    };
    let verify_on = |p: &zknet_core::stark::StarkProof, pr: B256, nr: B256, d: &[u8]| {
        let call = IStarkVerifier::verifyCall { prevRoot: pr, newRoot: nr, txs: d.to_vec().into(), proof: p.clone() };
        (call.abi_encode(), stark::verify(pr, nr, d, p).map(|_| ()).map_err(|e| e.to_string()))
    };

    println!("verifier-level (eth_call StarkVerifier.verify):");
    let (cd, n) = verify_on(&abi, prev, new, &data);
    check("honest proof", l1.call(va, cd).await, n);
    // claimed root differs from the computed one (sequencer mints coins)
    let mut minted = fin.clone();
    minted.set(5, minted.balances[5] + 1_000_000);
    let (cd, n) = verify_on(&abi, prev, field::to_b256(&minted.root()), &data);
    check("same proof, inflated newRoot", l1.call(va, cd).await, n);
    let mut d2 = data.clone();
    d2[9] ^= 1;
    let (cd, n) = verify_on(&abi, prev, new, &d2);
    check("same proof, amount changed in tx data", l1.call(va, cd).await, n);
    let (cd, n) = verify_on(&abi, new, new, &data);
    check("same proof, wrong prevRoot", l1.call(va, cd).await, n);
    let mut t = abi.clone();
    t.traceVals[3] = (t.traceVals[3] + U256::from(1)) % field::P;
    let (cd, n) = verify_on(&t, prev, new, &data);
    check("trace value changed after commitment", l1.call(va, cd).await, n);
    let mut t = abi.clone();
    let last = t.friVals.len() - 1; // last committed layer's last coset
    t.friVals[last] = (t.friVals[last] + U256::from(1)) % field::P;
    let (cd, n) = verify_on(&t, prev, new, &data);
    check("FRI coset value changed", l1.call(va, cd).await, n);
    let mut t = abi.clone();
    t.traceDecommit[0] = B256::ZERO;
    let (cd, n) = verify_on(&t, prev, new, &data);
    check("Merkle multi-proof sibling zeroed", l1.call(va, cd).await, n);
    let mut t = abi.clone();
    t.powNonce += U256::from(1);
    let (cd, n) = verify_on(&t, prev, new, &data);
    check("grinding nonce changed", l1.call(va, cd).await, n);

    println!("\nadversarial provers (full re-prove, eth_call StarkVerifier.verify):");
    let lie = Options { claim_new_root: Some(minted.root()), unchecked: true, ..Default::default() };
    for (name, opts, edit) in [
        ("claims inflated newRoot", lie.clone(), false),
        ("claims inflated newRoot + fakes H(z)", Options { fake_ood: true, ..lie.clone() }, false),
        ("credits 1 extra coin inside the trace", Options { unchecked: true, ..Default::default() }, true),
    ] {
        let mut s = fin.clone();
        let pv = stark::prove_with(&mut s, &txs, &opts, |t| {
            if edit {
                for x in &mut t[stark::air::BN][1024..2048] {
                    *x += stark::F::from(1u64);
                }
            }
        })?;
        let (cd, n) = verify_on(&pv.proof.to_abi(), prev, field::to_b256(&pv.public.new_root), &data);
        check(name, l1.call(va, cd).await, n);
    }

    println!("\nrollup-level (sequencer commits a bad batch, eth_call finalize):");
    let snap: String = l1.p.raw_request("evm_snapshot".into(), ()).await?;
    let res = async {
        let rc = l1.send(ra, IZKRollup::commitBatchCall { txs: data.clone().into(), newRoot: field::to_b256(&minted.root()) }.abi_encode()).await?;
        ensure!(rc.status());
        let idx = U256::from(finalized + 1);
        let fin_call = |p: &zknet_core::stark::StarkProof, d: &[u8]| IZKRollup::finalizeBatchCall { index: idx, txs: d.to_vec().into(), proof: p.clone() }.abi_encode();
        let n = stark::verify(prev, field::to_b256(&minted.root()), &data, &abi).map(|_| ()).map_err(|e| e.to_string());
        check("finalize minted root with honest proof", l1.call(ra, fin_call(&abi, &data)).await, n);
        println!("{:<44} {}", "finalize with different tx data", l1.call(ra, fin_call(&abi, &d2)).await.err().unwrap_or_default());
        println!(
            "{:<44} {}",
            "finalize batch out of order",
            l1.call(ra, IZKRollup::finalizeBatchCall { index: idx + U256::from(1), txs: data.clone().into(), proof: abi.clone() }.abi_encode()).await.err().unwrap_or_default()
        );
        anyhow::Ok(())
    }
    .await;
    let _: bool = l1.p.raw_request("evm_revert".into(), (snap,)).await?;
    res
}
