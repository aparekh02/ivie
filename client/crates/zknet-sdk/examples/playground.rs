//! Throw a real circom proof and some tampered copies at the verifier, and
//! compare the native verdict with the chain's for each one.
//!
//!   cargo run --release -p zknet-sdk --example playground [-- --node strict] [-- --curve bls12381]
//!
//! The submit at the end runs inside evm_snapshot / evm_revert, so the
//! statement isn't consumed and the example can be rerun.

use zknet_sdk::core::{Curve, SnarkjsProof, SnarkjsVk, U256, encode_proof, encode_vk, snarkjs::public_from_file, verify::rerandomize};
use zknet_sdk::{Req, Zknet};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let opt = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let curve_dir = opt("--curve").map(|c| if c.starts_with("bls") { "bls12381" } else { "bn128" }).unwrap_or("bn128");
    let circuit = opt("--circuit").unwrap_or_else(|| "multiplier".into());

    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../../circuits/build/{curve_dir}/{circuit}"));
    let vk = SnarkjsVk::from_file(dir.join("vk.json"))?;
    let proof = SnarkjsProof::from_file(dir.join("proof_0.json"))?;
    let public = public_from_file(dir.join("public_0.json"))?;

    let mut zk = Zknet::connect()?;
    if let Some(n) = opt("--node") {
        zk = zk.on(&n);
    }
    let st = zk.status()?;
    for n in &st.nodes {
        println!("node {:<7} {:<24} up={} block={:?} registry={} deployed={}", n.name, n.url, n.up, n.head.as_ref().map(|h| h.number), n.registry, n.registry_deployed);
    }

    // 1. the honest proof (registers the VK on first use)
    let r = zk.verify(Req::snarkjs(&vk, &proof, &public).register(true))?;
    println!("\ncircuit {} ({}, nPublic={})", r.circuit_id, r.curve, r.n_public);
    if let Some(tx) = &r.registered {
        println!("registered in block {} ({} gas)", tx.block, tx.gas_used);
    }

    // 2. tampered variants, all sent as raw bytes against the registered id
    let (curve, _raw) = encode_vk(&vk)?;
    let good = encode_proof(&proof, curve)?;
    let r_mod = match curve {
        Curve::Bn254 => "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        Curve::Bls12381 => "52435875175126190479447740508185965837690552500527637822603658699938581184513",
    };
    let x0: U256 = public[0].parse()?;
    let mut flipped = good.clone();
    flipped[curve.fp_bytes() - 1] ^= 1; // low bit of A.x
    let mut a_y_plus_p = good.clone();
    add_p_to_word(curve, &mut a_y_plus_p, 1);

    let cases: Vec<(&str, Vec<u8>, Vec<String>)> = vec![
        ("honest proof", good.clone(), public.clone()),
        ("re-randomized (A/s, sB, C)", rerandomize(curve, &good, 0xdead)?, public.clone()),
        ("input + 1", good.clone(), vec![(x0 + U256::from(1)).to_string()]),
        ("input + r (same value mod r)", good.clone(), vec![(x0 + r_mod.parse::<U256>()?).to_string()]),
        ("bit flip in A.x", flipped, public.clone()),
        ("A.y + p (non-canonical)", a_y_plus_p, public.clone()),
        ("truncated proof", good[..good.len() - 1].to_vec(), public.clone()),
        ("wrong input count", good.clone(), vec![public[0].clone(), "1".into()]),
    ];
    println!("\n{:<32} {:>8} {:>10} {:>9}  reason", "case", "native", "on-chain", "gas");
    for (name, p, ins) in cases {
        let v = zk.verify(Req::by_id(r.circuit_id, &p, &[]).inputs(&ins))?;
        let oc = v.onchain.as_ref().unwrap();
        let chain = match oc.ok {
            Some(true) => "valid".to_string(),
            Some(false) => "invalid".to_string(),
            None => "revert".to_string(),
        };
        let reason = v.local.reason.clone().or(oc.revert.clone()).unwrap_or_default();
        let mark = if v.agree == Some(false) { "  <-- DISAGREE" } else { "" };
        println!(
            "{:<32} {:>8} {:>10} {:>9}  {}{}",
            name,
            if v.local.ok { "valid" } else { "invalid" },
            chain,
            oc.gas.map(|g| g.to_string()).unwrap_or("-".into()),
            reason,
            mark
        );
    }

    // 3. submit for real, then roll the chain back. proof_2 is used because
    //    e2e/run.mjs consumes proof_0's statement (earlier runs may have consumed
    //    this one too, which shows up as AlreadyConsumed).
    let proof = SnarkjsProof::from_file(dir.join("proof_2.json"))?;
    let public = public_from_file(dir.join("public_2.json"))?;
    let good = encode_proof(&proof, curve)?;
    let snap = zk.snapshot()?;
    let s = zk.submit(Req::snarkjs(&vk, &proof, &public))?;
    match (&s.tx, &s.revert) {
        (Some(tx), _) => println!("\nsubmit: block {} gas {} success={} inputsHash={}", tx.block, tx.gas_used, tx.success, s.inputs_hash),
        (None, Some(why)) => println!("\nsubmit not sent: {why}"),
        _ => {}
    }
    let again = zk.submit(Req::by_id(r.circuit_id, &rerandomize(curve, &good, 99)?, &[]).inputs(&public))?;
    println!("replay with a re-randomized proof: {}", again.revert.as_deref().unwrap_or("ACCEPTED (bug!)"));
    println!("evm_revert({snap}) -> {}", zk.revert(&snap)?);
    Ok(())
}

/// Add the field modulus to Fp word `idx` of a proof (keeps the value mod p, breaks canonicity).
fn add_p_to_word(curve: Curve, proof: &mut [u8], idx: usize) {
    let p = match curve {
        Curve::Bn254 => "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
        Curve::Bls12381 => "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    };
    let w = curve.fp_bytes();
    let mut pb = vec![0u8; w];
    let ph = zknet_sdk::core::Bytes::from(hex_to_bytes(p));
    pb[w - ph.len()..].copy_from_slice(&ph);
    let word = &mut proof[idx * w..(idx + 1) * w];
    let mut carry = 0u16;
    for i in (0..w).rev() {
        let s = word[i] as u16 + pb[i] as u16 + carry;
        word[i] = s as u8;
        carry = s >> 8;
    }
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    let h = if h.len() % 2 == 1 { format!("0{h}") } else { h.to_string() };
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
}
