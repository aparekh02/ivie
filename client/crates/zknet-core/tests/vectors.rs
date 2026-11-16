//! Differential test: the native verifier must reproduce every verdict in
//! contracts/test/vectors (the same fixtures Foundry and e2e/run.mjs use),
//! and the encoders must reproduce the JS encodings and circuit ids.

use serde::Deserialize;
use std::path::PathBuf;
use zknet_core::{Bytes, Curve, B256, SnarkjsVk, check_vk, circuit_id, encode_vk, parse_u256, verify};
use zknet_core::verify::{rerandomize, unprepare_vk};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    name: String,
    curve: u8,
    raw_vk: Bytes,
    circuit_id: B256,
    unsafe_vk: Bytes,
    valid: Vec<Case>,
    invalid: Vec<Case>,
    snarkjs: Snark,
}
#[derive(Deserialize)]
struct Snark {
    vk: SnarkjsVk,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    proof: Bytes,
    inputs: Vec<String>,
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/test/vectors")
}

fn fixtures() -> Vec<Fixture> {
    let dir = vectors_dir();
    let mut names = Vec::new();
    for idx in ["circom_index.json", "sim_index.json"] {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join(idx)).expect("vectors present")).unwrap();
        names.extend(v["fixtures"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()));
    }
    names
        .iter()
        .map(|n| serde_json::from_slice(&std::fs::read(dir.join(format!("{n}.json"))).unwrap()).unwrap())
        .collect()
}

#[test]
fn native_verifier_matches_every_vector() {
    let (mut ok, mut rej) = (0, 0);
    for fx in fixtures() {
        let curve = Curve::from_id(fx.curve).unwrap();
        // encoders reproduce the JS output
        let (c2, raw) = encode_vk(&fx.snarkjs.vk).unwrap();
        assert_eq!(c2, curve, "{}", fx.name);
        assert_eq!(raw, fx.raw_vk.to_vec(), "{}: encode_vk", fx.name);
        assert_eq!(circuit_id(curve, &raw), fx.circuit_id, "{}: circuit id", fx.name);
        // VK hygiene, as prepare() enforces
        assert!(check_vk(curve, &raw).is_ok(), "{}", fx.name);
        assert!(check_vk(curve, &fx.unsafe_vk).is_err(), "{}: gamma == delta VK accepted", fx.name);

        for c in &fx.valid {
            let inputs: Vec<_> = c.inputs.iter().map(|s| parse_u256(s).unwrap()).collect();
            verify(curve, &raw, &c.proof, &inputs).unwrap_or_else(|e| panic!("{} / {}: valid rejected: {e}", fx.name, c.name));
            let rr = rerandomize(curve, &c.proof, 7).unwrap();
            assert_ne!(rr, c.proof.to_vec());
            verify(curve, &raw, &rr, &inputs).unwrap();
            ok += 1;
        }
        for c in &fx.invalid {
            let inputs: Vec<_> = c.inputs.iter().map(|s| parse_u256(s).unwrap()).collect();
            let r = verify(curve, &raw, &c.proof, &inputs);
            assert!(r.is_err(), "{} / {}: INVALID proof accepted", fx.name, c.name);
            rej += 1;
        }

        // vkOf returns the prepared VK; un-preparing gives back the raw VK
        let prepared = unprepare_vk(curve, &raw).unwrap();
        assert_ne!(prepared, raw);
        assert_eq!(unprepare_vk(curve, &prepared).unwrap(), raw);
    }
    assert_eq!(ok + rej, 317, "expected the 317 e2e vectors ({ok} valid, {rej} invalid)");
}

#[test]
fn registry_address_matches_e2e() {
    let artifact = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/out/ZKVerifierRegistry.sol/ZKVerifierRegistry.json");
    let Ok(bytes) = std::fs::read(&artifact) else { return }; // forge build not run
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let code: Bytes = v["bytecode"]["object"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        zknet_core::registry_address(&code),
        "0x4740bc43d3B1eBb7Fa745df3De3Ab26014C31B9C".parse::<zknet_core::Address>().unwrap()
    );
}
