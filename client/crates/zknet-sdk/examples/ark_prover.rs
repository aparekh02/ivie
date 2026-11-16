//! A Rust prover, end to end: an arkworks Groth16 circuit, proved natively,
//! encoded with zknet-core, then registered, verified and submitted on zknet
//! through the socket. Start your own prover from this file.
//!
//!   cargo run --release -p zknet-sdk --example ark_prover
//!
//! Circuit: knowledge of x, y with x * y = z (z public). Swap `Mul` for your
//! own `ConstraintSynthesizer`.

use ark_groth16::Groth16;
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_relations::lc;
use ark_snark::SNARK;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use zknet_sdk::core::verify::bn254::{self, Engine, Fr};
use zknet_sdk::core::{Curve, U256, circuit_id};
use zknet_sdk::{Req, Zknet};

struct Mul {
    x: Option<Fr>,
    y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for Mul {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x = cs.new_witness_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let y = cs.new_witness_variable(|| self.y.ok_or(SynthesisError::AssignmentMissing))?;
        let z = cs.new_input_variable(|| Ok(self.x.ok_or(SynthesisError::AssignmentMissing)? * self.y.ok_or(SynthesisError::AssignmentMissing)?))?;
        cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + y, || lc!() + z)?;
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    // Test-only setup: the RNG seed is the toxic waste.
    let mut rng = StdRng::seed_from_u64(42);
    let (pk, vk) = Groth16::<Engine>::circuit_specific_setup(Mul { x: None, y: None }, &mut rng)?;

    // Encode the VK the way the registry wants it.
    let raw_vk = bn254::vk_bytes(&vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2, &vk.gamma_abc_g1);
    println!("circuit id (computed off-chain): {}", circuit_id(Curve::Bn254, &raw_vk));

    let mut zk = Zknet::connect()?;
    let reg = zk.register_raw(Curve::Bn254, &raw_vk, "ark_prover example")?;
    println!("register: already={} tx={:?} revert={:?}", reg.already_registered, reg.tx.map(|t| t.hash), reg.revert);

    // Prove a few statements, each checked natively and on chain.
    let snap = zk.snapshot()?;
    // Fresh statements every run: the registry accepts each (circuit, inputs) once.
    let salt = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos() as u64 % 1_000_000;
    for (x, y) in [(3 + salt, 11u64), (7, 6 + salt), (123456789 + salt, 987654321)] {
        let t = std::time::Instant::now();
        let proof = Groth16::<Engine>::prove(&pk, Mul { x: Some(x.into()), y: Some(y.into()) }, &mut rng)?;
        let prove_ms = t.elapsed().as_secs_f64() * 1e3;
        let bytes = bn254::proof_bytes(&proof.a, &proof.b, &proof.c);
        let z = U256::from(x) * U256::from(y);

        let v = zk.verify(Req::raw(Curve::Bn254, &raw_vk, &bytes, &[z]))?;
        let oc = v.onchain.unwrap();
        println!(
            "x*y = {z:<20} prove {prove_ms:>6.1} ms | native {} ({} us) | chain {:?} ({} gas) | agree={:?}",
            v.local.ok, v.local.micros, oc.ok, oc.gas.unwrap_or_default(), v.agree
        );

        let s = zk.submit(Req::raw(Curve::Bn254, &raw_vk, &bytes, &[z]))?;
        println!("  submit -> {}", s.tx.map(|t| format!("block {} gas {}", t.block, t.gas_used)).or(s.revert).unwrap_or_default());

        // a wrong claim must fail both verifiers
        let bad = zk.verify(Req::raw(Curve::Bn254, &raw_vk, &bytes, &[z + U256::from(1)]))?;
        assert!(!bad.local.ok && bad.onchain.unwrap().ok == Some(false));
    }
    zk.revert(&snap)?;
    Ok(())
}
