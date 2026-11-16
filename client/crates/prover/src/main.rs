//! Your prover workspace.
//!
//!   cargo run --release -p prover              # native checks + chain (needs zknetd)
//!   cargo run --release -p prover -- --offline # native checks only, no daemon
//!
//! How it's laid out:
//!   1. CIRCUIT   - what you're proving. Replace `Circuit` with your own.
//!   2. PROVER    - `my_prove`. It calls ark-groth16 for now. Replace it piece
//!                  by piece with your own code. `reference_prove` stays as the
//!                  oracle to compare against.
//!   3. CHECKS    - native verifier (fast), then the on-chain verifier through
//!                  zknetd, inside evm_snapshot/evm_revert so nothing is
//!                  permanently consumed.

use ark_ec::AffineRepr;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_relations::lc;
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore, SeedableRng, rngs::StdRng};
use zknet_sdk::core::verify::bn254::{self, Engine, Fr};
use zknet_sdk::core::{Curve, U256, circuit_id};
use zknet_sdk::{Req, Zknet};

// =====================================================================
// 1. CIRCUIT
// =====================================================================

/// Statement: "I know x, y such that x * y = z", with z public.
/// Inputs are `Option`s so the same struct serves setup (None) and proving (Some).
#[derive(Clone)]
struct Circuit {
    x: Option<Fr>,
    y: Option<Fr>,
}

impl Circuit {
    /// Public inputs, in the order `new_input_variable` allocates them.
    fn public_inputs(&self) -> Vec<Fr> {
        vec![self.x.unwrap() * self.y.unwrap()]
    }
}

impl ConstraintSynthesizer<Fr> for Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let missing = || SynthesisError::AssignmentMissing;
        let x = cs.new_witness_variable(|| self.x.ok_or_else(missing))?;
        let y = cs.new_witness_variable(|| self.y.ok_or_else(missing))?;
        let z = cs.new_input_variable(|| Ok(self.x.ok_or_else(missing)? * self.y.ok_or_else(missing)?))?;
        cs.enforce_r1cs_constraint(|| lc!() + x, || lc!() + y, || lc!() + z)?;
        Ok(())
    }
}

// =====================================================================
// 2. PROVER
// =====================================================================

/// YOUR prover. It starts as a passthrough to ark-groth16. Replace its body
/// step by step:
///   a. synthesize the constraint system and extract the witness
///   b. R1CS -> QAP: evaluate A, B, C over the domain, iFFT, coset FFT,
///      compute h = (A*B - C) / Z
///   c. the MSMs: A = alpha + Σ a_i·u_i(τ) + r·delta, B likewise in G2,
///      C = Σ witness·L_i + h·H + s·A + r·B - r·s·delta
/// With the same (r, s) as `reference_prove`, the bytes must match exactly.
fn my_prove(pk: &ProvingKey<Engine>, circuit: Circuit, rng: &mut (impl RngCore + CryptoRng)) -> anyhow::Result<Proof<Engine>> {
    // TODO: replace with your own implementation
    Ok(Groth16::<Engine>::prove(pk, circuit, rng)?)
}

/// The oracle. Leave this alone.
fn reference_prove(pk: &ProvingKey<Engine>, circuit: Circuit, rng: &mut (impl RngCore + CryptoRng)) -> anyhow::Result<Proof<Engine>> {
    Ok(Groth16::<Engine>::prove(pk, circuit, rng)?)
}

// =====================================================================
// 3. CHECKS
// =====================================================================

fn to_u256(x: &Fr) -> U256 {
    use ark_ff::{BigInteger, PrimeField};
    U256::from_be_slice(&x.into_bigint().to_bytes_be())
}

fn raw_vk(vk: &VerifyingKey<Engine>) -> Vec<u8> {
    bn254::vk_bytes(&vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2, &vk.gamma_abc_g1)
}

fn main() -> anyhow::Result<()> {
    let offline = std::env::args().any(|a| a == "--offline");

    // Test-only trusted setup. The seed IS the toxic waste.
    let mut setup_rng = StdRng::seed_from_u64(0xC0FFEE);
    let (pk, vk) = Groth16::<Engine>::circuit_specific_setup(Circuit { x: None, y: None }, &mut setup_rng)?;
    let raw_vk = raw_vk(&vk);
    let id = circuit_id(Curve::Bn254, &raw_vk);
    println!("circuit {id}  (nPublic = {})", vk.gamma_abc_g1.len() - 1);
    zknet_sdk::core::check_vk(Curve::Bn254, &raw_vk).map_err(|e| anyhow::anyhow!("registry would refuse this VK: {e}"))?;

    let statements = [(3u64, 11u64), (12345, 67890)];
    let mut proofs = Vec::new();

    for (x, y) in statements {
        let circuit = Circuit { x: Some(x.into()), y: Some(y.into()) };
        let inputs: Vec<U256> = circuit.public_inputs().iter().map(to_u256).collect();

        // Same RNG seed for both, so same (r, s): the bytes should be identical.
        let seed = x ^ (y << 20);
        let t = std::time::Instant::now();
        let mine = my_prove(&pk, circuit.clone(), &mut StdRng::seed_from_u64(seed))?;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        let oracle = reference_prove(&pk, circuit, &mut StdRng::seed_from_u64(seed))?;

        let bytes = bn254::proof_bytes(&mine.a, &mine.b, &mine.c);
        let same = bytes == bn254::proof_bytes(&oracle.a, &oracle.b, &oracle.c);
        let native = zknet_sdk::core::verify(Curve::Bn254, &raw_vk, &bytes, &inputs);
        println!(
            "x={x} y={y}: prove {ms:.1} ms | matches oracle: {same} | native verify: {:?} | A is identity: {}",
            native,
            mine.a.is_zero()
        );
        proofs.push((bytes, inputs));
    }

    if offline {
        return Ok(());
    }

    // ---- on chain, through zknetd (`npm run zknetd`)
    let mut zk = Zknet::connect()?; // .on("strict") for 12 s slots
    let reg = zk.register_raw(Curve::Bn254, &raw_vk, "prover scratch")?;
    println!("register: already={} {:?}", reg.already_registered, reg.revert);

    let snap = zk.snapshot()?;
    for (bytes, inputs) in &proofs {
        let v = zk.verify(Req::raw(Curve::Bn254, &raw_vk, bytes, inputs))?;
        let oc = v.onchain.as_ref().unwrap();
        println!("chain verify: {:?} ({} gas) agree={:?}", oc.ok, oc.gas.unwrap_or_default(), v.agree);

        let s = zk.submit(Req::raw(Curve::Bn254, &raw_vk, bytes, inputs))?;
        println!("  submit: {}", s.tx.map(|t| format!("block {} gas {}", t.block, t.gas_used)).or(s.revert).unwrap_or_default());
    }
    zk.revert(&snap)?; // roll back so the same statements can be submitted next run

    // ---- scratch: try things here
    // let (bytes, inputs) = &proofs[0];
    // let mut bad = bytes.clone(); bad[10] ^= 1;
    // println!("{:?}", zk.verify(Req::raw(Curve::Bn254, &raw_vk, &bad, inputs))?.onchain);

    Ok(())
}
