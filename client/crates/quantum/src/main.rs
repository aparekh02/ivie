//! qattack: a quantum **algebraic** attack lab against the in-AIR Poseidon hash
//! that backs the STARK state tree.
//!
//!   cargo run --release -p quantum                  full lab + report + viz JSON
//!   cargo run --release -p quantum -- preimage [R]   elimination preimage at R rounds
//!   cargo run --release -p quantum -- xl [R]         XL/Macaulay solving degree at R rounds
//!   cargo run --release -p quantum -- qaoa           QAOA preimage amplification (statevector)
//!   cargo run --release -p quantum -- forge          second-preimage / tamperable-leaf demo
//!   cargo run --release -p quantum -- margin         security-margin curve (degree vs rounds)
//!   cargo run --release -p quantum -- floors         Grover crypto floors (Merkle / grind)
//!   cargo run --release -p quantum -- emit <path>    write the visual-memory JSON
//!
//! The headline attack is algebraic, not brute force: eliminate the Poseidon
//! round system to one univariate polynomial over F_p and root-find it
//! (`groebner`), or linearize the multivariate system and read the solving
//! degree (`xl`). Both recover a *verified* reduced-round preimage. `qaoa` adds a
//! variational quantum search over the same cost. The honest result is the
//! `margin` curve: how many rounds put all of this out of reach.

use std::time::Instant;
use quantum::grover;
use quantum::oracle::{Grind, MerklePreimage};
use quantum::{attack, groebner, poseidon, qaoa, xl};
use zknet_core::stark::field::F;

fn arg_usize(default: usize) -> usize {
    std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(default)
}

/// Elimination preimage attack: recover an input hashing to a committed target.
fn preimage(rounds: usize) {
    println!("Algebraic elimination preimage attack on {rounds}-round Poseidon leaf hash");
    let secret = F::from(0x00C0_FFEE_1234u64);
    let target = poseidon::leaf_r(secret, rounds);
    println!("  committed target leaf      {target}");
    println!("  (attacker sees only the target; the secret is hidden)");
    let t0 = Instant::now();
    let res = groebner::attack(target, rounds, 0x5EED);
    let dt = t0.elapsed();
    println!("  elimination polynomial deg {} = 3^{rounds}", res.elim_degree);
    println!("  distinct F_p preimages     {}", res.root_count);
    match res.found {
        Some(b) => println!("  recovered preimage b*      {b}"),
        None => println!("  recovered preimage b*      <none>"),
    }
    println!("  verifies against real hash {}", res.verified);
    println!("  wall-clock                 {:.3} s", dt.as_secs_f64());
    println!(
        "  => {} field ops vs ~2^{:.0} brute force / ~2^{:.0} Grover.\n",
        if res.verified { "broke it in poly" } else { "n/a" },
        attack::field_bits(),
        attack::field_bits() / 2.0
    );
}

/// XL / Macaulay multivariate solving degree.
fn xl_demo(rounds: usize) {
    println!("XL / Macaulay linearization on {rounds}-round Poseidon (solving degree)");
    let secret = F::from(0xABCDEu64);
    let target = poseidon::leaf_r(secret, rounds);
    let budget = if rounds <= 2 { 6000 } else { 30000 };
    let t0 = Instant::now();
    let res = xl::attack(target, rounds, 18, budget);
    let dt = t0.elapsed();
    println!("  variables (b + interiors)  {}", res.vars);
    println!("  degree-3 generators        {}", res.gens);
    match (res.solving_degree, res.matrix) {
        (Some(d), Some((r, c))) => {
            println!("  SOLVING DEGREE D*          {d}");
            println!("  Macaulay matrix            {r} x {c}");
        }
        _ => println!("  solving degree             not reached within budget (cols <= {budget})"),
    }
    println!("  recovered b & verified     {}", res.verified);
    println!("  wall-clock                 {:.3} s", dt.as_secs_f64());
    println!("  => D* is the number a Poseidon round count is chosen to blow up.\n");
}

/// QAOA statevector search for a windowed preimage.
fn qaoa_demo() {
    println!("QAOA preimage amplification (exact statevector, Hamming-distance cost)");
    let (r, n, m, p, grid) = (3usize, 12u32, 14u32, 2usize, 20usize);
    let secret = F::from(42u64);
    let target = poseidon::leaf_r(secret, r);
    let res = qaoa::optimize(target, r, n, m, p, grid);
    println!("  qubits n / layers p        {n} / {p}");
    println!("  ground states (preimages)  {}", res.marked);
    println!("  uniform sample prob        {:.5}", res.uniform_prob);
    println!("  QAOA sample prob           {:.5}", res.success_prob);
    println!("  amplification              {:.2}x over uniform", res.amplification);
    print!("  top candidates             ");
    for (x, pr) in res.top.iter().take(4) {
        print!("x={x}:{pr:.3}  ");
    }
    println!("\n  => a graded cost landscape QAOA can climb; on a flat hash this is just Grover.\n");
}

/// Second-preimage / tamperable-leaf demonstration.
fn forge_demo() {
    println!("Tamperable leaf via reduced-round second preimage");
    for rounds in [3usize, 5] {
        let fg = attack::forge_leaf(1_000_000, rounds, 0xBEEF ^ rounds as u64);
        println!("  --- {rounds} rounds ---");
        println!("    committed leaf target    {}", fg.committed_target);
        println!("    original wallet value    {}", fg.original_value);
        println!("    recovered preimage       {}", fg.recovered_preimage.as_deref().unwrap_or("<none>"));
        println!("    verifies                 {}", fg.verified);
        println!("    distinct preimages       {}", fg.preimage_count);
        match &fg.second_preimage {
            Some(b2) => println!("    SECOND PREIMAGE b'       {b2}  -> value swappable under unchanged root"),
            None => println!("    second preimage          none at this target (single F_p preimage)"),
        }
        println!("    tamperable               {}", fg.tamperable);
    }
    println!("  => at full ROUNDS=127 the elimination polynomial (deg 3^127≈2^201) cannot be formed;");
    println!("     this works only on the reduced-round knob. See `margin` for where it dies.\n");
}

/// Security-margin curve.
fn margin_demo(ran: usize, recovered: usize) {
    let m = attack::margin(ran, recovered);
    println!("Security margin: algebraic degree of the leaf hash vs round count");
    println!("  field log2(p) = {:.1} ; Grover preimage = 2^{:.1} ; full {} rounds = 2^{:.0} degree\n",
        m.field_bits, m.grover_preimage_bits, m.full_rounds, m.full_degree_log2);
    println!("  {:>6}  {:>12}  {:>10}  {:>13}  {:>4}", "rounds", "deg=2^", "work~2^", "materializable", "ran");
    for p in m.points.iter().filter(|p| p.rounds <= 24 || p.rounds % 4 == 0) {
        println!("  {:>6}  {:>12.1}  {:>10.1}  {:>13}  {:>4}",
            p.rounds, p.degree_log2, p.work_log2,
            if p.materializable { "yes" } else { "NO" },
            if p.recovered { "✓" } else if p.ran { "·" } else { "" });
    }
    println!("\n  degree crosses 2^64 at round {}, 2^96 at round {}, the Grover line (2^{:.0}) at round {}.",
        m.cross_64, m.cross_96, m.grover_preimage_bits, m.cross_grover);
    println!("  => the attack is only feasible while 3^r stays small; ROUNDS=127 is ~{:.0}x past the wall.\n",
        (m.full_degree_log2 / (m.cross_grover as f64 * 1.585)).max(1.0));
}

/// Grover crypto floors (the non-algebraic baseline the margin compares to).
fn floors() {
    println!("Grover crypto floors (keccak-based Merkle + Fiat-Shamir grind) — the baseline\n");
    for bits in [8u32, 10, 12] {
        let o = MerklePreimage::new(bits, 0xABCD);
        let out = grover::search((bits + 6) as usize, |x| o.marks(x));
        println!("  Merkle trunc={bits}b  Grover exponent 2^{:.1} (predicted 2^{:.1})", out.quantum_bits, o.predicted_bits());
    }
    let g = Grind::new(4, 4, 7, 1, 2);
    let out = grover::search((g.predicted_bits() * 2.0).ceil() as usize + 6, |x| g.marks(x));
    println!("  grind pow=4 Q=4 rho=1/2  Grover exponent 2^{:.1} (predicted 2^{:.1})", out.quantum_bits, g.predicted_bits());
    println!("\n  Full scale: Merkle 160b -> 2^80 Grover ; grind (pow24,Q18,rho1/16) -> 2^48 Grover.");
    println!("  Keccak has no algebraic shortcut — Shor is inert. Only Poseidon is algebraically attackable.\n");
}

fn emit(path: &str) {
    // run the executable part up to a round count that finishes quickly
    let viz = attack::assemble(6, 6);
    let json = serde_json::to_string_pretty(&viz).unwrap();
    std::fs::write(path, &json).unwrap();
    println!("wrote visual-memory JSON ({} bytes) to {path}", json.len());
}

fn full() {
    println!("== Quantum algebraic attack lab: in-AIR Poseidon hash ==");
    println!("   Eliminate the round system to a univariate polynomial and root-find it, or");
    println!("   linearize it (XL) and read the solving degree. Both recover verified preimages.");
    println!("   The honest payload is the margin curve. Keccak stays Grover-only; Shor is inert.\n");
    preimage(5);
    xl_demo(2);
    qaoa_demo();
    forge_demo();
    margin_demo(6, 6);
}

fn main() {
    let which = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    match which.as_str() {
        "preimage" => preimage(arg_usize(5)),
        "xl" => xl_demo(arg_usize(2)),
        "qaoa" => qaoa_demo(),
        "forge" => forge_demo(),
        "margin" => margin_demo(6, 6),
        "floors" => floors(),
        "emit" => emit(std::env::args().nth(2).as_deref().unwrap_or("viz.json")),
        _ => full(),
    }
}
