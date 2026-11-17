//! qattack: quantum attack lab for the zknet STARK verifier.
//!
//!   cargo run --release -p quantum -- floors   Grover crypto floors (Merkle / grind)

use quantum::grover;
use quantum::oracle::{Grind, MerklePreimage};

/// Grover crypto floors (the non-algebraic keccak baseline).
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
}

fn main() {
    floors();
}
