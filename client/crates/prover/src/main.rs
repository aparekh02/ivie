// claim in, first failed check out.
//
//   cargo run --release -p prover            native verifier
//   cargo run --release -p prover -- chain   StarkVerifier.sol via zknetd
//
// trace  T = 2048·|txs| rows × 18 cols (column ids: stark::air::O0 .. BIT), one row per Poseidon round
// commit traceRoot ─α─ compRoot ─z─ OOD t(z), t(gz), H(z) ─γ─ FRI roots (fold 8) ─β─ last layer ─ pow 24 ─ 18 queries
// accept iff  H(z) = Σ α^i C_i(z)/Z_i(z)  and every opened value hashes to a root committed before z
// lies    stark::Options { claim_new_root, unchecked, fake_ood } + a closure over the trace

use zknet_sdk::Zknet;
use zknet_sdk::stark::{self, Chain, Claim, F, Native, Options, Oracle, State, Tx};

fn main() {
    let txs = vec![Tx { from: 3, to: 9, amount: 1234 }, Tx { from: 9, to: 127, amount: 5 }];
    let pre = State::genesis();

    let mut o: Box<dyn Oracle> =
        if std::env::args().any(|a| a == "chain") { Box::new(Chain::new(Zknet::connect().unwrap()).unwrap()) } else { Box::new(Native::default()) };

    let mut s = pre.clone();
    let honest = Claim::from_proven(&stark::prove(&mut s, &txs).unwrap());

    run(&mut *o, &pre, &txs, &honest);
    eprintln!("queries: {}", o.queries());
}

fn run(o: &mut dyn Oracle, pre: &State, txs: &[Tx], honest: &Claim) {
    assert_eq!(o.ask(honest), Ok(()));

    let mut s = pre.clone();
    let lie = Options { unchecked: true, ..Default::default() };
    let forged = stark::prove_with(&mut s, txs, &lie, |t: &mut [Vec<F>]| {
        let _ = t;
    })
    .unwrap();
    let _ = o.ask(&Claim::from_proven(&forged));
}
