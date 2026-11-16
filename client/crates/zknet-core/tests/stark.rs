use zknet_core::stark::{self, State, StarkReject, Tx, field};

fn batch() -> Vec<Tx> {
    vec![Tx { from: 3, to: 9, amount: 1234 }, Tx { from: 9, to: 127, amount: 5 }]
}

#[test]
fn prove_verify_roundtrip() {
    let mut s = State::genesis();
    let pre = s.clone();
    let p = stark::prove(&mut s, &batch()).unwrap();
    for (n, d) in &p.timings {
        eprintln!("{n:>22}: {d:?}");
    }
    let mut chk = pre.clone();
    chk.apply(&batch()).unwrap();
    assert_eq!(chk.root(), s.root());
    assert_eq!(p.public.new_root, s.root());
    let abi = p.proof.to_abi();
    let txs = stark::state::encode_txs(&batch());
    eprintln!("proof size {} bytes", p.proof.size());
    let prev = field::to_b256(&pre.root());
    let new = field::to_b256(&s.root());
    stark::verify(prev, new, &txs, &abi).unwrap();
    // wrong claimed root, wrong txs, tampered values
    assert!(stark::verify(prev, prev, &txs, &abi).is_err());
    let mut t2 = txs.clone();
    t2[9] ^= 1;
    assert!(stark::verify(prev, new, &t2, &abi).is_err());
    let mut a = abi.clone();
    a.ood[0] += alloy_primitives::U256::from(1);
    assert_eq!(stark::verify(prev, new, &txs, &a).unwrap_err(), StarkReject::Pow);
}

#[test]
fn bad_tx_is_unprovable() {
    let mut s = State::genesis();
    assert!(stark::prove(&mut s, &[Tx { from: 0, to: 1, amount: 2_000_000 }]).is_err());
}

/// Adversarial provers: each lie is caught by a specific check.
#[test]
fn adversarial_provers() {
    use stark::{Options, prove_with};
    let txs = batch();
    let pre = State::genesis();
    let prev = field::to_b256(&pre.root());
    let data = stark::state::encode_txs(&txs);
    let mut minted = pre.clone();
    minted.set(5, minted.balances[5] + 1_000_000);
    let run = |opts: Options, tamper: &dyn Fn(&mut [Vec<stark::F>])| {
        let mut s = pre.clone();
        let p = prove_with(&mut s, &txs, &opts, |t| tamper(t)).unwrap();
        stark::verify(prev, field::to_b256(&p.public.new_root), &data, &p.proof.to_abi()).map(|_| ())
    };
    let lie = Options { claim_new_root: Some(minted.root()), unchecked: true, ..Default::default() };
    assert_eq!(run(lie.clone(), &|_| {}), Err(StarkReject::Ood), "false root, honest OOD");
    let lie_ood = Options { fake_ood: true, ..lie };
    let e = run(lie_ood, &|_| {}).unwrap_err();
    assert!(matches!(e, StarkReject::LastLayer { .. } | StarkReject::Fold { .. }), "false root + faked OOD: {e:?}");
    // edit a balance inside the committed trace (credit 1 extra coin)
    let edit = |t: &mut [Vec<stark::F>]| {
        for x in &mut t[stark::air::BN][1024..2048] {
            *x += stark::F::from(1u64);
        }
    };
    let unchecked = Options { unchecked: true, ..Default::default() };
    assert_eq!(run(unchecked, &edit), Err(StarkReject::Ood), "trace edit");
    // the honest prover refuses to prove its own tampered trace
    let mut s = pre.clone();
    assert!(prove_with(&mut s, &txs, &Options::default(), edit).is_err());
}
