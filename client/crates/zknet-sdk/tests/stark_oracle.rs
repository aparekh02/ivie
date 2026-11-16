//! Native vs on-chain STARK verifier, reason for reason.
//! Needs zknetd running and `zkrollup deploy` done; skips otherwise.

use zknet_core::U256;
use zknet_sdk::Zknet;
use zknet_sdk::stark::{self, Chain, Claim, Native, Options, Oracle, State, Tx, field};

#[test]
fn native_equals_chain() {
    let Ok(conn) = Zknet::connect() else {
        eprintln!("skip: zknetd not running");
        return;
    };
    let mut chain = Chain::new(conn).expect("contracts/out (forge build)");
    let mut native = Native::default();
    let txs = vec![Tx { from: 1, to: 2, amount: 77 }, Tx { from: 2, to: 9, amount: 70 }];
    let mut s = State::genesis();
    let honest = Claim::from_proven(&stark::prove(&mut s, &txs).unwrap());
    if chain.call(&honest).is_err() {
        eprintln!("skip: rollup not deployed (zkrollup deploy)");
        return;
    }

    let mut cases: Vec<(String, Claim)> = vec![("honest".into(), honest.clone())];
    let bump = |x: &mut U256| *x = (*x + U256::from(1)) % field::P;
    let uq = honest.proof.compVals.len() / 3;
    for q in [0usize, uq / 2, uq - 1] {
        let mut c = honest.clone();
        bump(&mut c.proof.traceVals[q * 18 + 5]);
        cases.push((format!("traceVals q{q}"), c));
        let mut c = honest.clone();
        bump(&mut c.proof.compVals[q * 3]);
        cases.push((format!("compVals q{q}"), c));
    }
    let fv = honest.proof.friVals.len();
    for i in [0usize, 9, fv / 2, fv - 1] {
        let mut c = honest.clone();
        bump(&mut c.proof.friVals[i]);
        cases.push((format!("friVals[{i}]"), c));
    }
    for (name, k) in [("traceDecommit", 0usize), ("compDecommit", 1), ("friDecommit", 2)] {
        let mut c = honest.clone();
        let v = match k {
            0 => &mut c.proof.traceDecommit,
            1 => &mut c.proof.compDecommit,
            _ => &mut c.proof.friDecommit,
        };
        v[3] = Default::default();
        cases.push((format!("{name}[3] zeroed"), c));
    }
    let mut c = honest.clone();
    c.proof.traceDecommit.pop();
    cases.push(("traceDecommit short".into(), c));
    for i in [0usize, 17, 36, 38] {
        let mut c = honest.clone();
        bump(&mut c.proof.ood[i]);
        cases.push((format!("ood[{i}]"), c));
    }
    let mut c = honest.clone();
    bump(&mut c.proof.lastLayer[3]);
    cases.push(("lastLayer".into(), c));
    let mut c = honest.clone();
    c.proof.ood.pop();
    cases.push(("short ood".into(), c));
    let mut c = honest.clone();
    c.proof.ood[0] = field::P;
    cases.push(("non-canonical".into(), c));
    let mut c = honest.clone();
    c.txs.truncate(10);
    cases.push(("txs truncated".into(), c));
    // adversarial provers
    let mut minted = State::genesis();
    minted.set(5, 1);
    for fake_ood in [false, true] {
        let mut s = State::genesis();
        let o = Options { claim_new_root: Some(minted.root()), unchecked: true, fake_ood };
        cases.push((format!("false root fake_ood={fake_ood}"), Claim::from_proven(&stark::prove_with(&mut s, &txs, &o, |_| {}).unwrap())));
    }

    for (name, c) in &cases {
        let (n, ch) = (native.ask(c), chain.ask(c));
        eprintln!("{name:<28} native={n:?}");
        assert_eq!(n, ch, "{name}: native and chain disagree");
    }
    assert!(native.ask(&honest).is_ok());
    // the daemon's own differential endpoint agrees too
    let mut zk = Zknet::connect().unwrap();
    for (name, c) in cases.iter().step_by(4) {
        let r: zknet_sdk::core::api::VerifyResult = zk.request("zk_verify", serde_json::json!({ "calldata": zknet_sdk::core::Bytes::from(c.calldata()) })).unwrap();
        assert!(r.agree, "{name}: zk_verify disagree {r:?}");
    }
    eprintln!("{} cases agree", cases.len());
}
