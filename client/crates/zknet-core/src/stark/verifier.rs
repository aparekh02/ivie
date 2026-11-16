//! Native STARK verifier. Same checks, same order, same reject reasons as
//! `StarkVerifier.sol`.
//!
//! ```text
//!  1. statement: txs length, power-of-two count, accounts < 128
//!  2. static shapes (ood, friRoots, lastLayer, friDecommitLen), canonical values
//!  3. channel: traceRoot→α, compRoot→z, OOD→γ, friRoots→β_i, lastLayer, PoW   -> Pow
//!     then the queries (sorted, deduplicated)
//!  4. dynamic shapes (one trace/comp row per query, 8 values per queried coset)
//!  5. OOD: Σ z^(sT) H_s(z) == Σ α^i C_i(mask)/Z_i(z)                        -> Ood
//!  6. trace rows ∈ traceRoot, composition rows ∈ compRoot (batched)        -> TraceMerkle / CompMerkle
//!  7. D(x_q) from the opened rows and the OOD mask
//!  8. per FRI layer: cosets ∈ friRoot_i (batched)                           -> FriMerkle
//!                    each coset holds the expected value                   -> Deep (layer 0) / Fold
//!                    fold each coset by 8 with β_i
//!  9. last layer: folded value == Σ c_k x^k                                 -> LastLayer
//! ```

use super::air::{self, Roots, W};
use super::channel::{self, Channel};
use super::field::{self, F, be32, from_b256, from_u256};
use super::fri::{self, COSET};
use super::merkle;
use super::proof::*;
use super::state::{self, ACCOUNTS, TX_BYTES};
use alloy_primitives::{B256, U256};
use ark_ff::{Field, One, Zero};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize)]
#[serde(tag = "kind")]
pub enum StarkReject {
    #[error("bad batch size {n}")]
    BatchSize { n: usize },
    #[error("tx {index}: account out of range")]
    BadAccount { index: usize },
    #[error("bad length: {what}")]
    Shape { what: &'static str },
    #[error("non-canonical field element in {what}")]
    NonCanonical { what: &'static str },
    #[error("proof of work too weak")]
    Pow,
    #[error("out-of-domain check failed: H(z) != constraints(z)")]
    Ood,
    #[error("challenge hit a domain point")]
    Degenerate,
    #[error("trace rows not in traceRoot")]
    TraceMerkle,
    #[error("composition rows not in compRoot")]
    CompMerkle,
    #[error("FRI layer {layer}: cosets not in its root")]
    FriMerkle { layer: usize },
    #[error("query {q}: FRI layer 0 does not hold D(x)")]
    Deep { q: usize },
    #[error("FRI layer {layer}, item {q}: disagrees with the fold of layer {}", layer - 1)]
    Fold { layer: usize, q: usize },
    #[error("item {q}: last fold != last-layer polynomial")]
    LastLayer { q: usize },
}

impl StarkReject {
    /// Same codes as the Solidity `Shape(uint8)` / `NonCanonical(uint8)` errors.
    pub const SHAPES: [&'static str; 8] = ["ood", "friRoots", "lastLayer", "friDecommitLen", "traceVals", "compVals", "friVals", "friDecommit"];
    pub const CANON: [&'static str; 7] = ["roots", "ood", "lastLayer", "powNonce", "traceVals", "compVals", "friVals"];
}

/// Everything derived from the channel (exposed for experiments).
#[derive(Clone, Debug)]
pub struct Challenges {
    pub log_t: u32,
    pub alpha: F,
    pub z: F,
    pub gamma: F,
    pub betas: Vec<F>,
    /// sorted, deduplicated query positions (bit-reversed LDE indices)
    pub queries: Vec<usize>,
}

pub fn verify(prev: B256, new: B256, txs: &[u8], p: &StarkProof) -> Result<Challenges, StarkReject> {
    use StarkReject::*;
    // 1. statement
    if !txs.len().is_multiple_of(TX_BYTES) {
        return Err(BatchSize { n: txs.len() });
    }
    let b = txs.len() / TX_BYTES;
    if b == 0 || !b.is_power_of_two() || b > state::MAX_BATCH {
        return Err(BatchSize { n: b });
    }
    let txv = state::decode_txs(txs).unwrap();
    if let Some(index) = txv.iter().position(|t| t.from as usize >= ACCOUNTS || t.to as usize >= ACCOUNTS) {
        return Err(BadAccount { index });
    }
    let t = air::trace_len(b);
    let log_t = t.trailing_zeros();
    let n = BLOWUP * t;
    let log_n = n.trailing_zeros();
    let (nl, last_log) = fri::plan(log_t);

    // 2. static shapes, canonical values
    let shapes = [
        p.ood.len() == 2 * W + air::SEGMENTS,
        p.friRoots.len() == nl,
        p.lastLayer.len() == 1 << last_log,
        p.friDecommitLen.len() == nl,
    ];
    if let Some(i) = shapes.iter().position(|ok| !ok) {
        return Err(Shape { what: StarkReject::SHAPES[i] });
    }
    let canon = |v: &[U256]| v.iter().map(|x| from_u256(*x)).collect::<Option<Vec<F>>>();
    let (Some(prev_f), Some(new_f)) = (from_b256(prev), from_b256(new)) else { return Err(NonCanonical { what: "roots" }) };
    let ood = canon(&p.ood).ok_or(NonCanonical { what: "ood" })?;
    let last = canon(&p.lastLayer).ok_or(NonCanonical { what: "lastLayer" })?;
    if p.powNonce >= U256::from(1u128 << 64) {
        return Err(NonCanonical { what: "powNonce" });
    }
    let tv = canon(&p.traceVals).ok_or(NonCanonical { what: "traceVals" })?;
    let cv = canon(&p.compVals).ok_or(NonCanonical { what: "compVals" })?;
    let fv = canon(&p.friVals).ok_or(NonCanonical { what: "friVals" })?;

    // 3. channel
    let mut ch = Channel::new(&channel::public_input(log_t, &prev, &new, txs));
    ch.mix(p.traceRoot.as_slice());
    let alpha = ch.field();
    ch.mix(p.compRoot.as_slice());
    let z = ch.field();
    ch.mix_field(&ood);
    let gamma = ch.field();
    let mut betas = Vec::with_capacity(nl);
    for r in &p.friRoots {
        ch.mix(r.as_slice());
        betas.push(ch.field());
    }
    ch.mix_field(&last);
    let nonce = p.powNonce.to::<u64>();
    if !channel::pow_ok(&ch.pow_seed(POW_BITS), nonce, POW_BITS) {
        return Err(Pow);
    }
    ch.mix(&nonce.to_be_bytes());
    let qs = ch.queries(QUERIES, n);

    // 4. dynamic shapes
    let mut cosets_per_layer = Vec::with_capacity(nl);
    let mut pos = qs.clone();
    for _ in 0..nl {
        let mut c: Vec<usize> = pos.iter().map(|x| x / COSET).collect();
        c.dedup();
        cosets_per_layer.push(c.len());
        pos = c;
    }
    let dlen = U256::from(p.friDecommit.len());
    let dec_ok = p.friDecommitLen.iter().all(|l| *l <= dlen) && p.friDecommitLen.iter().map(|l| l.to::<usize>()).sum::<usize>() == p.friDecommit.len();
    let dyn_shapes = [
        p.traceVals.len() == qs.len() * W,
        p.compVals.len() == qs.len() * air::SEGMENTS,
        p.friVals.len() == cosets_per_layer.iter().sum::<usize>() * COSET,
        dec_ok,
    ];
    if let Some(i) = dyn_shapes.iter().position(|ok| !ok) {
        return Err(Shape { what: StarkReject::SHAPES[4 + i] });
    }

    // 5. OOD consistency
    let g = field::root(t);
    let expect = ood_expected(z, t, &txv, &ood, prev_f, new_f, alpha)?;
    let zt = field::pow(z, t as u64);
    let hs = &ood[2 * W..];
    if hs[0] + zt * hs[1] + zt * zt * hs[2] != expect {
        return Err(Ood);
    }

    // 6. batched trace / composition decommitments
    let row_leaves = |vals: &[F], width: usize| -> Vec<(usize, B256)> {
        qs.iter().enumerate().map(|(i, &q)| (q, merkle::leaf(&vals[i * width..(i + 1) * width].iter().flat_map(be32).collect::<Vec<u8>>()))).collect()
    };
    if !merkle::verify_multi(&p.traceRoot, log_n as usize, &row_leaves(&tv, W), &p.traceDecommit) {
        return Err(TraceMerkle);
    }
    if !merkle::verify_multi(&p.compRoot, log_n as usize, &row_leaves(&cv, air::SEGMENTS), &p.compDecommit) {
        return Err(CompMerkle);
    }

    // 7. DEEP composition at the queried points
    let gz = g * z;
    let gp: Vec<F> = std::iter::successors(Some(F::one()), |x| Some(*x * gamma)).take(2 * W + air::SEGMENTS).collect();
    let xs: Vec<F> = qs.iter().map(|&q| fri::point(field::offset(), log_n, q)).collect();
    let mut den: Vec<F> = xs.iter().flat_map(|x| [*x - z, *x - gz]).collect();
    if den.iter().any(|d| d.is_zero()) {
        return Err(Degenerate);
    }
    ark_ff::batch_inversion(&mut den);
    let mut items: Vec<(usize, F)> = qs
        .iter()
        .enumerate()
        .map(|(i, &q)| {
            let row = &tv[i * W..(i + 1) * W];
            let crow = &cv[i * air::SEGMENTS..(i + 1) * air::SEGMENTS];
            let (mut a, mut bs) = (F::zero(), F::zero());
            for j in 0..W {
                a += gp[2 * j] * (row[j] - ood[j]);
                bs += gp[2 * j + 1] * (row[j] - ood[W + j]);
            }
            for s in 0..air::SEGMENTS {
                a += gp[2 * W + s] * (crow[s] - ood[2 * W + s]);
            }
            (q, a * den[2 * i] + bs * den[2 * i + 1])
        })
        .collect();

    // 8. FRI layers
    let mut off = field::offset();
    let mut log_m = log_n;
    let mut fo = 0; // offset into friVals
    let mut doff = 0; // offset into friDecommit
    for (layer, &beta) in betas.iter().enumerate() {
        let mut cosets: Vec<usize> = items.iter().map(|(q, _)| q / COSET).collect();
        cosets.dedup();
        let vals = &fv[fo..fo + cosets.len() * COSET];
        fo += cosets.len() * COSET;
        let leaves: Vec<(usize, B256)> =
            cosets.iter().enumerate().map(|(i, &c)| (c, merkle::leaf(&vals[i * COSET..(i + 1) * COSET].iter().flat_map(be32).collect::<Vec<u8>>()))).collect();
        let dl = p.friDecommitLen[layer].to::<usize>();
        if !merkle::verify_multi(&p.friRoots[layer], (log_m - fri::STEP) as usize, &leaves, &p.friDecommit[doff..doff + dl]) {
            return Err(FriMerkle { layer });
        }
        doff += dl;
        let mut ci = 0;
        for (i, &(q, v)) in items.iter().enumerate() {
            while cosets[ci] != q / COSET {
                ci += 1;
            }
            if vals[ci * COSET + q % COSET] != v {
                return Err(if layer == 0 { Deep { q: i } } else { Fold { layer, q: i } });
            }
        }
        let mut x0: Vec<F> = cosets.iter().map(|&c| fri::point(off, log_m, c * COSET)).collect();
        ark_ff::batch_inversion(&mut x0);
        items = cosets.iter().enumerate().map(|(i, &c)| (c, fri::fold_coset(&vals[i * COSET..(i + 1) * COSET], x0[i], beta))).collect();
        off = field::pow(off, COSET as u64);
        log_m -= fri::STEP;
    }

    // 9. last layer
    for (i, &(q, v)) in items.iter().enumerate() {
        if air::horner(&last, fri::point(off, log_m, q)) != v {
            return Err(LastLayer { q: i });
        }
    }
    Ok(Challenges { log_t, alpha, z, gamma, betas, queries: qs })
}

/// What H(z) must equal, given the claimed OOD frame: Σ α^i C_i(frame)/Z_i(z).
pub fn ood_expected(z: F, t: usize, txs: &[state::Tx], ood: &[F], prev: F, new: F, alpha: F) -> Result<F, StarkReject> {
    let g = field::root(t);
    let g_inv = g.inverse().unwrap();
    let roots = Roots::get();
    let mut den = air::denominators(z, t, g_inv, &roots);
    if den.iter().any(|d| d.is_zero()) {
        return Err(StarkReject::Degenerate);
    }
    ark_ff::batch_inversion(&mut den);
    let fac = air::factors_from_inv(z, t, g_inv, &roots, &den);
    let pc = air::periodic_coeffs();
    let y = field::pow(z, (t / 128) as u64);
    let c = [air::horner(&pc[0], y), air::horner(&pc[1], y), air::horner(&pc[2], y)];
    let (va, vm) = air::update_targets(txs);
    let mut xu = field::pow(g, (air::UPDATE - 1) as u64);
    let h = field::pow(g, air::UPDATE as u64);
    for _ in 0..va.len() {
        if xu == z {
            return Err(StarkReject::Degenerate);
        }
        xu *= h;
    }
    let v = (air::interp_update_ends(z, t, g, &va), air::interp_update_ends(z, t, g, &vm));
    let num = air::numerators(&ood[..W], &ood[W..2 * W], &c, v, (prev, new));
    Ok(air::combine(&num, &fac, alpha))
}
