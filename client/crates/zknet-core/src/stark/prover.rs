//! The STARK prover for the rollup AIR (Stone-style pipeline).
//!
//! ```text
//!  trace (T×18) ─iFFT─► t_j ─LDE on 3·⟨ω_16T⟩, bit-reversed─► Merkle(rows) ─► traceRoot ─► α
//!  H = Σ α^i C_i/Z_i on the LDE ─► H0 + x^T H1 + x^2T H2 ─► Merkle(rows) ─► compRoot ─► z
//!  OOD mask: t_j(z), t_j(gz), H_s(z) ─► γ
//!  DEEP D(x) = Σ γ^k (t_j(x) - t_j(z))/(x - z) + (t_j(x) - t_j(gz))/(x - gz) + (H_s(x) - H_s(z))/(x - z)
//!  FRI: commit D with one 8-coset per leaf ─► β_0 ─► fold by 8 ─► commit ─► ... ─► last layer coefficients
//!  proof of work (24 bits) ─► 18 queries ─► batched multi-proof decommitments
//! ```

use super::air::{self, Public, Roots, W};
use super::channel::{self, Channel};
use super::field::{self, F, be32, to_b256};
use super::fri::{self, COSET, bitrev};
use super::merkle::{self, Tree};
use super::proof::*;
use super::state::{self, State, Tx, TxError};
use alloy_primitives::B256;
use ark_ff::{Field, One, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rayon::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error(transparent)]
    Tx(#[from] TxError),
    #[error("batch of {0} txs: must be a power of two in 1..={max}", max = state::MAX_BATCH)]
    BatchSize(usize),
    #[error("trace violates constraint {constraint} at row {row} (AIR bug)")]
    Constraint { constraint: usize, row: usize },
    #[error("{0} has degree above its bound (AIR bug)")]
    Degree(&'static str),
}

/// Everything a prover produces: the statement and the proof.
pub struct Proven {
    pub public: Public,
    pub proof: Proof,
    pub timings: Vec<(&'static str, std::time::Duration)>,
}

impl Proven {
    pub fn calldata(&self) -> Vec<u8> {
        self.proof.calldata(&self.public.prev_root, &self.public.new_root, &state::encode_txs(&self.public.txs))
    }
}

/// Knobs for an adversarial prover. The default is the honest prover.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Claim this post-state root instead of the real one.
    pub claim_new_root: Option<F>,
    /// Skip the honest prover's self-checks (constraint and degree checks):
    /// commit to whatever the (tampered) trace gives, truncating H and the
    /// last FRI layer to their degree bounds.
    pub unchecked: bool,
    /// Lie about H_0(z) so the OOD equation holds anyway. The DEEP quotient
    /// (H_0(x) - H_0(z))/(x - z) is then not a polynomial, and FRI must catch it.
    pub fake_ood: bool,
}

fn row_leaf(cols: &[Vec<F>], k: usize) -> B256 {
    merkle::leaf(&cols.iter().flat_map(|c| be32(&c[k])).collect::<Vec<u8>>())
}

/// Reorders natural-order evaluations into bit-reversed order.
fn to_bitrev(v: &[F]) -> Vec<F> {
    let log = v.len().trailing_zeros();
    (0..v.len()).into_par_iter().map(|i| v[bitrev(i, log)]).collect()
}

/// Proves `txs` against `state`, which is advanced to the post-state.
pub fn prove(state: &mut State, txs: &[Tx]) -> Result<Proven, ProveError> {
    prove_with(state, txs, &Options::default(), |_| {})
}

/// Like [`prove`], but `tamper` may edit the trace (column-major, `air::W`
/// columns × T rows) before it is committed.
pub fn prove_with(state: &mut State, txs: &[Tx], opts: &Options, tamper: impl FnOnce(&mut [Vec<F>])) -> Result<Proven, ProveError> {
    let b = txs.len();
    if !b.is_power_of_two() || b > state::MAX_BATCH {
        return Err(ProveError::BatchSize(b));
    }
    let mut timings = vec![];
    let mut clock = std::time::Instant::now();
    let mut lap = |name: &'static str, timings: &mut Vec<_>| {
        timings.push((name, clock.elapsed()));
        clock = std::time::Instant::now();
    };

    let prev_root = state.root();
    let mut post = state.clone();
    let mut tr = air::build_trace(&mut post, txs)?;
    tamper(&mut tr);
    let public = Public { prev_root, new_root: opts.claim_new_root.unwrap_or(post.root()), txs: txs.to_vec() };
    if !opts.unchecked {
        air::check_trace(&tr, &public).map_err(|(constraint, row)| ProveError::Constraint { constraint, row })?;
    }
    lap("trace", &mut timings);

    let t = tr[0].len();
    let log_t = t.trailing_zeros();
    let n = BLOWUP * t;
    let log_n = n.trailing_zeros();
    let tdom = Radix2EvaluationDomain::<F>::new(t).unwrap();
    let ldom = Radix2EvaluationDomain::<F>::new(n).unwrap().get_coset(field::offset()).unwrap();
    let g = tdom.group_gen();
    let g_inv = g.inverse().unwrap();
    let x_of = |k: usize| ldom.element(k); // natural order

    // 1. trace polynomials, LDE, commitment (rows in bit-reversed order)
    let coeffs: Vec<Vec<F>> = tr.par_iter().map(|c| tdom.ifft(c)).collect();
    let lde: Vec<Vec<F>> = coeffs.par_iter().map(|c| ldom.fft(c)).collect();
    let lde_br: Vec<Vec<F>> = lde.iter().map(|c| to_bitrev(c)).collect();
    let trace_tree = Tree::new((0..n).into_par_iter().map(|k| row_leaf(&lde_br, k)).collect());
    lap("trace LDE + commit", &mut timings);

    let data = state::encode_txs(txs);
    let mut ch = Channel::new(&channel::public_input(log_t, &to_b256(&prev_root), &to_b256(&public.new_root), &data));
    ch.mix(trace_tree.root().as_slice());
    let alpha = ch.field();

    // 2. composition polynomial H, evaluated pointwise on the LDE (natural order)
    let roots = Roots::get();
    let pc = air::periodic_coeffs();
    let period = BLOWUP * 128; // x^(T/128) repeats every 16·128 LDE points
    let per: Vec<[F; 3]> = (0..period)
        .into_par_iter()
        .map(|k| {
            let y = field::pow(x_of(k), (t / 128) as u64);
            [air::horner(&pc[0], y), air::horner(&pc[1], y), air::horner(&pc[2], y)]
        })
        .collect();
    let (va, vm) = air::update_targets(txs);
    let sdom = Radix2EvaluationDomain::<F>::new(va.len()).unwrap().get_coset(field::pow(g, (air::UPDATE - 1) as u64)).unwrap();
    let v_acct = ldom.fft(&sdom.ifft(&va));
    let v_amt = ldom.fft(&sdom.ifft(&vm));
    let pi = (public.prev_root, public.new_root);
    let h_evals: Vec<F> = (0..n)
        .into_par_iter()
        .chunks(4096)
        .flat_map_iter(|ks| {
            let mut dens: Vec<F> = ks.iter().flat_map(|&k| air::denominators(x_of(k), t, g_inv, &roots)).collect();
            ark_ff::batch_inversion(&mut dens);
            ks.iter()
                .enumerate()
                .map(|(i, &k)| {
                    let inv: [F; 7] = dens[7 * i..7 * i + 7].try_into().unwrap();
                    let fac = air::factors_from_inv(x_of(k), t, g_inv, &roots, &inv);
                    let cur: Vec<F> = (0..W).map(|j| lde[j][k]).collect();
                    let nxt: Vec<F> = (0..W).map(|j| lde[j][(k + BLOWUP) % n]).collect();
                    let num = air::numerators(&cur, &nxt, &per[k % period], (v_acct[k], v_amt[k]), pi);
                    air::combine(&num, &fac, alpha)
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let mut h_coeffs = ldom.ifft(&h_evals);
    if h_coeffs[air::SEGMENTS * t..].iter().any(|c| !c.is_zero()) {
        if !opts.unchecked {
            return Err(ProveError::Degree("composition H"));
        }
        h_coeffs.truncate(air::SEGMENTS * t);
    }
    let segs: Vec<Vec<F>> = (0..air::SEGMENTS).map(|s| h_coeffs[s * t..(s + 1) * t].to_vec()).collect();
    let comp: Vec<Vec<F>> = segs.par_iter().map(|c| ldom.fft(c)).collect();
    let comp_br: Vec<Vec<F>> = comp.iter().map(|c| to_bitrev(c)).collect();
    let comp_tree = Tree::new((0..n).into_par_iter().map(|k| row_leaf(&comp_br, k)).collect());
    lap("composition + commit", &mut timings);

    ch.mix(comp_tree.root().as_slice());
    let z = ch.field();
    let gz = g * z;

    // 3. out-of-domain mask values
    let mut ood: Vec<F> = coeffs.iter().map(|c| air::horner(c, z)).collect();
    ood.extend(coeffs.iter().map(|c| air::horner(c, gz)));
    ood.extend(segs.iter().map(|c| air::horner(c, z)));
    if opts.fake_ood {
        let expect = super::verifier::ood_expected(z, t, txs, &ood, public.prev_root, public.new_root, alpha).unwrap_or_default();
        let zt = field::pow(z, t as u64);
        ood[2 * W] = expect - zt * ood[2 * W + 1] - zt * zt * ood[2 * W + 2];
    }
    ch.mix_field(&ood);
    let gamma = ch.field();

    // 4. DEEP composition (natural order), then bit-reverse for FRI
    let gp: Vec<F> = std::iter::successors(Some(F::one()), |x| Some(*x * gamma)).take(2 * W + air::SEGMENTS).collect();
    let mut inv_z: Vec<F> = (0..n).into_par_iter().map(|k| x_of(k) - z).collect();
    let mut inv_gz: Vec<F> = (0..n).into_par_iter().map(|k| x_of(k) - gz).collect();
    ark_ff::batch_inversion(&mut inv_z);
    ark_ff::batch_inversion(&mut inv_gz);
    let deep: Vec<F> = (0..n)
        .into_par_iter()
        .map(|k| {
            let (mut a, mut bs) = (F::zero(), F::zero());
            for j in 0..W {
                a += gp[2 * j] * (lde[j][k] - ood[j]);
                bs += gp[2 * j + 1] * (lde[j][k] - ood[W + j]);
            }
            for s in 0..air::SEGMENTS {
                a += gp[2 * W + s] * (comp[s][k] - ood[2 * W + s]);
            }
            a * inv_z[k] + bs * inv_gz[k]
        })
        .collect();
    lap("DEEP", &mut timings);

    // 5. FRI: commit each layer as 8-cosets, fold by 8
    let (nl, last_log) = fri::plan(log_t);
    let mut layers: Vec<(Vec<F>, Tree)> = Vec::with_capacity(nl);
    let mut f = to_bitrev(&deep);
    let mut off = field::offset();
    let mut log_m = log_n;
    let mut fri_roots = vec![];
    for _ in 0..nl {
        let tree = Tree::new(f.par_chunks(COSET).map(|c| merkle::leaf(&c.iter().flat_map(be32).collect::<Vec<u8>>())).collect());
        ch.mix(tree.root().as_slice());
        fri_roots.push(tree.root());
        let beta = ch.field();
        let mut x0: Vec<F> = (0..f.len() / COSET).into_par_iter().map(|c| fri::point(off, log_m, c * COSET)).collect();
        ark_ff::batch_inversion(&mut x0);
        let next: Vec<F> = f.par_chunks(COSET).zip(x0.par_iter()).map(|(v, xi)| fri::fold_coset(v, *xi, beta)).collect();
        layers.push((f, tree));
        f = next;
        off = field::pow(off, COSET as u64);
        log_m -= fri::STEP;
    }
    let natural: Vec<F> = (0..f.len()).map(|i| f[bitrev(i, log_m)]).collect();
    let rdom = Radix2EvaluationDomain::<F>::new(f.len()).unwrap().get_coset(off).unwrap();
    let mut last_layer = rdom.ifft(&natural);
    let keep = 1usize << last_log;
    if last_layer[keep..].iter().any(|c| !c.is_zero()) && !opts.unchecked {
        return Err(ProveError::Degree("FRI last layer"));
    }
    last_layer.truncate(keep);
    ch.mix_field(&last_layer);
    lap("FRI", &mut timings);

    // 6. proof of work
    let seed = ch.pow_seed(POW_BITS);
    let pow_nonce = channel::grind(&seed, POW_BITS);
    ch.mix(&pow_nonce.to_be_bytes());
    lap("grind", &mut timings);

    // 7. queries and batched decommitments
    let qs = ch.queries(QUERIES, n);
    let trace_vals: Vec<F> = qs.iter().flat_map(|&p| (0..W).map(move |j| (j, p))).map(|(j, p)| lde_br[j][p]).collect();
    let comp_vals: Vec<F> = qs.iter().flat_map(|&p| (0..air::SEGMENTS).map(move |s| (s, p))).map(|(s, p)| comp_br[s][p]).collect();
    let mut fri_vals = vec![];
    let mut fri_decommit = vec![];
    let mut pos = qs.clone();
    for (vals, tree) in &layers {
        let mut cosets: Vec<usize> = pos.iter().map(|p| p / COSET).collect();
        cosets.dedup();
        for &c in &cosets {
            fri_vals.extend_from_slice(&vals[c * COSET..(c + 1) * COSET]);
        }
        fri_decommit.push(tree.multiproof(&cosets));
        pos = cosets;
    }
    lap("queries", &mut timings);

    *state = post;
    Ok(Proven {
        public,
        proof: Proof {
            log_t,
            trace_root: trace_tree.root(),
            comp_root: comp_tree.root(),
            ood,
            fri_roots,
            last_layer,
            pow_nonce,
            trace_vals,
            trace_decommit: trace_tree.multiproof(&qs),
            comp_vals,
            comp_decommit: comp_tree.multiproof(&qs),
            fri_vals,
            fri_decommit,
        },
        timings,
    })
}
