//! The rollup AIR: "applying this batch moves the state root from prevRoot
//! to newRoot".
//!
//! Each transfer is two single-leaf Merkle updates, a debit then a credit. Each
//! update walks the path from the leaf to the root twice, in parallel lanes:
//! lane O hashes the OLD leaf up to the old root, lane N hashes the NEW leaf up
//! to the new root, and both use the same siblings and direction bits.
//!
//! ```text
//!   row i:  update u = i / 1024 (even: debit, odd: credit; tx = u / 2)
//!           cycle  c = (i / 128) % 8 (0: leaf hash, 1..=7: tree levels)
//!           round  r = i % 128 (rows 0..126: rounds, row 127: permutation output)
//!   T = 2048 · batch_len rows
//! ```
//!
//! Every constraint is enforced on a coset-structured set of rows (all rows,
//! every 128th, every 1024th, ...), so each zerofier has a closed form the
//! verifier evaluates in O(log T).
//!
//! The constraints, grouped by zerofier (the same order as `Air.sol`):
//! ```text
//!   A  rows ≠ 127 mod 128     next lane state = Poseidon round(cur + C_r)   (6)
//!   B  rows ≠ 127 mod 128     sib, dir, idx, pw constant within a cycle     (4)
//!   C  rows ≠ 1023 mod 1024   bo, bn, amt, acct, sgn, root constant          (6)
//!   D  127 mod 128, not 1023  absorb (out, sib) by dir into both lanes,
//!                             idx += dir·pw, pw *= 2                         (8)
//!   E  1023 mod 1024, not last   next update: lanes = (bo|bn, 0, 1),
//!                             idx = 0, pw = 1, root' = new root              (9)
//!   F  1023 mod 1024          sgn' = -sgn                                    (1)
//!   H  1023 mod 1024          old root == root, bn = bo + sgn·amt,
//!                             acct == idx, acct == V_acct, amt == V_amt      (5)
//!   I  all rows               dir, bit binary                                (2)
//!   J  rows ≠ 63 mod 64       acc' = 2 acc + bit'                            (1)
//!   K  63 mod 64              acc' = bit'                                    (1)
//!   L  63 mod 1024            acc == bn  (so bn ∈ [0, 2^64))                 (1)
//!   M  row 0                  first update's lanes, idx, pw, sgn = -1,
//!                             root = prevRoot                               (10)
//!   N  last row               lane N output = newRoot                       (1)
//! ```
//! V_acct / V_amt interpolate the tx data on the update-end rows, so the
//! proof is bound to the exact batch the verifier saw on L1.

use super::field::{self, F};
use super::hash;
use super::state::{DEPTH, State, Tx, TxError};
use ark_ff::{AdditiveGroup, Field, One, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

pub const W: usize = 18;
pub const O0: usize = 0;
pub const N0: usize = 3;
pub const SIB: usize = 6;
pub const DIR: usize = 7;
pub const IDX: usize = 8;
pub const PW: usize = 9;
pub const BO: usize = 10;
pub const BN: usize = 11;
pub const AMT: usize = 12;
pub const ACCT: usize = 13;
pub const SGN: usize = 14;
pub const ROOT: usize = 15;
pub const ACC: usize = 16;
pub const BIT: usize = 17;

pub const CYCLE: usize = 128;
pub const UPDATE: usize = CYCLE * (DEPTH + 1); // 1024
pub const TX_ROWS: usize = 2 * UPDATE;
pub const RANGE: usize = 64;

/// Constraint count (55) and the zerofier group of each, in order.
pub const NC: usize = 55;
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Group {
    A,
    C,
    D,
    E,
    F,
    I,
    J,
    K,
    L,
    M,
    N,
}
pub const GROUPS: [(Group, usize); 11] = [
    (Group::A, 10), // A + B
    (Group::C, 6),
    (Group::D, 8),
    (Group::E, 9),
    (Group::F, 6), // F + H
    (Group::I, 2),
    (Group::J, 1),
    (Group::K, 1),
    (Group::L, 1),
    (Group::M, 10),
    (Group::N, 1),
];

/// Composition degree bound (in units of T): deg H < 3T.
pub const SEGMENTS: usize = 3;

pub fn trace_len(batch: usize) -> usize {
    TX_ROWS * batch
}

#[derive(Clone, Debug)]
pub struct Public {
    pub prev_root: F,
    pub new_root: F,
    pub txs: Vec<Tx>,
}

/// Interpolation targets on update-end rows: (acct, amt) for update u.
pub fn update_targets(txs: &[Tx]) -> (Vec<F>, Vec<F>) {
    let mut a = Vec::with_capacity(2 * txs.len());
    let mut m = Vec::with_capacity(2 * txs.len());
    for t in txs {
        a.push(F::from(t.from as u64));
        a.push(F::from(t.to as u64));
        m.push(F::from(t.amount));
        m.push(F::from(t.amount));
    }
    (a, m)
}

/// Builds the execution trace (column-major), and moves `state` forward.
pub fn build_trace(state: &mut State, txs: &[Tx]) -> Result<Vec<Vec<F>>, TxError> {
    let t = trace_len(txs.len());
    let mut tr = vec![vec![F::zero(); t]; W];
    let mut u = 0usize;
    for (index, tx) in txs.iter().enumerate() {
        for (acct, debit) in [(tx.from, true), (tx.to, false)] {
            let a = acct as usize;
            if a >= super::state::ACCOUNTS {
                return Err(TxError::Account(acct));
            }
            let bo = state.balances[a];
            let bn = if debit {
                bo.checked_sub(tx.amount).ok_or(TxError::Insufficient { index, balance: bo, amount: tx.amount })?
            } else {
                bo.checked_add(tx.amount).ok_or(TxError::Overflow { index })?
            };
            let root = state.root();
            let sibs = state.path(a);
            fill_update(&mut tr, u * UPDATE, a, bo, bn, tx.amount, if debit { field::neg_one() } else { F::one() }, root, &sibs);
            state.set(a, bn);
            u += 1;
        }
    }
    Ok(tr)
}

#[allow(clippy::too_many_arguments)]
fn fill_update(tr: &mut [Vec<F>], base: usize, acct: usize, bo: u64, bn: u64, amt: u64, sgn: F, root: F, sibs: &[F]) {
    let (fbo, fbn) = (F::from(bo), F::from(bn));
    let mut o_in = [fbo, F::zero(), F::from(hash::TAG_LEAF)];
    let mut n_in = [fbn, F::zero(), F::from(hash::TAG_LEAF)];
    let (mut idx, mut pw) = (F::zero(), F::one());
    for c in 0..=DEPTH {
        let (sib, dir) = if c == 0 { (F::zero(), 0u64) } else { (sibs[c - 1], ((acct >> (c - 1)) & 1) as u64) };
        if c > 0 {
            let fd = F::from(dir);
            idx += fd * pw;
            pw = pw.double();
            let tag = F::from(hash::TAG_NODE);
            o_in = if dir == 1 { [sib, o_in[0], tag] } else { [o_in[0], sib, tag] };
            n_in = if dir == 1 { [sib, n_in[0], tag] } else { [n_in[0], sib, tag] };
        }
        let ot = hash::trace(o_in);
        let nt = hash::trace(n_in);
        for r in 0..CYCLE {
            let i = base + c * CYCLE + r;
            for j in 0..3 {
                tr[O0 + j][i] = ot[r][j];
                tr[N0 + j][i] = nt[r][j];
            }
            tr[SIB][i] = sib;
            tr[DIR][i] = F::from(dir);
            tr[IDX][i] = idx;
            tr[PW][i] = pw;
        }
        // carry the permutation outputs into the next cycle's inputs
        o_in = ot[CYCLE - 1];
        n_in = nt[CYCLE - 1];
    }
    for r in 0..UPDATE {
        let i = base + r;
        tr[BO][i] = fbo;
        tr[BN][i] = fbn;
        tr[AMT][i] = F::from(amt);
        tr[ACCT][i] = F::from(acct as u64);
        tr[SGN][i] = sgn;
        tr[ROOT][i] = root;
    }
    // range check: the first 64-row block of the update decomposes bn MSB-first
    let mut acc = 0u128;
    for j in 0..RANGE {
        let bit = (bn >> (RANGE - 1 - j)) & 1;
        acc = 2 * acc + bit as u128;
        tr[BIT][base + j] = F::from(bit);
        tr[ACC][base + j] = F::from(acc);
    }
    // other blocks stay zero (acc = bit = 0 satisfies J/K)
}

/// Periodic round-constant columns: value at row r (mod 128) is C[r] (0 at r=127).
pub fn periodic_table() -> [Vec<F>; 3] {
    let c = hash::constants();
    let col = |j: usize| (0..CYCLE).map(|r| if r < hash::ROUNDS { c[r][j] } else { F::zero() }).collect::<Vec<F>>();
    [col(0), col(1), col(2)]
}

/// Coefficients q_j with q_j(ω_128^r) = C[r][j]; the column is c_j(x) = q_j(x^(T/128)).
pub fn periodic_coeffs() -> [Vec<F>; 3] {
    let d = Radix2EvaluationDomain::<F>::new(CYCLE).unwrap();
    periodic_table().map(|v| d.ifft(&v))
}

pub fn horner(c: &[F], x: F) -> F {
    c.iter().rev().fold(F::zero(), |acc, k| acc * x + k)
}

/// The constant roots of unity the zerofiers use (independent of T).
pub struct Roots {
    pub w128_inv: F,
    pub w1024_inv: F,
    pub w64_inv: F,
    pub w1024_63: F,
}

impl Roots {
    pub fn get() -> Self {
        Roots {
            w128_inv: field::root(128).inverse().unwrap(),
            w1024_inv: field::root(1024).inverse().unwrap(),
            w64_inv: field::root(64).inverse().unwrap(),
            w1024_63: field::pow(field::root(1024), 63),
        }
    }
}

/// [x^T - 1, Z128, Z1024, Z64, Z63, x - 1, x - g^-1], the values to invert.
pub fn denominators(x: F, t: usize, g_inv: F, roots: &Roots) -> [F; 7] {
    let x1024 = field::pow(x, (t / 1024) as u64);
    let x128 = field::pow(x1024, 8);
    let x64 = x128.square();
    let xt = field::pow(x64, 64);
    [xt - F::one(), x128 - roots.w128_inv, x1024 - roots.w1024_inv, x64 - roots.w64_inv, x1024 - roots.w1024_63, x - F::one(), x - g_inv]
}

pub fn factors_from_inv(x: F, t: usize, g_inv: F, roots: &Roots, inv: &[F; 7]) -> [F; 11] {
    let x1024 = field::pow(x, (t / 1024) as u64);
    let x128 = field::pow(x1024, 8);
    let x64 = x128.square();
    let z128 = x128 - roots.w128_inv;
    let z1024 = x1024 - roots.w1024_inv;
    let z64 = x64 - roots.w64_inv;
    let [i_all, i_128, i_1024, i_64, i_63, i_first, i_last] = *inv;
    [
        z128 * i_all,             // A: all rows except 127 mod 128
        z1024 * i_all,            // C: all except 1023 mod 1024
        z1024 * i_128,            // D: 127 mod 128 except 1023 mod 1024
        (x - g_inv) * i_1024,     // E: 1023 mod 1024 except last
        i_1024,                   // F+H: 1023 mod 1024
        i_all,                    // I: all rows
        z64 * i_all,              // J: all except 63 mod 64
        i_64,                     // K: 63 mod 64
        i_63,                     // L: 63 mod 1024
        i_first,                  // M: row 0
        i_last,                   // N: last row
    ]
}

/// Constraint numerators at one point. `cur`/`nxt` are the trace at x and g·x,
/// `c` the periodic round constants at x, `v` = (V_acct(x), V_amt(x)).
pub fn numerators(cur: &[F], nxt: &[F], c: &[F; 3], v: (F, F), pi: (F, F)) -> [F; NC] {
    let one = F::one();
    let two = F::from(2u64);
    let mut out = [F::zero(); NC];
    let mut k = 0;
    let mut put = |x: F| {
        out[k] = x;
        k += 1;
    };
    // A: rounds
    for lane in [O0, N0] {
        let cube = |j: usize| {
            let y = cur[lane + j] + c[j];
            y * y.square()
        };
        let m = hash::mds([cube(0), cube(1), cube(2)]);
        for j in 0..3 {
            put(nxt[lane + j] - m[j]);
        }
    }
    // B: cycle-constant
    for col in [SIB, DIR, IDX, PW] {
        put(nxt[col] - cur[col]);
    }
    // C: update-constant
    for col in [BO, BN, AMT, ACCT, SGN, ROOT] {
        put(nxt[col] - cur[col]);
    }
    // D: node absorb
    let (s, d) = (nxt[SIB], nxt[DIR]);
    for lane in [O0, N0] {
        let out = cur[lane];
        put(nxt[lane] - (out + d * (s - out)));
        put(nxt[lane + 1] - (s + d * (out - s)));
        put(nxt[lane + 2] - two);
    }
    put(nxt[IDX] - (cur[IDX] + d * cur[PW]));
    put(nxt[PW] - two * cur[PW]);
    // E: next update starts
    put(nxt[O0] - nxt[BO]);
    put(nxt[O0 + 1]);
    put(nxt[O0 + 2] - one);
    put(nxt[N0] - nxt[BN]);
    put(nxt[N0 + 1]);
    put(nxt[N0 + 2] - one);
    put(nxt[IDX]);
    put(nxt[PW] - one);
    put(nxt[ROOT] - cur[N0]);
    // F: sign alternates
    put(nxt[SGN] + cur[SGN]);
    // H: update-end checks
    put(cur[O0] - cur[ROOT]);
    put(cur[BN] - cur[BO] - cur[SGN] * cur[AMT]);
    put(cur[ACCT] - cur[IDX]);
    put(cur[ACCT] - v.0);
    put(cur[AMT] - v.1);
    // I: binary
    put(cur[DIR] * (cur[DIR] - one));
    put(cur[BIT] * (cur[BIT] - one));
    // J, K: range accumulator
    put(nxt[ACC] - two * cur[ACC] - nxt[BIT]);
    put(nxt[ACC] - nxt[BIT]);
    // L: range link
    put(cur[ACC] - cur[BN]);
    // M: first row
    put(cur[O0] - cur[BO]);
    put(cur[O0 + 1]);
    put(cur[O0 + 2] - one);
    put(cur[N0] - cur[BN]);
    put(cur[N0 + 1]);
    put(cur[N0 + 2] - one);
    put(cur[IDX]);
    put(cur[PW] - one);
    put(cur[SGN] + one);
    put(cur[ROOT] - pi.0);
    // N: last row
    put(cur[N0] - pi.1);
    debug_assert_eq!(k, NC);
    out
}

/// H(x) = Σ_i α^i · num_i(x) · factor_{group(i)}(x).
pub fn combine(num: &[F; NC], factors: &[F; 11], alpha: F) -> F {
    let mut acc = F::zero();
    let mut ap = F::one();
    let mut i = 0;
    for (g, (_, n)) in GROUPS.iter().enumerate() {
        let mut s = F::zero();
        for _ in 0..*n {
            s += ap * num[i];
            ap *= alpha;
            i += 1;
        }
        acc += s * factors[g];
    }
    acc
}

/// Barycentric evaluation of the update-end interpolant at x
/// (points g^(1024u+1023), values `vals[u]`). Needs x off those points.
pub fn interp_update_ends(x: F, t: usize, g: F, vals: &[F]) -> F {
    let u = vals.len();
    assert_eq!(u * UPDATE, t);
    let h = field::pow(g, UPDATE as u64);
    let mut xu = field::pow(g, (UPDATE - 1) as u64);
    let mut den = Vec::with_capacity(u);
    let mut pts = Vec::with_capacity(u);
    for _ in 0..u {
        pts.push(xu);
        den.push(x - xu);
        xu *= h;
    }
    ark_ff::batch_inversion(&mut den);
    let roots = Roots::get();
    let z = field::pow(x, u as u64) - roots.w1024_inv;
    let s: F = vals.iter().zip(&pts).zip(&den).map(|((v, p), d)| *v * p * d).sum();
    // L_u(x) = Z(x) · x_u / (U · ω^-1 · (x - x_u))
    z * s * (F::from(u as u64) * roots.w1024_inv).inverse().unwrap()
}

/// Debug helper: checks every constraint on every row of a trace.
/// Returns (constraint index, row) of the first violation.
pub fn check_trace(tr: &[Vec<F>], pi: &Public) -> Result<(), (usize, usize)> {
    let t = tr[0].len();
    let (va, vm) = update_targets(&pi.txs);
    let per = periodic_table();
    for i in 0..t {
        let cur: Vec<F> = (0..W).map(|j| tr[j][i]).collect();
        let nxt: Vec<F> = (0..W).map(|j| tr[j][(i + 1) % t]).collect();
        let r = i % CYCLE;
        let c = [per[0][r], per[1][r], per[2][r]];
        let ue = i % UPDATE == UPDATE - 1;
        let v = if ue { (va[i / UPDATE], vm[i / UPDATE]) } else { (F::zero(), F::zero()) };
        let num = numerators(&cur, &nxt, &c, v, (pi.prev_root, pi.new_root));
        let on = |g: Group| -> bool {
            match g {
                Group::A => r != CYCLE - 1,
                Group::C => !ue,
                Group::D => r == CYCLE - 1 && !ue,
                Group::E => ue && i != t - 1,
                Group::F => ue,
                Group::I => true,
                Group::J => i % RANGE != RANGE - 1,
                Group::K => i % RANGE == RANGE - 1,
                Group::L => i % UPDATE == RANGE - 1,
                Group::M => i == 0,
                Group::N => i == t - 1,
            }
        };
        let mut k = 0;
        for (g, n) in GROUPS {
            for _ in 0..n {
                if on(g) && !num[k].is_zero() {
                    return Err((k, i));
                }
                k += 1;
            }
        }
    }
    Ok(())
}
