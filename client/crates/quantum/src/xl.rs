//! Multivariate algebraic attack via **XL / Macaulay linearization** — the
//! linear-algebra member of the Groebner-basis family, and the one that makes
//! the *solving degree* an explicit, measurable number.
//!
//! Where `groebner` eliminates the intermediate state variables into one
//! univariate polynomial, `xl` keeps them. The reduced-round leaf preimage
//! becomes an iterated system of **degree-3** equations:
//!
//! ```text
//!   s[0]      = [b, 0, TAG_LEAF]                 (b unknown)
//!   s[r+1]    = round_r(s[r])                    r = 0 .. R-2   (3 cubic eqs each)
//!   round_{R-1}(s[R-1])[0] = target                            (1 cubic eq)
//! ```
//!
//! with unknowns `b` and the interior states `s[1..R-1]` (so `n = 1 + 3(R-1)`
//! variables). XL builds the Macaulay matrix at successive degrees `D`: rows are
//! the products `m · g_i` of each generator `g_i` by every monomial `m` with
//! `deg(m) ≤ D - deg(g_i)`, columns are all monomials of degree `≤ D`. Row
//! reduction over `F_p` yields linear forms `x_i - c_i` once `D` reaches the
//! **solving degree** `D*`; the recovered `b` is checked against the real hash.
//!
//! `D*` is exactly the quantity a Poseidon round count is chosen to inflate: the
//! attack is polynomial in the Macaulay matrix size `~ C(n+D*, D*)`, so security
//! is the claim that `D*` (hence that binomial) is astronomically large at full
//! rounds. This module measures `D*` where it is small enough to run, which is
//! the evidence end of the margin curve.

use std::collections::BTreeMap;
use ark_ff::{Field, Zero};
use ark_poly::DenseUVPolynomial;
use ark_poly::univariate::DensePolynomial;
use zknet_core::stark::field::F;
use zknet_core::stark::hash::{self, TAG_LEAF};
use crate::poseidon;

/// Multivariate polynomial over `F_p`: monomial (exponent vector, length `n`) → coeff.
type Mono = Vec<u8>;
#[derive(Clone)]
struct MPoly {
    n: usize,
    terms: BTreeMap<Mono, F>,
}

impl MPoly {
    fn zero(n: usize) -> Self {
        MPoly { n, terms: BTreeMap::new() }
    }
    fn constant(n: usize, c: F) -> Self {
        let mut t = BTreeMap::new();
        if !c.is_zero() {
            t.insert(vec![0u8; n], c);
        }
        MPoly { n, terms: t }
    }
    fn var(n: usize, i: usize) -> Self {
        let mut e = vec![0u8; n];
        e[i] = 1;
        let mut t = BTreeMap::new();
        t.insert(e, F::from(1u64));
        MPoly { n, terms: t }
    }
    fn add_assign(&mut self, other: &MPoly) {
        for (m, &c) in &other.terms {
            let e = self.terms.entry(m.clone()).or_insert_with(F::zero);
            *e += c;
            if e.is_zero() {
                self.terms.remove(m);
            }
        }
    }
    fn add(&self, other: &MPoly) -> MPoly {
        let mut r = self.clone();
        r.add_assign(other);
        r
    }
    fn scale(&self, k: F) -> MPoly {
        let mut t = BTreeMap::new();
        if !k.is_zero() {
            for (m, &c) in &self.terms {
                t.insert(m.clone(), c * k);
            }
        }
        MPoly { n: self.n, terms: t }
    }
    fn add_const(&self, c: F) -> MPoly {
        self.add(&MPoly::constant(self.n, c))
    }
    fn mul(&self, other: &MPoly) -> MPoly {
        let mut t: BTreeMap<Mono, F> = BTreeMap::new();
        for (ma, &ca) in &self.terms {
            for (mb, &cb) in &other.terms {
                let m: Mono = ma.iter().zip(mb).map(|(x, y)| x + y).collect();
                let e = t.entry(m).or_insert_with(F::zero);
                *e += ca * cb;
            }
        }
        t.retain(|_, c| !c.is_zero());
        MPoly { n: self.n, terms: t }
    }
    fn cube(&self) -> MPoly {
        self.mul(self).mul(self)
    }
    fn degree(&self) -> usize {
        self.terms.keys().map(|m| m.iter().map(|&e| e as usize).sum::<usize>()).max().unwrap_or(0)
    }
}

/// Symbolic round on a triple of multivariate polynomials (mirrors `hash::round`).
fn round_mpoly(s: &[MPoly; 3], c: &[F; 3]) -> [MPoly; 3] {
    let cubes = [
        s[0].add_const(c[0]).cube(),
        s[1].add_const(c[1]).cube(),
        s[2].add_const(c[2]).cube(),
    ];
    let sum = cubes[0].add(&cubes[1]).add(&cubes[2]);
    let two = F::from(2u64);
    let three = F::from(3u64);
    [
        sum.add(&cubes[0].scale(two)),
        sum.add(&cubes[1].scale(-two)),
        sum.add(&cubes[2].scale(-three)),
    ]
}

/// Build the iterated generator system for the `R`-round leaf preimage.
/// Variable 0 is `b`; variables `1 + 3(r-1) + j` are `s[r][j]` for `r = 1..R-1`.
fn system(target: F, r: usize) -> (usize, Vec<MPoly>) {
    let n = 1 + 3 * r.saturating_sub(1);
    let c = hash::constants();
    let mut gens = Vec::new();

    let state_var = |r_idx: usize, j: usize| -> MPoly { MPoly::var(n, 1 + 3 * (r_idx - 1) + j) };

    // s[0] = [b, 0, TAG_LEAF]
    let mut cur = [
        MPoly::var(n, 0),
        MPoly::zero(n),
        MPoly::constant(n, F::from(TAG_LEAF)),
    ];

    for (round, cr) in c[..r].iter().enumerate() {
        let img = round_mpoly(&cur, cr);
        if round == r - 1 {
            // last round: pin output cell 0 to the target
            gens.push(img[0].add_const(-target));
        } else {
            // interior: introduce fresh state variables equal to this round's image
            let next = [state_var(round + 1, 0), state_var(round + 1, 1), state_var(round + 1, 2)];
            for j in 0..3 {
                // gen = s[round+1][j] - img[j]
                gens.push(next[j].add(&img[j].scale(-F::from(1u64))));
            }
            cur = next;
        }
    }
    (n, gens)
}

/// All exponent vectors over `n` vars with total degree `≤ d`, each mapped to a
/// column index. Returns (index map, ordered list).
fn monomials(n: usize, d: usize) -> (BTreeMap<Mono, usize>, Vec<Mono>) {
    let mut out: Vec<Mono> = Vec::new();
    let mut cur = vec![0u8; n];
    fn rec(pos: usize, left: usize, cur: &mut Vec<u8>, out: &mut Vec<Vec<u8>>) {
        if pos == cur.len() {
            out.push(cur.clone());
            return;
        }
        for e in 0..=left {
            cur[pos] = e as u8;
            rec(pos + 1, left - e, cur, out);
        }
        cur[pos] = 0;
    }
    rec(0, d, &mut cur, &mut out);
    let idx: BTreeMap<Mono, usize> = out.iter().cloned().enumerate().map(|(i, m)| (m, i)).collect();
    (idx, out)
}

/// Gaussian elimination to reduced row echelon form over `F_p`, in place,
/// choosing pivot columns in the given `order` (an elimination order: interior
/// monomials first, so the surviving rows are purely in `b`).
fn rref(rows: &mut [Vec<F>], order: &[usize]) {
    let mut pivot = 0;
    for &col in order {
        let Some(sel) = (pivot..rows.len()).find(|&r| !rows[r][col].is_zero()) else { continue };
        rows.swap(pivot, sel);
        let inv = rows[pivot][col].inverse().unwrap();
        for x in rows[pivot].iter_mut() {
            *x *= inv;
        }
        let pivot_row = rows[pivot].clone();
        for (r, row) in rows.iter_mut().enumerate() {
            if r != pivot && !row[col].is_zero() {
                let f = row[col];
                for (x, p) in row.iter_mut().zip(pivot_row.iter()) {
                    *x -= f * *p;
                }
            }
        }
        pivot += 1;
        if pivot == rows.len() {
            break;
        }
    }
}

/// Result of the XL attack at a given round count.
pub struct XlResult {
    pub rounds: usize,
    pub vars: usize,
    pub gens: usize,
    /// Smallest Macaulay degree at which every variable was pinned (`None` if
    /// not reached within the degree/size budget).
    pub solving_degree: Option<usize>,
    /// Macaulay matrix size (rows × cols) at the solving degree, if reached.
    pub matrix: Option<(usize, usize)>,
    /// Recovered input `b`, verified against the real reduced-round hash.
    pub recovered_b: Option<F>,
    pub verified: bool,
}

/// Run XL on the `r`-round leaf preimage of `target`, trying Macaulay degrees up
/// to `max_degree` while the column count stays under `col_budget`.
pub fn attack(target: F, r: usize, max_degree: usize, col_budget: usize) -> XlResult {
    let (n, gens) = system(target, r);
    let gen_degs: Vec<usize> = gens.iter().map(|g| g.degree()).collect();
    let start = *gen_degs.iter().max().unwrap_or(&1);

    for d in start..=max_degree {
        let (idx, list) = monomials(n, d);
        let cols = list.len();
        if cols > col_budget {
            break;
        }
        // build Macaulay rows: m * g_i for deg(m) <= d - deg(g_i)
        let mut rows: Vec<Vec<F>> = Vec::new();
        for (g, &dg) in gens.iter().zip(&gen_degs) {
            if dg > d {
                continue;
            }
            let (_, mults) = monomials(n, d - dg);
            for m in &mults {
                let mut row = vec![F::zero(); cols];
                for (gm, &gc) in &g.terms {
                    let prod: Mono = gm.iter().zip(m).map(|(x, y)| x + y).collect();
                    if let Some(&ci) = idx.get(&prod) {
                        row[ci] += gc;
                    }
                }
                if row.iter().any(|x| !x.is_zero()) {
                    rows.push(row);
                }
            }
        }
        // Classify columns: pure powers of b (var 0) vs interior monomials.
        let mut pow_of_b = vec![None; cols];
        for (m, &ci) in &idx {
            let total: usize = m.iter().map(|&e| e as usize).sum();
            if total == m[0] as usize {
                // all exponents outside var 0 are zero -> monomial is b^{m[0]}
                pow_of_b[ci] = Some(m[0] as usize);
            }
        }
        // Elimination order: interior columns first (so they are pivoted away),
        // leaving reduced rows that are univariate in b.
        let mut order: Vec<usize> = (0..cols).filter(|&c| pow_of_b[c].is_none()).collect();
        order.extend((0..cols).filter(|&c| pow_of_b[c].is_some()));

        let n_rows = rows.len();
        rref(&mut rows, &order);

        // A reduced row supported only on pure powers of b is a univariate
        // elimination relation u(b) = 0 in the ideal — exactly what elimination
        // produces. The lowest-degree such relation pins b to its roots.
        let mut best: Option<Vec<F>> = None;
        for row in &rows {
            if row.iter().enumerate().all(|(c, v)| v.is_zero() || pow_of_b[c].is_some()) {
                let mut coeffs = vec![F::zero(); d + 1];
                let mut nonzero = false;
                for (c, &v) in row.iter().enumerate() {
                    if !v.is_zero() {
                        coeffs[pow_of_b[c].unwrap()] = v;
                        nonzero = true;
                    }
                }
                while coeffs.len() > 1 && coeffs.last() == Some(&F::zero()) {
                    coeffs.pop();
                }
                if nonzero && coeffs.len() > 1 {
                    let deg = coeffs.len() - 1;
                    if best.as_ref().map(|b| b.len() - 1 > deg).unwrap_or(true) {
                        best = Some(coeffs);
                    }
                }
            }
        }
        if let Some(coeffs) = best {
            let u = DensePolynomial::from_coefficients_vec(coeffs);
            if let Some(b) = crate::groebner::one_fp_root(&u, 0xA11CE ^ (d as u64)) {
                let verified = poseidon::leaf_r(b, r) == target;
                if verified {
                    return XlResult {
                        rounds: r,
                        vars: n,
                        gens: gens.len(),
                        solving_degree: Some(d),
                        matrix: Some((n_rows, cols)),
                        recovered_b: Some(b),
                        verified,
                    };
                }
            }
        }
    }
    XlResult { rounds: r, vars: n, gens: gens.len(), solving_degree: None, matrix: None, recovered_b: None, verified: false }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xl_solves_small_rounds() {
        // R=1 and R=2: XL must reach a solving degree and recover a verified preimage.
        for r in 1..=2 {
            let secret = F::from(777u64 + r as u64);
            let target = poseidon::leaf_r(secret, r);
            let res = attack(target, r, 12, 5000);
            assert!(res.solving_degree.is_some(), "no solving degree at R={r}");
            assert!(res.verified, "XL preimage did not verify at R={r}");
        }
    }
}
