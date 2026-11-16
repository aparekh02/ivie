// Off-chain Groth16 toolkit shared by vector generation, e2e and the future
// prover integration.
//
//   encodeVk / encodeProof   snarkjs JSON -> exact on-chain byte layouts
//   referenceVerify          independent verifier (noble-curves pairing)
//   simulate                 trapdoor "simulator" that makes VALID proofs for
//                            any public inputs, used to fuzz the verifier
//                            without a circuit or prover
//   mutations                adversarial variants of a valid proof
//
// JSON uses the snarkjs shapes: G1 [x, y, z], G2 [[x0, x1], [y0, y1], [z0, z1]],
// decimal strings, Fp2 elements as c0 + c1*u.

import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

export const CURVES = {
  bn254: { id: 0, lib: bn254, fpBytes: 32, name: 'bn254', snarkjs: 'bn128' },
  bls12381: { id: 1, lib: bls12_381, fpBytes: 64, name: 'bls12381', snarkjs: 'bls12381' },
};
export function curveOf(name) {
  const n = String(name).toLowerCase().replace(/[-_]/g, '');
  if (n === 'bn128' || n === 'bn254' || n === 'altbn128') return CURVES.bn254;
  if (n === 'bls12381') return CURVES.bls12381;
  throw new Error(`unsupported curve ${name}`);
}
export const P = (c) => c.lib.fields.Fp.ORDER;
export const R = (c) => c.lib.fields.Fr.ORDER;

// ---------- byte helpers
const hexN = (v, bytes) => {
  const h = BigInt(v).toString(16);
  if (h.length > bytes * 2) throw new Error(`value exceeds ${bytes} bytes`);
  return h.padStart(bytes * 2, '0');
};
export const word = (v) => hexN(v, 32);
export const keccakHex = (hex) => '0x' + Buffer.from(keccak_256(Buffer.from(hex.replace(/^0x/, ''), 'hex'))).toString('hex');

// ---------- JSON <-> points
const big = (s) => BigInt(s);
export function g1FromJson(c, j) {
  if (big(j[2] ?? 1) === 0n) return c.lib.G1.Point.ZERO;
  const p = c.lib.G1.Point.fromAffine({ x: big(j[0]), y: big(j[1]) });
  return p;
}
export function g2FromJson(c, j) {
  const Fp2 = c.lib.fields.Fp2;
  const z = j[2] ? [big(j[2][0]), big(j[2][1])] : [1n, 0n];
  if (z[0] === 0n && z[1] === 0n) return c.lib.G2.Point.ZERO;
  return c.lib.G2.Point.fromAffine({
    x: Fp2.create({ c0: big(j[0][0]), c1: big(j[0][1]) }),
    y: Fp2.create({ c0: big(j[1][0]), c1: big(j[1][1]) }),
  });
}
export function g1ToJson(p) {
  if (p.is0()) return ['0', '1', '0'];
  const a = p.toAffine();
  return [a.x.toString(), a.y.toString(), '1'];
}
export function g2ToJson(p) {
  if (p.is0()) return [['0', '0'], ['1', '0'], ['0', '0']];
  const a = p.toAffine();
  return [[a.x.c0.toString(), a.x.c1.toString()], [a.y.c0.toString(), a.y.c1.toString()], ['1', '0']];
}

// ---------- on-chain encodings (coordinates taken from JSON as-is, so that
// deliberately non-canonical test inputs survive encoding)
function encG1(c, j) {
  if (big(j[2] ?? 1) === 0n) return hexN(0, 2 * c.fpBytes);
  return hexN(j[0], c.fpBytes) + hexN(j[1], c.fpBytes);
}
function encG2(c, j) {
  const zero = j[2] && big(j[2][0]) === 0n && big(j[2][1]) === 0n;
  if (zero) return hexN(0, 4 * c.fpBytes);
  const [x0, x1] = j[0];
  const [y0, y1] = j[1];
  const b = c.fpBytes;
  // EIP-197 (BN254): imaginary first. EIP-2537 (BLS12-381): real first.
  return c === CURVES.bn254
    ? hexN(x1, b) + hexN(x0, b) + hexN(y1, b) + hexN(y0, b)
    : hexN(x0, b) + hexN(x1, b) + hexN(y0, b) + hexN(y1, b);
}
export function encodeVk(vk) {
  const c = curveOf(vk.curve);
  const ic = vk.IC.map((p) => encG1(c, p)).join('');
  return '0x' + encG1(c, vk.vk_alpha_1) + encG2(c, vk.vk_beta_2) + encG2(c, vk.vk_gamma_2) + encG2(c, vk.vk_delta_2) + ic;
}
export function encodeProof(proof, curveName = proof.curve) {
  const c = curveOf(curveName);
  return '0x' + encG1(c, proof.pi_a) + encG2(c, proof.pi_b) + encG1(c, proof.pi_c);
}
/// The registry's content address: keccak256(abi.encode(uint8 curve, bytes rawVk)).
export function circuitId(vk) {
  const c = curveOf(vk.curve);
  const raw = encodeVk(vk).slice(2);
  const len = raw.length / 2;
  const padded = raw.padEnd(Math.ceil(len / 32) * 64, '0');
  return keccakHex(word(c.id) + word(64) + word(len) + padded);
}
/// snarkjs-compatible calldata for generated verifiers: (a, b, c, inputs)
export function snarkjsCalldata(proof) {
  return {
    a: [proof.pi_a[0], proof.pi_a[1]],
    b: [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
    c: [proof.pi_c[0], proof.pi_c[1]],
  };
}

// ---------- reference verifier (spec, independent of the Solidity code)
/// Returns { ok, why }. Mirrors the on-chain rules: canonical coordinates,
/// on-curve + subgroup for every point, inputs < r, then the pairing equation.
export function referenceVerify(vk, proof, publicSignals) {
  const c = curveOf(vk.curve);
  try {
    if (publicSignals.length !== vk.IC.length - 1) return { ok: false, why: 'input count' };
    const inputs = publicSignals.map(big);
    if (inputs.some((x) => x < 0n || x >= R(c))) return { ok: false, why: 'input >= r' };
    const canon = (vals) => vals.every((v) => big(v) < P(c));
    const flat = [proof.pi_a.slice(0, 2), proof.pi_b[0], proof.pi_b[1], proof.pi_c.slice(0, 2)].flat();
    if (!canon(flat)) return { ok: false, why: 'non-canonical coordinate' };
    const A = g1FromJson(c, proof.pi_a);
    const B = g2FromJson(c, proof.pi_b);
    const C = g1FromJson(c, proof.pi_c);
    for (const p of [A, B, C]) p.assertValidity(); // on curve + prime-order subgroup
    let vkx = g1FromJson(c, vk.IC[0]);
    inputs.forEach((x, i) => {
      if (x !== 0n) vkx = vkx.add(g1FromJson(c, vk.IC[i + 1]).multiply(x));
    });
    const alpha = g1FromJson(c, vk.vk_alpha_1);
    const beta = g2FromJson(c, vk.vk_beta_2);
    const gamma = g2FromJson(c, vk.vk_gamma_2);
    const delta = g2FromJson(c, vk.vk_delta_2);
    const F12 = c.lib.fields.Fp12;
    // e(O, Q) = e(P, O) = 1, as the precompiles define it (noble throws instead)
    const e = (g1, g2) => (g1.is0() || g2.is0() ? F12.ONE : c.lib.pairing(g1, g2));
    const lhs = e(A, B);
    const rhs = F12.mul(F12.mul(e(alpha, beta), e(vkx, gamma)), e(C, delta));
    return F12.eql(lhs, rhs) ? { ok: true } : { ok: false, why: 'pairing' };
  } catch (e) {
    return { ok: false, why: `invalid point: ${e.message.slice(0, 60)}` };
  }
}

// ---------- deterministic RNG (xorshift-based, seeded) for reproducible vectors
export function rng(seed) {
  let s = keccak_256(new TextEncoder().encode(String(seed)));
  return {
    scalar(mod) {
      s = keccak_256(s);
      const v = BigInt('0x' + Buffer.from(s).toString('hex') + Buffer.from(keccak_256(s)).toString('hex'));
      return (v % (mod - 1n)) + 1n; // [1, mod)
    },
  };
}

// ---------- simulator: knows the toxic waste, so it can prove anything
const modp = (a, m) => ((a % m) + m) % m;
function inv(a, m) {
  let [t, nt, r, nr] = [0n, 1n, m, modp(a, m)];
  while (nr !== 0n) {
    const q = r / nr;
    [t, nt] = [nt, t - q * nt];
    [r, nr] = [nr, r - q * nr];
  }
  return modp(t, m);
}

export function simulate(curveName, nPublic, seed = 'zknet') {
  const c = curveOf(curveName);
  const r = R(c);
  const g = rng(`${seed}/${c.name}/${nPublic}`);
  const G1 = c.lib.G1.Point.BASE;
  const G2 = c.lib.G2.Point.BASE;
  const t = { alpha: g.scalar(r), beta: g.scalar(r), gamma: g.scalar(r), delta: g.scalar(r) };
  const k = Array.from({ length: nPublic + 1 }, () => g.scalar(r));
  const vk = {
    protocol: 'groth16',
    curve: c.snarkjs,
    nPublic,
    vk_alpha_1: g1ToJson(G1.multiply(t.alpha)),
    vk_beta_2: g2ToJson(G2.multiply(t.beta)),
    vk_gamma_2: g2ToJson(G2.multiply(t.gamma)),
    vk_delta_2: g2ToJson(G2.multiply(t.delta)),
    IC: k.map((ki) => g1ToJson(G1.multiply(ki))),
  };
  function prove(publicSignals) {
    const xs = publicSignals.map(big);
    const s = modp(k[0] + xs.reduce((acc, x, i) => acc + x * k[i + 1], 0n), r);
    const a = g.scalar(r);
    const b = g.scalar(r);
    const cc = modp((a * b - t.alpha * t.beta - s * t.gamma) * inv(t.delta, r), r);
    return {
      protocol: 'groth16',
      curve: c.snarkjs,
      pi_a: g1ToJson(G1.multiply(a)),
      pi_b: g2ToJson(G2.multiply(b)),
      pi_c: cc === 0n ? ['0', '1', '0'] : g1ToJson(G1.multiply(cc)),
    };
  }
  const randomInputs = () => Array.from({ length: nPublic }, () => g.scalar(r).toString());
  return { vk, prove, randomInputs, curve: c };
}

// ---------- adversarial mutations of a valid (vk, proof, inputs)
/// Each entry: { name, proof, inputs, expect } where expect is the reference
/// verdict ('valid' cases are re-randomizations and must still verify).
export function mutations(vk, proof, inputs, otherValid) {
  const c = curveOf(vk.curve);
  const p = P(c);
  const r = R(c);
  const clone = (x) => JSON.parse(JSON.stringify(x));
  const out = [];
  const add = (name, pr, ins, expect = 'invalid') => out.push({ name, proof: pr, inputs: ins ?? inputs, expect });

  if (inputs.length) {
    add('input[0] + 1', proof, [(modp(big(inputs[0]) + 1n, r)).toString(), ...inputs.slice(1)]);
    add('input[0] + r (non-canonical scalar)', proof, [(big(inputs[0]) + r).toString(), ...inputs.slice(1)]);
    add('input[last] = 0', proof, [...inputs.slice(0, -1), '0']);
    if (inputs.length > 1) add('inputs swapped', proof, [inputs[1], inputs[0], ...inputs.slice(2)]);
  }
  let m = clone(proof); m.pi_a[1] = (big(m.pi_a[1]) + p).toString();
  add('A.y + p (non-canonical encoding)', m);
  if (c === CURVES.bn254) {
    // Survives snarkjs's mod(sub(q, y'), q) negation: sub wraps mod 2^256, so
    // y' = ((y + 2^256) mod q) + q yields exactly q - y.
    m = clone(proof); m.pi_a[1] = (modp(big(m.pi_a[1]) + (1n << 256n), p) + p).toString();
    add('A.y wrap-malleable (((y + 2^256) mod q) + q)', m);
  }
  m = clone(proof); m.pi_c[0] = (big(m.pi_c[0]) + p).toString();
  add('C.x + p (non-canonical encoding)', m);
  m = clone(proof); m.pi_b[0][0] = (big(m.pi_b[0][0]) + p).toString();
  add('B.x.c0 + p (non-canonical encoding)', m);
  m = clone(proof); m.pi_a[1] = modp(p - big(m.pi_a[1]), p).toString();
  add('A negated', m);
  m = clone(proof); [m.pi_a, m.pi_c] = [m.pi_c, m.pi_a];
  add('A <-> C swapped', m);
  m = clone(proof); m.pi_b = [[m.pi_b[0][1], m.pi_b[0][0]], [m.pi_b[1][1], m.pi_b[1][0]], m.pi_b[2]];
  add('B Fp2 limbs swapped (wrong G2 order)', m);
  m = clone(proof); m.pi_a[1] = modp(big(m.pi_a[1]) + 1n, p).toString();
  add('A off curve', m);
  m = clone(proof); m.pi_b[1][0] = modp(big(m.pi_b[1][0]) + 1n, p).toString();
  add('B off curve', m);
  const tw = twistNonSubgroupPoint(c);
  if (tw) { m = clone(proof); m.pi_b = tw; add('B on twist but outside r-subgroup', m); }
  const g1bad = g1NonSubgroupPoint(c);
  if (g1bad) { m = clone(proof); m.pi_a = g1bad; add('A on curve but outside r-subgroup', m); }
  m = clone(proof); m.pi_a = ['0', '1', '0']; m.pi_b = [['0', '0'], ['1', '0'], ['0', '0']]; m.pi_c = ['0', '1', '0'];
  add('all-identity proof', m);
  m = clone(proof); m.pi_c = ['0', '1', '0'];
  add('C = identity', m);
  if (otherValid && inputs.length) add('valid proof for a different statement', otherValid.proof, inputs);

  // re-randomization: (A/s, s*B, C) satisfies the same equation -> VALID.
  const s = rng(`rerand/${proof.pi_a[0]}`).scalar(r);
  const A = g1FromJson(c, proof.pi_a).multiply(inv(s, r));
  const B = g2FromJson(c, proof.pi_b).multiply(s);
  add('re-randomized (A/s, sB, C) - malleability', { ...clone(proof), pi_a: g1ToJson(A), pi_b: g2ToJson(B) }, inputs, 'valid');
  return out;
}

// A point on the G2 twist curve that is NOT in the prime-order subgroup.
function twistNonSubgroupPoint(c) {
  const Fp2 = c.lib.fields.Fp2;
  const b2 = c === CURVES.bn254
    ? Fp2.div(Fp2.create({ c0: 3n, c1: 0n }), Fp2.create({ c0: 9n, c1: 1n }))
    : Fp2.create({ c0: 4n, c1: 4n });
  for (let i = 1n; i < 200n; i++) {
    const x = Fp2.create({ c0: i, c1: 1n });
    const rhs = Fp2.add(Fp2.mul(Fp2.sqr(x), x), b2);
    let y;
    try { y = Fp2.sqrt(rhs); } catch { continue; }
    if (!y) continue;
    const pt = { x, y };
    try {
      c.lib.G2.Point.fromAffine(pt).assertValidity();
    } catch {
      return [[x.c0.toString(), x.c1.toString()], [y.c0.toString(), y.c1.toString()], ['1', '0']];
    }
  }
  return null;
}
// BLS12-381 G1 has cofactor > 1: find y^2 = x^3 + 4 points outside the subgroup.
function g1NonSubgroupPoint(c) {
  if (c !== CURVES.bls12381) return null; // BN254 G1 has cofactor 1
  const Fp = c.lib.fields.Fp;
  for (let x = 1n; x < 500n; x++) {
    const rhs = Fp.add(Fp.mul(Fp.sqr(x), x), 4n);
    let y;
    try { y = Fp.sqrt(rhs); } catch { continue; }
    if (y === undefined) continue;
    try { c.lib.G1.Point.fromAffine({ x, y }).assertValidity(); } catch { return [x.toString(), y.toString(), '1']; }
  }
  return null;
}

/// The PREPARED vk (beta, gamma, delta negated), byte-identical to what the
/// registry stores via prepare(). Used by generated standalone verifiers.
export function encodePreparedVk(vk) {
  const c = curveOf(vk.curve);
  const p = P(c);
  const neg = (g2) => [g2[0], [modp(p - big(g2[1][0]), p).toString(), modp(p - big(g2[1][1]), p).toString()], g2[2]];
  return encodeVk({ ...vk, vk_beta_2: neg(vk.vk_beta_2), vk_gamma_2: neg(vk.vk_gamma_2), vk_delta_2: neg(vk.vk_delta_2) });
}

/// Inverse of encodeProof: on-chain bytes -> snarkjs-shaped JSON.
export function decodeProof(hex, curveName) {
  const c = curveOf(curveName);
  const b = c.fpBytes * 2; // hex chars per Fp element
  const h = hex.replace(/^0x/, '');
  const f = (i) => BigInt('0x' + h.slice(i * b, (i + 1) * b)).toString();
  const g1 = (o) => (f(o) === '0' && f(o + 1) === '0' ? ['0', '1', '0'] : [f(o), f(o + 1), '1']);
  const isZero2 = [2, 3, 4, 5].every((i) => f(i) === '0');
  // EIP-197 order is (x_im, x_re, y_im, y_re); EIP-2537 is (x_re, x_im, y_re, y_im)
  const g2 = isZero2 ? [['0', '0'], ['1', '0'], ['0', '0']]
    : c === CURVES.bn254 ? [[f(3), f(2)], [f(5), f(4)], ['1', '0']] : [[f(2), f(3)], [f(4), f(5)], ['1', '0']];
  return { protocol: 'groth16', curve: c.snarkjs, pi_a: g1(0), pi_b: g2, pi_c: g1(6) };
}
