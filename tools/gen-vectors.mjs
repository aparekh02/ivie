#!/usr/bin/env node
// Simulated Groth16 vectors (trapdoor-generated, no circuit needed) across
// both curves and a range of public-input counts, plus adversarial variants.
// Every vector's expected verdict is checked against the reference verifier
// before it is written.
//
//   node tools/gen-vectors.mjs
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as zk from './zk.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const OUT = join(here, '..', 'contracts', 'test', 'vectors');
mkdirSync(OUT, { recursive: true });

const SIZES = [0, 1, 2, 5, 16];
const VALID_PER_SET = 3;
const names = [];

for (const curve of ['bn254', 'bls12381']) {
  for (const n of SIZES) {
    const sim = zk.simulate(curve, n, 'zknet-vectors-v1');
    const valid = [];
    for (let i = 0; i < VALID_PER_SET; i++) {
      const inputs = sim.randomInputs();
      const proof = sim.prove(inputs);
      valid.push({ name: `simulated #${i}`, proof, inputs });
    }
    // edge inputs: all zero and all r-1
    const r = zk.R(sim.curve);
    for (const [label, v] of [['inputs = 0', 0n], ['inputs = r-1', r - 1n]]) {
      if (!n) continue;
      const inputs = Array(n).fill(v.toString());
      valid.push({ name: label, proof: sim.prove(inputs), inputs });
    }
    const muts = zk.mutations(sim.vk, valid[0].proof, valid[0].inputs, valid[1]);
    const all = [...valid.map((v) => ({ ...v, expect: 'valid' })), ...muts];
    for (const m of all) {
      const ref = zk.referenceVerify(sim.vk, m.proof, m.inputs);
      if ((ref.ok ? 'valid' : 'invalid') !== m.expect) throw new Error(`${curve}/${n} reference disagrees on "${m.name}": ${ref.why}`);
    }
    const name = `sim_${curve}_n${n}`;
    const hex = (v) => '0x' + BigInt(v).toString(16);
    const enc = (list) => list.map((m) => ({ name: m.name, proof: zk.encodeProof(m.proof, sim.vk.curve), inputs: m.inputs.map(hex) }));
    const good = all.filter((m) => m.expect === 'valid');
    const bad = all.filter((m) => m.expect === 'invalid');
    writeFileSync(join(OUT, `${name}.json`), JSON.stringify({
      name, source: 'simulated', curve: sim.curve.id, nPublic: n, constraints: null,
      rawVk: zk.encodeVk(sim.vk), circuitId: zk.circuitId(sim.vk), unsafeVk: '0x',
      nValid: good.length, nInvalid: bad.length, valid: enc(good), invalid: enc(bad), snarkjs: { vk: sim.vk },
    }, null, 1));
    names.push(name);
    console.log(`${name}: ${good.length} valid, ${bad.length} invalid`);
  }
}
writeFileSync(join(OUT, 'sim_index.json'), JSON.stringify({ fixtures: names }, null, 1));
