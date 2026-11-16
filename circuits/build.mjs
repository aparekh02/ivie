#!/usr/bin/env node
// Real Groth16 artifacts from the standard toolchain (circom 2.2 + snarkjs 0.7)
// for both curves. Used to cross-check the on-chain verifier against proofs
// it had no part in making.
//
//   node circuits/build.mjs            # build everything (cached ceremony)
//   node circuits/build.mjs --clean    # wipe build/ first
//
// Per curve: powers-of-tau (phase 1, 2^12, one contribution), then per
// circuit: groth16 setup + one phase-2 contribution, proofs, and fixtures in
// contracts/test/vectors/circom_<circuit>_<curve>.json.
//
// The zkey from BEFORE the phase-2 contribution is exported too
// (vk_no_phase2.json). There delta == gamma == G2 generator, which makes
// proofs forgeable, and the registry must refuse it.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as snarkjs from 'snarkjs';
import * as zk from '../tools/zk.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const BUILD = join(here, 'build');
const VECTORS = join(root, 'contracts', 'test', 'vectors');
const SNARKJS = join(root, 'node_modules', '.bin', 'snarkjs');
if (process.argv.includes('--clean')) rmSync(BUILD, { recursive: true, force: true });
mkdirSync(VECTORS, { recursive: true });

const sh = (bin, args) => execFileSync(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
const snark = (...a) => sh(SNARKJS, a);

// Deterministic "entropy" keeps builds reproducible. This is a TEST ceremony:
// anyone who reads this file knows the toxic waste.
const ENTROPY = 'zknet-test-ceremony-not-secure';

const CIRCUITS = [
  {
    name: 'multiplier',
    curves: ['bn128', 'bls12381'],
    inputs: [{ a: 3, b: 11 }, { a: 7919, b: 104729 }, { a: '123456789123456789', b: '987654321987654321' }],
  },
  {
    name: 'sum_of_squares',
    curves: ['bn128', 'bls12381'],
    inputs: [
      { x: [1, 2, 3, 4, 5, 6, 7, 8] },
      { x: [0, 0, 0, 0, 0, 0, 0, 0] },
      { x: ['1000000007', 3, '99999999999', 42, 0, 1, 2, '31337'] },
    ],
  },
  {
    name: 'nullifier',
    curves: ['bn128'],
    inputs: [
      { secret: '0x1234567890abcdef', salt: 1, externalTopic: 2026 },
      { secret: '0x1234567890abcdef', salt: 1, externalTopic: 2027 },
      { secret: '0xdeadbeefcafebabe', salt: 9, externalTopic: 2026 },
    ],
  },
];

function ceremony(curve) {
  const dir = join(BUILD, curve);
  mkdirSync(dir, { recursive: true });
  const fin = join(dir, 'pot12_final.ptau');
  if (existsSync(fin)) return fin;
  console.log(`[${curve}] phase 1: powers of tau 2^12`);
  snark('powersoftau', 'new', curve, '12', join(dir, 'pot12_0.ptau'));
  snark('powersoftau', 'contribute', join(dir, 'pot12_0.ptau'), join(dir, 'pot12_1.ptau'), '--name=zknet-1', `-e=${ENTROPY}-p1`);
  snark('powersoftau', 'prepare', 'phase2', join(dir, 'pot12_1.ptau'), fin);
  return fin;
}

const fixtures = [];
for (const c of CIRCUITS) {
  for (const curve of c.curves) {
    const ptau = ceremony(curve);
    const dir = join(BUILD, curve, c.name);
    mkdirSync(dir, { recursive: true });
    console.log(`[${curve}] ${c.name}: compile`);
    const out = sh('circom', [join(here, 'src', `${c.name}.circom`), '--r1cs', '--wasm', '-p', curve, '-o', dir]);
    const constraints = /non-linear constraints: (\d+)/.exec(out)?.[1];
    const r1cs = join(dir, `${c.name}.r1cs`);
    const wasm = join(dir, `${c.name}_js`, `${c.name}.wasm`);
    const z0 = join(dir, `${c.name}_0000.zkey`);
    const zf = join(dir, `${c.name}_final.zkey`);
    snark('groth16', 'setup', r1cs, ptau, z0);
    snark('zkey', 'contribute', z0, zf, '--name=zknet-phase2', `-e=${ENTROPY}-${c.name}`);
    snark('zkey', 'export', 'verificationkey', z0, join(dir, 'vk_no_phase2.json'));
    snark('zkey', 'export', 'verificationkey', zf, join(dir, 'vk.json'));
    if (curve === 'bn128') {
      // baseline for the differential test (snarkjs only emits BN254 Solidity)
      const sol = join(root, 'contracts', 'test', 'snarkjs', `${c.name}.sol`);
      snark('zkey', 'export', 'solidityverifier', zf, sol);
      const pascal = c.name.replace(/(^|_)(.)/g, (_, __, ch) => ch.toUpperCase());
      writeFileSync(sol, readFileSync(sol, 'utf8')
        .replace('contract Groth16Verifier', `contract Snarkjs${pascal}Verifier`)
        .replace('pragma solidity >=0.7.0 <0.9.0;', 'pragma solidity ^0.8.0;'));
    }
    const vk = JSON.parse(readFileSync(join(dir, 'vk.json'), 'utf8'));
    const vkUnsafe = JSON.parse(readFileSync(join(dir, 'vk_no_phase2.json'), 'utf8'));

    const valid = [];
    for (const [i, input] of c.inputs.entries()) {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zf);
      const snarkOk = await snarkjs.groth16.verify(vk, publicSignals, proof);
      const ref = zk.referenceVerify(vk, proof, publicSignals);
      if (!snarkOk || !ref.ok) throw new Error(`${c.name}/${curve} proof ${i}: snarkjs=${snarkOk} ref=${JSON.stringify(ref)}`);
      writeFileSync(join(dir, `proof_${i}.json`), JSON.stringify(proof, null, 1));
      writeFileSync(join(dir, `public_${i}.json`), JSON.stringify(publicSignals));
      valid.push({ proof, publicSignals });
    }

    // adversarial set from proof 0; "different statement" uses proof 1
    const muts = zk.mutations(vk, valid[0].proof, valid[0].publicSignals, { proof: valid[1].proof });
    for (const m of muts) {
      const ref = zk.referenceVerify(vk, m.proof, m.inputs);
      if ((ref.ok ? 'valid' : 'invalid') !== m.expect) throw new Error(`reference disagrees on "${m.name}"`);
    }
    const fx = fixture({
      name: `circom_${c.name}_${curve}`,
      source: 'circom+snarkjs',
      constraints: Number(constraints),
      vk,
      valid: [...valid.map((v) => ({ name: 'snarkjs proof', proof: v.proof, inputs: v.publicSignals })), ...muts.filter((m) => m.expect === 'valid')],
      invalid: muts.filter((m) => m.expect === 'invalid'),
      unsafeVk: vkUnsafe,
    });
    fixtures.push(fx.name);
    console.log(`[${curve}] ${c.name}: ${constraints} constraints, ${fx.nValid} valid / ${fx.nInvalid} invalid vectors`);
  }
}

export function fixture({ name, source, constraints, vk, valid, invalid, unsafeVk }) {
  const c = zk.curveOf(vk.curve);
  const hex = (v) => '0x' + BigInt(v).toString(16);
  const enc = (list) => list.map((m) => ({ name: m.name, proof: zk.encodeProof(m.proof, vk.curve), inputs: m.inputs.map(hex) }));
  const fx = {
    name,
    source,
    curve: c.id,
    nPublic: vk.IC.length - 1,
    constraints: constraints ?? null,
    rawVk: zk.encodeVk(vk),
    circuitId: zk.circuitId(vk),
    unsafeVk: unsafeVk ? zk.encodeVk(unsafeVk) : '0x',
    nValid: valid.length,
    nInvalid: invalid.length,
    valid: enc(valid),
    invalid: enc(invalid),
    snarkjs: { vk },
  };
  writeFileSync(join(VECTORS, `${name}.json`), JSON.stringify(fx, null, 1));
  return fx;
}

// standalone generated verifiers (kept in sync with the zkeys above)
const GEN = [
  ['bn128', 'multiplier', 'MultiplierVerifierBN254'],
  ['bn128', 'nullifier', 'NullifierVerifierBN254'],
  ['bls12381', 'sum_of_squares', 'SumOfSquaresVerifierBLS12381'],
];
mkdirSync(join(root, 'contracts', 'src', 'generated'), { recursive: true });
for (const [curve, circ, cname] of GEN) {
  sh('node', [join(root, 'tools', 'gen-verifier.mjs'), join(BUILD, curve, circ, 'vk.json'), cname, join(root, 'contracts', 'src', 'generated', `${cname}.sol`)]);
}

writeFileSync(join(VECTORS, 'circom_index.json'), JSON.stringify({ fixtures }, null, 1));
console.log(`wrote ${fixtures.length} fixtures to ${VECTORS}`);
process.exit(0); // snarkjs keeps worker threads alive
