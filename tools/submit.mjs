#!/usr/bin/env node
// Plug-in point for a prover: take a snarkjs-format Groth16 proof and verify it
// on zknet, both off-chain (reference) and on-chain (eth_call + optional tx).
//
//   node tools/submit.mjs --vk vk.json --proof proof.json --public public.json \
//        [--rpc http://127.0.0.1:9545] [--registry 0x...] [--tx] [--register]
//
// Any prover that emits snarkjs JSON (snarkjs, rapidsnark, arkworks/gnark with
// a JSON exporter) works on BN254 ("bn128") or BLS12-381 ("bls12381").
//   --register  register the VK if the registry doesn't know it yet
//   --tx        also send submit() as a transaction (records the statement)
// The registry address defaults to the CREATE2 address e2e/run.mjs deploys.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { concat, decodeEventLog, encodeFunctionData, getContractAddress, pad, toHex } from 'viem';
import { clients } from '../chain/wallet.mjs';
import * as zk from './zk.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (n, d) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : d);
const flag = (n) => args.includes(n);
const need = (n) => opt(n) ?? (console.error(`missing ${n}\nusage: submit.mjs --vk vk.json --proof proof.json --public public.json [--tx] [--register]`), process.exit(2));

const vk = JSON.parse(readFileSync(need('--vk'), 'utf8'));
const proof = JSON.parse(readFileSync(need('--proof'), 'utf8'));
const publicSignals = JSON.parse(readFileSync(need('--public'), 'utf8')).map(String);
const URL = opt('--rpc', process.env.ZKNET_RPC || 'http://127.0.0.1:9545');

const artifact = JSON.parse(readFileSync(join(here, '../contracts/out/ZKVerifierRegistry.sol/ZKVerifierRegistry.json'), 'utf8'));
const abi = artifact.abi;
const registry = opt('--registry') ?? getContractAddress({
  from: '0x4e59b44847b379578588920cA78FbF26c0B4956C', opcode: 'CREATE2', bytecode: artifact.bytecode.object,
  salt: pad(toHex('zknet.registry.v1', { size: 32 }), { size: 32 }),
});
const { pub, wallet } = clients(URL, Number(opt('--key-index', 0)));
const c = zk.curveOf(vk.curve);
const id = zk.circuitId(vk);
const proofBytes = zk.encodeProof(proof, vk.curve);
const inputs = publicSignals.map(BigInt);

const out = { curve: c.name, circuitId: id, registry, nPublic: inputs.length };
out.reference = zk.referenceVerify(vk, proof, publicSignals);

const code = await pub.getCode({ address: registry });
if (!code || code === '0x') throw new Error(`no registry at ${registry} - run e2e/run.mjs once, or pass --registry`);
const known = await pub.readContract({ address: registry, abi, functionName: 'circuits', args: [id] });
if (known[2] === '0x0000000000000000000000000000000000000000') {
  if (!flag('--register')) throw new Error(`circuit ${id} not registered (pass --register)`);
  const hash = await wallet.sendTransaction({ to: registry, data: encodeFunctionData({ abi, functionName: 'register', args: [c.id, zk.encodeVk(vk), opt('--label', 'submit.mjs')] }) });
  const r = await pub.waitForTransactionReceipt({ hash });
  if (r.status !== 'success') throw new Error('register reverted (invalid VK? gamma == delta?)');
  out.registered = { tx: hash, block: Number(r.blockNumber), gasUsed: Number(r.gasUsed) };
}
out.onchainVerify = await pub.readContract({ address: registry, abi, functionName: 'verify', args: [id, proofBytes, inputs] });

if (flag('--tx')) {
  const data = encodeFunctionData({ abi, functionName: 'submit', args: [id, proofBytes, inputs] });
  try {
    const hash = await wallet.sendTransaction({ to: registry, data });
    const r = await pub.waitForTransactionReceipt({ hash });
    const ev = r.logs.map((l) => { try { return decodeEventLog({ abi, ...l }); } catch { return null; } }).find((e) => e?.eventName === 'ProofVerified');
    out.submit = { tx: hash, status: r.status, block: Number(r.blockNumber), gasUsed: Number(r.gasUsed), inputsHash: ev?.args.inputsHash };
  } catch (e) {
    out.submit = { error: e.shortMessage ?? e.message };
  }
}
console.log(JSON.stringify(out, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 1));
process.exit(out.onchainVerify && out.reference.ok ? 0 : 1);
