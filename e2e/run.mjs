#!/usr/bin/env node
// End-to-end on a live zknet: real signed transactions, real blocks, real
// receipts. Nothing here touches anvil cheat methods.
//
//   node e2e/run.mjs [--rpc http://127.0.0.1:9545] [--quick]
//
// 1. Deploys ZKVerifierRegistry via the canonical CREATE2 deployer, so its
//    address is identical on every chain (including mainnet).
// 2. Registers every fixture VK and checks the on-chain id against JS.
// 3. For EVERY vector, compares the eth_call verdict with the independent JS
//    reference verifier (differential on the live node).
// 4. submit() for valid proofs (tx), then attacks as txs: invalid proof,
//    re-randomized replay, the unsafe no-phase-2 VK. Each must revert, and
//    the invalid-proof burn must be bounded even with a 2^24 gas limit.
// Writes e2e/reports/<timestamp>.json.

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { concat, decodeErrorResult, decodeEventLog, encodeFunctionData, getContractAddress, keccak256, pad, toHex, formatEther, formatGwei } from 'viem';
import { clients } from '../chain/wallet.mjs';
import * as zk from '../tools/zk.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..');
const args = process.argv.slice(2);
const opt = (n, d) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : d);
const URL = opt('--rpc', process.env.ZKNET_RPC || 'http://127.0.0.1:9545');
const QUICK = args.includes('--quick');

const artifact = JSON.parse(readFileSync(join(root, 'contracts/out/ZKVerifierRegistry.sol/ZKVerifierRegistry.json'), 'utf8'));
const abi = artifact.abi;
const initcode = artifact.bytecode.object;
const CREATE2_DEPLOYER = '0x4e59b44847b379578588920cA78FbF26c0B4956C';
const SALT = pad(toHex('zknet.registry.v1', { size: 32 }), { size: 32 });

const { pub, wallet, account } = clients(URL, 0);
const t0 = Date.now();
const log = (...a) => console.log(`[${((Date.now() - t0) / 1000).toFixed(1).padStart(6)}s]`, ...a);
const report = { url: URL, startedAt: new Date().toISOString(), chain: {}, registry: null, circuits: [], attacks: [], differential: { agree: 0, disagree: [] } };

// ------------------------------------------------------------------ chain
const chainId = await pub.getChainId();
const nodeInfo = await pub.request({ method: 'anvil_nodeInfo' }).catch(() => ({}));
const head = await pub.getBlock();
report.chain = { chainId, hardFork: nodeInfo.hardFork, block: Number(head.number), baseFeeGwei: formatGwei(head.baseFeePerGas) };
log(`chain ${chainId} ${nodeInfo.hardFork ?? ''} block #${head.number} base fee ${formatGwei(head.baseFeePerGas)} gwei`);
if (chainId !== 1) throw new Error('expected zknet (chain id 1)');

async function sendTx(req) {
  const hash = await wallet.sendTransaction(req);
  const r = await pub.waitForTransactionReceipt({ hash });
  return { hash, receipt: r, gasUsed: Number(r.gasUsed), costEth: formatEther(r.gasUsed * r.effectiveGasPrice), block: Number(r.blockNumber) };
}
const call = (functionName, args) => pub.readContract({ address: report.registry, abi, functionName, args });

// ------------------------------------------------------------------ deploy (CREATE2)
const registry = getContractAddress({ from: CREATE2_DEPLOYER, salt: SALT, bytecode: initcode, opcode: 'CREATE2' });
report.registry = registry;
if ((await pub.getCode({ address: registry }))?.length > 2) {
  log(`registry already deployed at ${registry}`);
} else {
  const tx = await sendTx({ to: CREATE2_DEPLOYER, data: concat([SALT, initcode]) });
  log(`deployed registry ${registry} in block ${tx.block}: ${tx.gasUsed} gas`);
  report.deploy = tx;
}

// ------------------------------------------------------------------ fixtures
const vecDir = join(root, 'contracts/test/vectors');
const idx = (f) => JSON.parse(readFileSync(join(vecDir, f), 'utf8')).fixtures;
let names = [...idx('circom_index.json'), ...idx('sim_index.json')];
// the attack section targets circom_nullifier_bn128, so quick mode keeps it
if (QUICK) names = names.filter((n) => n.startsWith('circom_multiplier') || n.endsWith('_n16') || n === 'circom_nullifier_bn128');

for (const name of names) {
  const fx = JSON.parse(readFileSync(join(vecDir, `${name}.json`), 'utf8'));
  const vk = fx.snarkjs.vk;
  const entry = { name, curve: vk.curve, nPublic: fx.nPublic, source: fx.source };

  // register (or detect existing)
  const known = await call('circuits', [fx.circuitId]);
  if (known[2] === '0x0000000000000000000000000000000000000000') {
    const tx = await sendTx({ to: registry, data: encodeFunctionData({ abi, functionName: 'register', args: [fx.curve, fx.rawVk, name] }) });
    const ev = tx.receipt.logs.map((l) => { try { return decodeEventLog({ abi, ...l }); } catch { return null; } }).find((e) => e?.eventName === 'CircuitRegistered');
    if (ev.args.id !== fx.circuitId) throw new Error(`${name}: on-chain id ${ev.args.id} != JS ${fx.circuitId}`);
    entry.registerGas = tx.gasUsed;
  }
  const id = fx.circuitId;

  // differential: every vector, eth_call vs reference verifier
  for (const c of [...fx.valid, ...fx.invalid]) {
    const inputs = c.inputs.map(BigInt);
    const onchain = await call('verify', [id, c.proof, inputs]);
    const ref = zk.referenceVerify(vk, zk.decodeProof(c.proof, vk.curve), inputs.map(String)).ok;
    if (onchain === ref) report.differential.agree++;
    else report.differential.disagree.push({ name, case: c.name, onchain, ref });
  }

  // a real submit() of the first valid proof (skip if a previous run consumed it)
  const v = fx.valid[0];
  const inputsHash = keccak256(concat(v.inputs.map((x) => pad(toHex(BigInt(x)), { size: 32 }))));
  if (!(await call('consumed', [id, inputsHash]))) {
    const tx = await sendTx({ to: registry, data: encodeFunctionData({ abi, functionName: 'submit', args: [id, v.proof, v.inputs.map(BigInt)] }) });
    const ev = tx.receipt.logs.map((l) => { try { return decodeEventLog({ abi, ...l }); } catch { return null; } }).find((e) => e?.eventName === 'ProofVerified');
    if (!ev || ev.args.inputsHash !== inputsHash) throw new Error(`${name}: ProofVerified event missing/wrong`);
    Object.assign(entry, { submitGas: tx.gasUsed, submitCostEth: tx.costEth, submitBlock: tx.block, submitTx: tx.hash });
  }
  entry.verifyGas = Number(await pub.estimateGas({ to: registry, data: encodeFunctionData({ abi, functionName: 'verify', args: [id, v.proof, v.inputs.map(BigInt)] }) }));
  report.circuits.push(entry);
  log(`${name.padEnd(34)} n=${String(fx.nPublic).padEnd(2)} verify ${entry.verifyGas} gas${entry.submitGas ? `, submit tx ${entry.submitGas} gas (${entry.submitCostEth} ETH) block ${entry.submitBlock}` : ''}`);
}

// ------------------------------------------------------------------ attacks as transactions
// Each attack must revert for the RIGHT reason: the error is decoded from an
// eth_call replay of the same tx and compared with `expect.error`.
async function revertReason(data, gas) {
  try { await pub.call({ account, to: registry, data, gas: BigInt(gas) }); return null; }
  catch (e) {
    const raw = e.cause?.data ?? e.data ?? e.cause?.cause?.data;
    const hex = typeof raw === 'string' ? raw : raw?.data;
    if (!hex) return 'unknown';
    try { return decodeErrorResult({ abi, data: hex }).errorName; } catch { return hex.slice(0, 10); }
  }
}
async function attack(label, data, gas, expect) {
  const reason = await revertReason(data, gas);
  const tx = await sendTx({ to: registry, data, gas: BigInt(gas) });
  const reverted = tx.receipt.status === 'reverted';
  const pass = reverted && reason === expect.error && (!expect.maxGas || tx.gasUsed < expect.maxGas);
  report.attacks.push({ label, reverted, reason, gasUsed: tx.gasUsed, gasLimit: gas, block: tx.block, pass });
  log(`attack: ${label.padEnd(52)} ${reverted ? 'REVERTED' : 'ACCEPTED!'} ${String(reason).padEnd(16)} gasUsed ${tx.gasUsed} / limit ${gas} ${pass ? 'ok' : 'FAIL'}`);
}
{
  const fx = JSON.parse(readFileSync(join(vecDir, 'circom_nullifier_bn128.json'), 'utf8'));
  const bad = fx.invalid.find((c) => c.name === 'A off curve');
  const enc = (fn, a) => encodeFunctionData({ abi, functionName: fn, args: a });
  await attack('submit(off-curve proof) with 2^24 gas limit', enc('submit', [fx.circuitId, bad.proof, bad.inputs.map(BigInt)]), 2 ** 24, { error: 'InvalidProof', maxGas: 1_000_000 });
  const rr = fx.valid.find((c) => c.name.startsWith('re-randomized'));
  await attack('submit(re-randomized proof of consumed statement)', enc('submit', [fx.circuitId, rr.proof, rr.inputs.map(BigInt)]), 1_000_000, { error: 'AlreadyConsumed' });
  const wrap = fx.invalid.find((c) => c.name.startsWith('A.y wrap'));
  await attack('submit(snarkjs wrap-malleable A.y encoding)', enc('submit', [fx.circuitId, wrap.proof, wrap.inputs.map(BigInt)]), 2_000_000, { error: 'InvalidProof' });
  await attack('register(no-phase-2 VK, gamma == delta)', enc('register', [0, fx.unsafeVk, 'unsafe']), 3_000_000, { error: 'InvalidVK' });
}

// ------------------------------------------------------------------ summary
const d = report.differential;
const attacksOk = report.attacks.every((a) => a.pass);
report.finishedAt = new Date().toISOString();
report.ok = d.disagree.length === 0 && attacksOk;
mkdirSync(join(here, 'reports'), { recursive: true });
const out = join(here, 'reports', `${report.startedAt.replace(/[:.]/g, '-')}.json`);
writeFileSync(out, JSON.stringify(report, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 1));
writeFileSync(join(here, 'reports', 'latest.json'), readFileSync(out));
log(`differential: ${d.agree} agree, ${d.disagree.length} disagree; attacks ${report.attacks.filter((a) => a.pass).length}/${report.attacks.length} blocked`);
if (d.disagree.length) console.log(d.disagree);
log(`${report.ok ? 'E2E OK' : 'E2E FAILED'}  report: ${out}`);
process.exit(report.ok ? 0 : 1);
