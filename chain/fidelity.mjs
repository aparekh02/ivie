#!/usr/bin/env node
// Probes a running zknet against Ethereum mainnet facts (from the snapshot
// and from the specs). Every check is PASS / FAIL / GAP, where GAP is a known
// anvil limitation, listed so nobody mistakes it for mainnet behavior.
//
//   node chain/fidelity.mjs [--rpc http://127.0.0.1:9545] [--json out.json]

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { rpc, keccakHex, word, toHex } from './rpc.mjs';
import { clients } from './wallet.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SNAP = JSON.parse(readFileSync(join(here, 'mainnet-snapshot.json'), 'utf8'));
const args = process.argv.slice(2);
const opt = (n, d) => (args.indexOf(n) >= 0 ? args[args.indexOf(n) + 1] : d);
const URL = opt('--rpc', process.env.ZKNET_RPC || 'http://127.0.0.1:9545');
const KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'; // anvil #0
const FROM = '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266';
const call = (m, p = []) => rpc(URL, m, p);
const ethCall = (to, data, extra = {}) => call('eth_call', [{ to, data, ...extra }, 'latest']);
const cast = (...a) => execFileSync('cast', [...a, '--rpc-url', URL], { stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim();

const results = [];
async function check(group, name, fn) {
  try {
    const r = await fn();
    const status = r === true ? 'PASS' : r?.gap ? 'GAP' : r === false ? 'FAIL' : r?.ok ? 'PASS' : 'FAIL';
    results.push({ group, name, status, detail: typeof r === 'object' ? r.detail : undefined });
  } catch (e) {
    results.push({ group, name, status: 'FAIL', detail: e.message.slice(0, 160) });
  }
}
const eq = (a, b, detail) => ({ ok: String(a).toLowerCase() === String(b).toLowerCase(), detail: detail ?? `got ${a}, want ${b}` });
const gap = (detail) => ({ gap: true, detail });
const pc = (n) => '0x' + n.toString(16).padStart(40, '0');
// eth_call with no `to` runs `data` as initcode; RETURN data is the result.
// gasPrice is set so BASEFEE is the real block base fee (geth and anvil both
// zero it for eth_call without a gas price - the NoBaseFee rule).
const run = (code) => call('eth_call', [{ from: FROM, data: '0x' + code, gasPrice: head.baseFeePerGas }, 'latest']);
// initcode: <push expr> PUSH0 MSTORE PUSH1 32 PUSH0 RETURN
const ret1 = (expr) => expr + '5f52' + '60205ff3';

const info = await call('anvil_nodeInfo');
const head = await call('eth_getBlockByNumber', ['latest', false]);
const cfg = await call('eth_config');
const meta = (() => { try { return JSON.parse(readFileSync(join(here, '.run', `anvil-${new globalThis.URL(URL).port}.json`), 'utf8')); } catch { return {}; } })();

// ------------------------------------------------------------ identity
await check('identity', 'chainId = 1', async () => eq(Number(await call('eth_chainId')), 1));
await check('identity', 'net_version = 1', async () => eq(await call('net_version'), '1'));
await check('identity', 'hardfork = Osaka', async () => eq(info.hardFork, 'Osaka'));
await check('identity', 'eth_config precompile set == mainnet', async () =>
  eq(JSON.stringify(cfg.current.precompiles), JSON.stringify(SNAP.config.precompiles), `${Object.keys(cfg.current.precompiles).length} precompiles`));
await check('identity', 'eth_config system contracts == mainnet', async () =>
  eq(JSON.stringify(cfg.current.systemContracts), JSON.stringify(SNAP.config.systemContracts), 'EIP-4788/2935/7002/7251 + deposit'));
await check('identity', 'blob schedule == mainnet (BPO2 14/21)', async () => {
  const a = cfg.current.blobSchedule, m = SNAP.config.blobSchedule;
  return a.target === m.target && a.max === m.max ? true : gap(`anvil hard-codes ${a.target}/${a.max}; mainnet ${m.target}/${m.max} (blob fee curve differs)`);
});

// ------------------------------------------------------------ header
await check('header', 'post-Prague header fields present', async () => {
  const need = ['baseFeePerGas', 'withdrawalsRoot', 'blobGasUsed', 'excessBlobGas', 'parentBeaconBlockRoot', 'requestsHash'];
  const missing = need.filter((k) => head[k] === undefined);
  return { ok: missing.length === 0, detail: missing.length ? `missing ${missing}` : need.join(', ') };
});
await check('header', 'PoS constants (difficulty 0, nonce 0, no uncles)', async () =>
  ({ ok: BigInt(head.difficulty) === 0n && BigInt(head.nonce) === 0n && head.sha3Uncles === '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347' }));
await check('header', 'gas limit == mainnet', async () => eq(Number(head.gasLimit), SNAP.head.gasLimit));
await check('header', 'block height ~ mainnet', async () => ({ ok: Number(head.number) >= SNAP.head.number, detail: `#${Number(head.number)} (mainnet snapshot #${SNAP.head.number})` }));
await check('header', 'coinbase = block builder', async () => eq(head.miner, SNAP.head.miner));
await check('header', 'timestamps on the beacon 12 s slot grid', async () => {
  const off = (Number(head.timestamp) - SNAP.beacon.genesisTime) % SNAP.beacon.secondsPerSlot;
  if (off === 0) return { ok: true, detail: `slot ${(Number(head.timestamp) - SNAP.beacon.genesisTime) / 12}` };
  return meta.fast ? gap(`--fast mines on tx arrival, block is ${off}s off-slot`) : { ok: false, detail: `off by ${off}s` };
});
await check('header', 'prevrandao (mixHash) is random', async () => ({ ok: BigInt(head.mixHash) !== 0n }));
await check('header', 'parentBeaconBlockRoot from a consensus layer', async () =>
  BigInt(head.parentBeaconBlockRoot) === 0n ? gap('no CL: root is 0x00..; EIP-4788 contract stores zeros') : true);

// ------------------------------------------------------------ system contracts / predeploys
for (const [k, s] of Object.entries(SNAP.systemContracts)) {
  await check('state', `${k} code == mainnet`, async () => eq(keccakHex(await call('eth_getCode', [s.address, 'latest'])), s.codeHash, s.address));
}
for (const p of SNAP.predeploys) {
  await check('state', `${p.name} code == mainnet`, async () => eq(keccakHex(await call('eth_getCode', [p.address, 'latest'])), p.codeHash, p.address));
}
await check('state', 'deposit contract empty root (constructor storage)', async () =>
  eq(await ethCall('0x00000000219ab540356cBB839Cbe05303d7705Fa', '0xc5f2892f'), '0xd70a234731285c6804c2a4f56711ddb8c82c99740f207854891028af34e27e5e'));
await check('state', 'EIP-2935 serves parent block hash', async () => {
  const n = Number(head.number);
  const parent = await call('eth_getBlockByNumber', [toHex(n - 1), false]);
  if (!parent) return gap('genesis has no parent');
  return eq(await ethCall('0x0000F90827F1C53a10cb7A02335B175320002935', word(n - 1)), parent.hash);
});

// ------------------------------------------------------------ precompiles
await check('precompile', '0x01 ecrecover', async () => eq(await ethCall(pc(1),
  '0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3' + word(28).slice(2) +
  '9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608' + '4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada'),
  word('0x7156526fbd7a3c72969b54f64e42c10fbb768c8a')));
await check('precompile', '0x02 sha256("")', async () => eq(await ethCall(pc(2), '0x'), '0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'));
await check('precompile', '0x03 ripemd160("")', async () => eq(await ethCall(pc(3), '0x'), word('0x9c1185a5c5e9fc54612808977ee8f548b2258d31')));
await check('precompile', '0x04 identity', async () => eq(await ethCall(pc(4), '0xdeadbeef'), '0xdeadbeef'));
await check('precompile', '0x05 modexp 3^5 mod 7 = 5', async () => eq(await ethCall(pc(5), word(1) + word(1).slice(2) + word(1).slice(2) + '030507'), '0x05'));
await check('precompile', '0x05 modexp EIP-7823 bound (1025-byte base rejected)', async () => {
  try { await ethCall(pc(5), word(1025) + word(1).slice(2) + word(1).slice(2) + '00'.repeat(1027)); return { ok: false, detail: 'accepted' }; }
  catch { return true; }
});
await check('precompile', '0x06 ecAdd G+G = 2G', async () => eq(await ethCall(pc(6), word(1) + word(2).slice(2) + word(1).slice(2) + word(2).slice(2)),
  '0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4'));
await check('precompile', '0x07 ecMul 2*G = 2G', async () => eq(await ethCall(pc(7), word(1) + word(2).slice(2) + word(2).slice(2)),
  '0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4'));
await check('precompile', '0x08 ecPairing(empty) = 1', async () => eq(await ethCall(pc(8), '0x'), word(1)));
await check('precompile', '0x09 blake2f (EIP-152 length rule)', async () => {
  const good = await ethCall(pc(9), '0x' + word(12).slice(-8) + '00'.repeat(208) + '01');
  let bad = false;
  try { await ethCall(pc(9), '0x' + '00'.repeat(212)); } catch { bad = true; }
  return { ok: good.length === 2 + 128 && bad, detail: '213-byte input -> 64 bytes; 212 -> error' };
});
await check('precompile', '0x0a KZG point evaluation (zero blob)', async () => {
  const commitment = Buffer.concat([Buffer.from([0xc0]), Buffer.alloc(47)]); // G1 infinity = commitment to 0
  const vh = Buffer.from(sha256(commitment)); vh[0] = 0x01;
  const input = '0x' + vh.toString('hex') + word(7).slice(2) + word(0).slice(2) + commitment.toString('hex') + commitment.toString('hex');
  return eq(await ethCall(pc(0x0a), input),
    word(4096) + '73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001', 'FIELD_ELEMENTS_PER_BLOB || BLS_MODULUS');
});
const BLS_G1 = '0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb' +
  '0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1';
await check('precompile', '0x0b BLS12 G1ADD(G, O) = G', async () => eq(await ethCall(pc(0x0b), '0x' + BLS_G1 + '00'.repeat(128)), '0x' + BLS_G1));
await check('precompile', '0x0c BLS12 G1MSM(G, 1) = G', async () => eq(await ethCall(pc(0x0c), '0x' + BLS_G1 + word(1).slice(2)), '0x' + BLS_G1));
await check('precompile', '0x0d-0x11 BLS12 G2ADD/G2MSM/PAIRING/MAP respond', async () => {
  const z = (n) => '0x' + '00'.repeat(n);
  const outs = await Promise.all([ethCall(pc(0x0d), z(512)), ethCall(pc(0x0e), z(288)), ethCall(pc(0x0f), z(384)), ethCall(pc(0x10), z(64)), ethCall(pc(0x11), z(128))]);
  const lens = outs.map((o) => (o.length - 2) / 2);
  return { ok: JSON.stringify(lens) === '[256,256,32,128,256]' && BigInt(outs[2]) === 1n, detail: `output sizes ${lens}` };
});
await check('precompile', '0x100 P256VERIFY (EIP-7951)', async () => {
  const sk = p256.utils.randomSecretKey();
  const pub = p256.getPublicKey(sk, false);
  const h = sha256(new TextEncoder().encode('zknet'));
  const sig = p256.sign(h, sk, { prehash: false, format: 'compact' });
  const hex = (b) => Buffer.from(b).toString('hex');
  const out = await ethCall(pc(0x100), '0x' + hex(h) + hex(sig) + hex(pub.slice(1)));
  const bad = await ethCall(pc(0x100), '0x' + hex(h) + hex(sig.map((x, i) => (i === 5 ? x ^ 1 : x))) + hex(pub.slice(1)));
  return { ok: BigInt(out) === 1n && bad === '0x', detail: 'valid -> 1, tampered -> empty' };
});

// ------------------------------------------------------------ opcodes
await check('opcode', 'CLZ (EIP-7939, Osaka): clz(1) = 255', async () => eq(BigInt(await run(ret1('60011e'))), 255n));
await check('opcode', 'PUSH0 / MCOPY / TSTORE+TLOAD', async () => {
  // TSTORE(0, 42); TLOAD(0) -> mem[0x20]; MCOPY 32 bytes 0x20 -> 0x00; RETURN mem[0..32]
  const code = '602a5f5d' + '5f5c' + '602052' + '60206020' + '5f5e' + '60205ff3';
  return eq(BigInt(await run(code)), 42n);
});
await check('opcode', 'CHAINID = 1', async () => eq(BigInt(await run(ret1('46'))), 1n));
await check('opcode', 'BASEFEE > 0, BLOBBASEFEE >= 1', async () => {
  const bf = BigInt(await run(ret1('48'))), bbf = BigInt(await run(ret1('4a')));
  return { ok: bf > 0n && bbf >= 1n, detail: `basefee ${bf}, blobbasefee ${bbf}` };
});

// ------------------------------------------------------------ transactions
await check('tx', 'EIP-7825: gas limit 2^24 + 1 rejected', async () => {
  try { await call('eth_sendTransaction', [{ from: FROM, to: FROM, gas: toHex(2 ** 24 + 1) }]); return { ok: false, detail: 'accepted' }; }
  catch (e) { return { ok: /gas/i.test(e.message), detail: e.message.slice(0, 80) }; }
});
await check('tx', 'EIP-3860: initcode > 49152 bytes rejected', async () => {
  try { await call('eth_estimateGas', [{ from: FROM, data: '0x' + '00'.repeat(49153) }]); return { ok: false, detail: 'accepted' }; }
  catch (e) { return { ok: true, detail: e.message.slice(0, 80) }; }
});
await check('tx', 'EIP-170: 24577-byte runtime code rejected', async () => {
  // initcode: return 24577 zero bytes
  const code = '616001' + '5f' + 'f3';
  try { await call('eth_estimateGas', [{ from: FROM, data: '0x' + code }]); return { ok: false, detail: 'accepted' }; }
  catch (e) { return { ok: true, detail: e.message.slice(0, 80) }; }
});
const types = {};
const { pub, wallet, account } = clients(URL, 0);
const eoa = clients(URL, 1).account;
await check('tx', 'type 0 (legacy, EIP-155) / 1 / 2 / 3 (blob) / 4 (7702) all mine', async () => {
  const to = '0x000000000000000000000000000000000000dEaD';
  const gasPrice = 2n * BigInt((await call('eth_getBlockByNumber', ['latest', false])).baseFeePerGas);
  const wait = async (hash) => pub.waitForTransactionReceipt({ hash });
  const r0 = await wait(await wallet.sendTransaction({ type: 'legacy', to, value: 1n, gasPrice }));
  const r1 = await wait(await wallet.sendTransaction({ type: 'eip2930', to, value: 1n, gasPrice, accessList: [{ address: to, storageKeys: [word(0)] }] }));
  const r2 = await wait(await wallet.sendTransaction({ to, value: 1n }));
  // blob: cast builds the EIP-7594 (PeerDAS cell-proof) wrapper Osaka mainnet requires
  const blobFile = join(here, '.run', 'blob.bin');
  writeFileSync(blobFile, 'zknet blob payload');
  const h3 = JSON.parse(cast('send', '--private-key', KEY, '--json', '--blob', '--path', blobFile, to)).transactionHash;
  const r3 = await wait(h3);
  // 7702: account #1 signs the authorization, account #0 relays it
  const authorization = await wallet.signAuthorization({ account: eoa, contractAddress: '0xcA11bde05977b3631167028862bE2a173976CA11' });
  // call getBlockNumber() on the EOA: only works if the delegated code runs
  const r4 = await wait(await wallet.sendTransaction({ authorizationList: [authorization], to: eoa.address, data: '0x42cbb15c' }));
  const typeNum = { legacy: 0, eip2930: 1, eip1559: 2, eip4844: 3, eip7702: 4 };
  for (const [t, r] of Object.entries({ 0: r0, 1: r1, 2: r2, 3: r3, 4: r4 })) {
    types[t] = { type: typeNum[r.type] ?? r.type, ok: r.status === 'success', block: Number(r.blockNumber) };
  }
  const ok = Object.entries(types).every(([t, v]) => v.type === Number(t) && v.ok);
  return { ok, detail: Object.entries(types).map(([t, v]) => `${t}:${v.ok ? 'ok' : 'FAILED'}@${v.block}`).join(' ') };
});
await check('tx', 'EIP-7702 delegation designator installed (0xef0100 || addr)', async () =>
  eq(await call('eth_getCode', ['0x70997970C51812dc3A010C7d01b50e0d17dc79C8', 'latest']), '0xef0100ca11bde05977b3631167028862be2a173976ca11'));
await check('tx', 'blob tx -> header blobGasUsed = 131072', async () => {
  const b = await call('eth_getBlockByNumber', [toHex(types[3].block), false]);
  return eq(Number(b.blobGasUsed), 131072);
});
await check('tx', 'EIP-1559 base fee recurrence holds block to block', async () => {
  const n = Number((await call('eth_getBlockByNumber', ['latest', false])).number);
  let checked = 0;
  // skip zknet's boot blocks: anvil carries the genesis base fee into block 1,
  // and zknet pins the fee at SNAP.head.number to resume at mainnet's level
  for (let i = Math.max(n - 12, SNAP.head.number + 2); i <= n; i++) {
    const p = await call('eth_getBlockByNumber', [toHex(i - 1), false]);
    const c = await call('eth_getBlockByNumber', [toHex(i), false]);
    if (!p || !c) continue;
    const bf = BigInt(p.baseFeePerGas), used = BigInt(p.gasUsed), target = BigInt(p.gasLimit) / 2n;
    let want = bf;
    if (used > target) { const d = (bf * (used - target)) / target / 8n; want = bf + (d > 1n ? d : 1n); }
    else if (used < target) want = bf - (bf * (target - used)) / target / 8n;
    if (BigInt(c.baseFeePerGas) !== want) return { ok: false, detail: `block ${i}: ${c.baseFeePerGas} != ${want}` };
    checked++;
  }
  return { ok: checked > 0, detail: `${checked} consecutive blocks` };
});
await check('tx', 'priority fee paid to builder coinbase', async () => {
  const before = BigInt(await call('eth_getBalance', [SNAP.head.miner, 'latest']));
  const hash = await wallet.sendTransaction({ to: '0x000000000000000000000000000000000000dEaD', maxPriorityFeePerGas: 2_000_000_000n, maxFeePerGas: 10_000_000_000n });
  const r = await pub.waitForTransactionReceipt({ hash });
  const after = BigInt(await call('eth_getBalance', [SNAP.head.miner, toHex(r.blockNumber)]));
  return { ok: after > before, detail: `+${after - before} wei` };
});

// ------------------------------------------------------------ report
const pad = (s, n) => String(s).padEnd(n);
let fails = 0, gaps = 0;
let group = '';
for (const r of results) {
  if (r.group !== group) { group = r.group; console.log(`\n${group.toUpperCase()}`); }
  if (r.status === 'FAIL') fails++;
  if (r.status === 'GAP') gaps++;
  const mark = r.status === 'PASS' ? 'PASS' : r.status === 'GAP' ? 'GAP ' : 'FAIL';
  console.log(`  ${mark}  ${pad(r.name, 58)} ${r.detail ?? ''}`);
}
console.log(`\n${results.length - fails - gaps} pass, ${gaps} known gaps, ${fails} fail   (${URL}, ${info.hardFork}, block ${Number(head.number)})`);
const out = opt('--json');
if (out) writeFileSync(out, JSON.stringify({ url: URL, at: new Date().toISOString(), results }, null, 1));
process.exit(fails ? 1 : 0);
