#!/usr/bin/env node
// zknet: an anvil node configured to look like Ethereum mainnet.
//
//   node chain/zknet.mjs start [--fast] [--fork <rpc>] [--port 9545] [--fresh]
//   node chain/zknet.mjs stop | status | env
//
// What "like mainnet" means here (every item is checked by chain/fidelity.mjs):
//   chain id 1, Osaka rules (EIP-7825 tx gas cap on), 12 s slots aligned to
//   the beacon genesis clock, mainnet block height / gas limit / base fee from
//   the snapshot, a builder coinbase, the EIP-4788/2935/7002/7251 system
//   contracts, and canonical singletons (deposit contract, Multicall3, Permit2,
//   CreateX, Safe factory, WETH9, CREATE2 deployer) with mainnet bytecode.
//
// --fast mines on every tx (plus 12 s timer) so tests don't wait a slot.
// --fork pins real mainnet state at the snapshot block instead of a genesis.

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, openSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { rpc, depositContractStorage, toHex } from './rpc.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const RUN = join(here, '.run');
const SNAP = JSON.parse(readFileSync(join(here, 'mainnet-snapshot.json'), 'utf8'));

const args = process.argv.slice(2);
const cmd = args[0] || 'status';
const flag = (n) => args.includes(n);
const opt = (n, d) => (args.indexOf(n) > 0 ? args[args.indexOf(n) + 1] : d);
const PORT = Number(opt('--port', process.env.ZKNET_PORT || 9545));
const URL = `http://127.0.0.1:${PORT}`;
const pidFile = join(RUN, `anvil-${PORT}.pid`);
const metaFile = join(RUN, `anvil-${PORT}.json`);

// Builder address used as block.coinbase (Titan in the snapshot head).
const COINBASE = SNAP.head.miner;
// Boot WARMUP blocks below the snapshot height and mine them at 12 s
// spacing, so BLOCKHASH, EIP-2935, eth_feeHistory and the base-fee curve have
// real history (a node with no parents breaks tools that look back).
const WARMUP = 64;

// Next mainnet-aligned slot timestamp at or after `t`.
function slotAligned(t) {
  const { genesisTime, secondsPerSlot } = SNAP.beacon;
  return genesisTime + Math.ceil((t - genesisTime) / secondsPerSlot) * secondsPerSlot;
}

async function up() {
  try { await rpc(URL, 'eth_chainId'); return true; } catch { return false; }
}

async function start() {
  if (await up()) { console.log(`zknet already running at ${URL}`); return; }
  mkdirSync(RUN, { recursive: true });
  const fork = opt('--fork', process.env.ZKNET_FORK_URL);
  const statePath = join(RUN, `state-${PORT}.json`);
  if (flag('--fresh')) rmSync(statePath, { force: true });

  const a = [
    '--port', String(PORT),
    '--hardfork', 'osaka',
    '--chain-id', String(Number(SNAP.config.chainId)),
    '--block-time', String(SNAP.beacon.secondsPerSlot),
    '--slots-in-an-epoch', String(SNAP.beacon.slotsPerEpoch),
    '--gas-limit', String(SNAP.head.gasLimit),
    '--enable-tx-gas-limit',
    '--order', 'fees',
    '--steps-tracing',
    '--accounts', '10',
    '--balance', '10000',
  ];
  if (flag('--fast')) a.push('--mixed-mining');
  if (fork) {
    a.push('--fork-url', fork, '--fork-block-number', String(SNAP.head.number));
  } else {
    a.push(
      '--number', String(SNAP.head.number - WARMUP),
      '--timestamp', String(slotAligned(Math.floor(Date.now() / 1000)) - WARMUP * SNAP.beacon.secondsPerSlot),
      '--base-fee', String(SNAP.head.baseFeePerGas),
    );
    if (!flag('--ephemeral')) a.push('--state', statePath);
  }

  const log = openSync(join(RUN, `anvil-${PORT}.log`), 'a');
  const child = spawn('anvil', a, { detached: true, stdio: ['ignore', log, log] });
  child.unref();
  writeFileSync(pidFile, String(child.pid));

  for (let i = 0; i < 100 && !(await up()); i++) await new Promise((r) => setTimeout(r, 100));
  if (!(await up())) throw new Error(`anvil did not come up; see ${join(RUN, `anvil-${PORT}.log`)}`);

  await rpc(URL, 'anvil_setCoinbase', [COINBASE]);
  const fresh = Number(await rpc(URL, 'eth_blockNumber')) === SNAP.head.number - WARMUP;
  if (!fork) await installMainnetArtifacts();
  if (!fork && fresh) {
    await rpc(URL, 'anvil_mine', [toHex(WARMUP), toHex(SNAP.beacon.secondsPerSlot)]);
    // empty warm-up blocks decay the base fee 12.5% each; resume at mainnet's level
    await rpc(URL, 'anvil_setNextBlockBaseFeePerGas', [toHex(SNAP.head.baseFeePerGas)]);
    await rpc(URL, 'evm_mine', []);
  }
  writeFileSync(metaFile, JSON.stringify({ url: URL, pid: child.pid, fork: fork || null, fast: flag('--fast'), args: a }, null, 1));
  const info = await rpc(URL, 'anvil_nodeInfo');
  console.log(`zknet up at ${URL}  chainId=${Number(info.environment.chainId)} fork=${info.hardFork} block=${Number(info.currentBlockNumber)} mode=${fork ? 'fork' : 'genesis'}${flag('--fast') ? '+fast' : ''}`);
}

// Canonical singletons with mainnet runtime bytecode (and constructor storage).
async function installMainnetArtifacts() {
  // System contracts: anvil ships its own builds; mainnet's deployed EIP-7251
  // bytecode differs, so install exactly what mainnet runs.
  for (const s of Object.values(SNAP.systemContracts)) {
    const have = await rpc(URL, 'eth_getCode', [s.address, 'latest']);
    if (have.toLowerCase() !== s.code.toLowerCase()) await rpc(URL, 'anvil_setCode', [s.address, s.code]);
  }
  for (const p of SNAP.predeploys) {
    const have = await rpc(URL, 'eth_getCode', [p.address, 'latest']);
    if (have.toLowerCase() !== p.code.toLowerCase()) await rpc(URL, 'anvil_setCode', [p.address, p.code]);
    const storage = p.storageRule === 'deposit-zero-hashes' ? depositContractStorage() : p.storage || {};
    for (const [slot, v] of Object.entries(storage)) await rpc(URL, 'anvil_setStorageAt', [p.address, slot, v]);
  }
  // WETH9 holds ETH 1:1 with its supply; a fresh chain has zero supply.
  await rpc(URL, 'anvil_setBalance', ['0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', toHex(0)]);
}

async function stop() {
  if (!existsSync(pidFile)) { console.log('zknet not running (no pid file)'); return; }
  const pid = Number(readFileSync(pidFile, 'utf8'));
  try { process.kill(pid, 'SIGTERM'); } catch {}
  for (let i = 0; i < 50 && (await up()); i++) await new Promise((r) => setTimeout(r, 100));
  rmSync(pidFile, { force: true });
  console.log(`zknet stopped (pid ${pid})`);
}

async function status() {
  if (!(await up())) { console.log(`zknet down (${URL})`); process.exitCode = 1; return; }
  const info = await rpc(URL, 'anvil_nodeInfo');
  const b = await rpc(URL, 'eth_getBlockByNumber', ['latest', false]);
  console.log(JSON.stringify({ url: URL, hardFork: info.hardFork, chainId: Number(info.environment.chainId),
    block: Number(b.number), timestamp: Number(b.timestamp), gasLimit: Number(b.gasLimit),
    baseFeePerGas: Number(b.baseFeePerGas), coinbase: b.miner }, null, 1));
}

const cmds = { start, stop, status, env: async () => console.log(`export ZKNET_RPC=${URL}`) };
if (!cmds[cmd]) { console.error(`unknown command ${cmd}`); process.exit(2); }
await cmds[cmd]();
