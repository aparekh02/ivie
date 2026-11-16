#!/usr/bin/env node
// Pull the parameters zknet copies from Ethereum mainnet and freeze them in
// chain/mainnet-snapshot.json. Read-only: eth_config (EIP-7910), the latest
// header, and eth_getCode / eth_getStorageAt for canonical contracts.
//
//   node chain/snapshot.mjs [--rpc https://ethereum-rpc.publicnode.com]
//
// The snapshot is committed so the chain boots offline and reproducibly.

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { rpc, keccakHex } from './rpc.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const argRpc = process.argv.indexOf('--rpc');
const RPC = argRpc > 0 ? process.argv[argRpc + 1] : (process.env.MAINNET_RPC || 'https://ethereum-rpc.publicnode.com');

// Canonical singletons that exist at the same address on mainnet. Contracts
// whose constructors write storage list the slots to copy.
const PREDEPLOYS = [
  { name: 'DepositContract', address: '0x00000000219ab540356cBB839Cbe05303d7705Fa', storageRule: 'deposit-zero-hashes' },
  { name: 'Multicall3', address: '0xcA11bde05977b3631167028862bE2a173976CA11' },
  { name: 'Permit2', address: '0x000000000022D473030F116dDEE9F6B43aC78BA3' },
  { name: 'SafeSingletonFactory', address: '0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7' },
  { name: 'CreateX', address: '0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed' },
  // Not copied: ERC-4337 EntryPoints. Their constructors CREATE a SenderCreator
  // child whose address is baked in as an immutable, so code alone is broken.
  { name: 'WETH9', address: '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2', slots: [0, 1, 2] },
  { name: 'Create2Deployer', address: '0x4e59b44847b379578588920cA78FbF26c0B4956C' },
];

const call = (m, p) => rpc(RPC, m, p);

const config = await call('eth_config', []);
const head = await call('eth_getBlockByNumber', ['latest', false]);
const systemContracts = {};
for (const [k, addr] of Object.entries(config.current.systemContracts)) {
  const code = await call('eth_getCode', [addr, head.number]);
  systemContracts[k] = { address: addr, code, codeHash: keccakHex(code), codeSize: (code.length - 2) / 2 };
}

const predeploys = [];
for (const p of PREDEPLOYS) {
  const code = await call('eth_getCode', [p.address, head.number]);
  if (code === '0x') throw new Error(`${p.name} has no code on mainnet`);
  const storage = {};
  for (const s of p.slots || []) {
    const slot = '0x' + s.toString(16).padStart(64, '0');
    const v = await call('eth_getStorageAt', [p.address, slot, head.number]);
    if (BigInt(v) !== 0n) storage[slot] = v;
  }
  predeploys.push({ ...p, slots: undefined, code, codeHash: keccakHex(code), storage });
  console.log(`  ${p.name.padEnd(22)} ${p.address} ${(code.length - 2) / 2} bytes`);
}

const snap = {
  takenAt: new Date().toISOString(),
  source: RPC.replace(/\/\/[^/]*@/, '//'),
  head: {
    number: Number(head.number),
    timestamp: Number(head.timestamp),
    gasLimit: Number(head.gasLimit),
    baseFeePerGas: Number(head.baseFeePerGas),
    excessBlobGas: Number(head.excessBlobGas),
    miner: head.miner,
    extraData: head.extraData,
  },
  // Beacon chain genesis; every execution block timestamp is genesis + 12*slot.
  beacon: { genesisTime: 1606824023, secondsPerSlot: 12, slotsPerEpoch: 32 },
  config: config.current,
  systemContracts,
  predeploys,
};
const out = join(here, 'mainnet-snapshot.json');
writeFileSync(out, JSON.stringify(snap, null, 1));
console.log(`wrote ${out}: mainnet block ${snap.head.number}, gasLimit ${snap.head.gasLimit}, blobs ${config.current.blobSchedule.target}/${config.current.blobSchedule.max}`);
