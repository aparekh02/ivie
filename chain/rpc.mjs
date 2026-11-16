// Minimal JSON-RPC client + helpers shared by the chain and e2e scripts.
import { keccak_256 } from '@noble/hashes/sha3.js';
import { sha256 } from '@noble/hashes/sha2.js';

let id = 0;
export async function rpc(url, method, params = []) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
  });
  const j = await res.json();
  if (j.error) {
    const e = new Error(`${method}: ${j.error.message}`);
    e.code = j.error.code;
    e.data = j.error.data;
    throw e;
  }
  return j.result;
}

export const hexToBytes = (h) => Uint8Array.from(Buffer.from(h.replace(/^0x/, ''), 'hex'));
export const bytesToHex = (b) => '0x' + Buffer.from(b).toString('hex');
export const keccakHex = (h) => bytesToHex(keccak_256(hexToBytes(h)));
export const sha256Bytes = (b) => sha256(b);
export const toHex = (n) => '0x' + BigInt(n).toString(16);
export const word = (n) => '0x' + BigInt(n).toString(16).padStart(64, '0');

// The deposit contract's constructor fills zero_hashes[i+1] = sha256(z[i] || z[i]).
// Solidity layout: branch[32] @ slots 0..31, deposit_count @ 32, zero_hashes[32] @ 33..64.
export function depositContractStorage() {
  const out = {};
  let z = new Uint8Array(32);
  for (let i = 0; i < 31; i++) {
    const buf = new Uint8Array(64);
    buf.set(z, 0);
    buf.set(z, 32);
    z = sha256(buf);
    out[word(33 + i + 1)] = bytesToHex(z);
  }
  return out;
}
