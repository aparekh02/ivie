# ivie

ivie attacks the hashes that ZK systems use to commit state. Proofs like STARKs
lean on arithmetization-friendly hashes (Poseidon and friends), which are built
from low-degree algebraic rounds to keep proving cheap. That low degree is also
a weakness. ivie turns a reduced-round hash into a polynomial system and solves
it, recovering preimages and collisions. A collision on a leaf is enough to swap
a wallet balance while the Merkle root the verifier committed to stays the same.

It runs two engines over `F_p` (`p = 2^251 + 17·2^192 + 1`):

- a QAOA circuit that searches for a preimage by minimizing the Hamming distance
  between a candidate's hash and the target, and
- an algebraic solver that eliminates the round system down to one polynomial
  and finds its roots directly (plus an XL/Macaulay variant).

I built and tested all of this against the STARK rollup in this repo (the
`zknet` chain). The chain isn't the point; it's just a realistic place to run
the attack against an actual prover, verifier, and on-chain commitment. The
honest finding is a curve: the attack is cheap at a few rounds and impossible at
the 127 the hash actually uses.

```
cd client
cargo run --release -p quantum                 # everything, plus the margin curve
cargo run --release -p quantum -- preimage 5   # recover a 5-round preimage
cargo run --release -p quantum -- qaoa         # QAOA statevector run
cargo run --release -p quantum -- forge        # collision -> swapped wallet value
cargo run --release -p quantum -- margin       # degree vs rounds
```

## How it works (`client/crates/quantum`)

The leaf hash is `leaf(b) = P([b, 0, tag])[0]`, where `P` is the Poseidon
permutation. For `r` rounds the attacker sees a committed leaf and wants a `b`
that hashes to it.

| module | what it does |
|---|---|
| `poseidon` | the round map at a chosen `r`, both as real field ops and symbolically over `F_p[b]` |
| `groebner` | composes the rounds into `f(b) = leaf_r(b) − target` (degree `3^r`), then finds its `F_p` roots with `gcd(f, x^p − x)` and Cantor–Zassenhaus |
| `xl` | the multivariate version: keep each round's state as variables, linearize (XL/Macaulay), and read off the solving degree `D*` |
| `qaoa` | an exact statevector QAOA whose cost is the Hamming distance to the target's output bits |
| `attack` | ties it together (collision → tampered leaf) and computes the margin curve |
| `grover`, `oracle` | a Grover simulation on the keccak hashes (Merkle, Fiat-Shamir), as a baseline to compare against |

Every recovered `b` is checked against the real permutation before I count it.
There's a self-contained page at `client/crates/quantum/viz/index.html` with the
pipeline, the degree curve, the XL table, and the QAOA distribution. The crate's
own README has more.

## Results

Measured on the testbed:

- QAOA raises the chance of sampling a preimage to about 7.8× the uniform rate
  (12 qubits, 2 layers).
- The algebraic solver recovers a preimage from the committed leaf alone: 5
  rounds in 0.7 s, 7 rounds in 35 s, both verified.
- At 3 and 5 rounds it finds a second input with the same leaf hash. Swap the
  balance to that input and the hash, path, and root don't change, so the
  verifier accepts it.
- XL hits solving degree 9 at 2 rounds (an 840×715 Macaulay matrix).

The elimination polynomial has degree `3^r`, so its size grows about 1.585 bits
per round. It passes `2^64` around round 41, `2^96` around round 61, and the
cost of a plain Grover preimage search (`2^125`) around round 80. At 127 rounds
the polynomial is `3^127 ≈ 2^201`; you can't even write it down, and Grover is
the only thing left. So the round count is doing its job.

## What this isn't

The full 127-round hash is not broken, and I don't pretend otherwise or weaken
the verifier to fake it. Attacking round-reduced versions and extrapolating is
the standard way to measure these hashes.

Keccak-256 (the Merkle and Fiat-Shamir hash) has no algebraic structure to
exploit, so it's Grover-only (`2^80`). Shor doesn't apply to any of this: it's
all hashes, no discrete log or hidden subgroup. The only lever quantum gives you
here is a Grover-style square-root, and the algebraic attack only beats that
while `3^r` is small.

## The testbed

A local chain that mimics Ethereum mainnet, with a StarkWare-style validity
rollup on top. It's here so the attack has a real target instead of a toy.

```
npm install
npm run chain:start:fast                         # or chain:start for 12 s slots
cd contracts && forge build && forge test
cd ../client
cargo run --release -p rollup -- deploy
cargo run --release -p rollup -- run -n 3 -b 4   # commit, prove, finalize
cargo run --release -p zknetd                    # light client + socket
```

Needs foundry (anvil/forge/cast ≥ 1.8), node ≥ 22, Rust 1.9x.

**Chain (`chain/`).** `snapshot.mjs` reads mainnet once and freezes it (config,
latest header, canonical bytecode) into a committed file, so the chain boots
offline and the same way every time. `zknet.mjs start` runs anvil as mainnet at
November 2026: chain id 1, Osaka rules, mainnet gas limit, base fee and height,
12 s slots, and the real system contracts and singletons installed with mainnet
bytecode. `fidelity.mjs` checks it against known answers (precompiles, opcodes,
limits, the base-fee recurrence, code hashes): 53 pass, 0 fail, 2 known gaps
(anvil's fixed blob schedule and missing consensus layer, both reported, not
hidden).

**Rollup (`contracts/src/stark/`, `client/`).** `commitBatch(txs, claimedRoot)`
posts the L2 transfers as calldata; `finalizeBatch(i, txs, proof)` runs
`StarkVerifier` on a STARK proof that those txs take the last root to the claimed
one, and only then does `stateRoot` move. The proof system follows StarkWare's
stack (Stone, SHARP, Starknet's L1 contracts):

- field p = 2^251 + 17·2^192 + 1; LDE blowup 16, bit-reversed
- Merkle over keccak truncated to 160 bits, batched multi-proofs
- FRI: layer 0 is the DEEP composition, then fold by 8, last layer as coefficients
- StarkWare-style channel with rejection sampling and prefixed proof-of-work
- 18 queries, 24-bit grinding, ~96 conjectured bits
- AIR: 18 columns, 55 constraints; each transfer is two Merkle-path updates through a Poseidon state tree, balances range-checked to 64 bits, start and end roots pinned

The Rust prover and a native copy of the verifier give the same reject reason as
the contract. `zknetd` follows the L1 nodes and serves a Unix socket; `zknet-sdk`
is the client for it. See [client/README.md](client/README.md).

## Layout

```
client/crates/quantum/   ivie: poseidon, qaoa, groebner, xl, attack, viz/
chain/                   zknet.mjs, snapshot.mjs, mainnet-snapshot.json, fidelity.mjs
contracts/src/stark/     StarkVerifier.sol, ZKRollup.sol, generated/RollupPeriodic.sol
contracts/test/          Stark.t.sol, vectors/stark/
client/crates/           zknet-core (field, hash, AIR, prover, verifier), zknetd, zknet-sdk, rollup
```
