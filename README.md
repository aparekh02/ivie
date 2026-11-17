# ivie — a QAOA-based attack architecture for ZK-proof hashes

**ivie** is a quantum attack lab for the hashes that commit state in STARK / zk
systems. The hashes that make these proofs cheap — arithmetization-friendly
permutations like Poseidon, built from low-degree algebraic rounds — are exactly
the ones a structured quantum/algebraic attack can take apart. ivie builds that
attack, recovers **verified** hash preimages and second preimages (the primitive
that lets a committed Merkle state root be tampered with), and measures the round
count at which it stops working.

It pairs two engines over the field `F_p`, `p = 2^251 + 17·2^192 + 1`:

- a **QAOA** search that drives a variational quantum circuit down a
  Hamming-distance cost between a candidate's hash and the target, and
- an **algebraic core** (Gröbner-style elimination + XL/Macaulay linearization)
  that eliminates the round system to a polynomial and solves it directly.

ivie was developed and validated against a self-contained STARK rollup testbed —
the `zknet` chain bundled in this repo — which is where the attack runs against a
real prover, verifier and on-L1 commitment, end to end. The chain is the
workbench; ivie is the program.

```
cd client
cargo run --release -p quantum                 # full lab: attack + margin curve
cargo run --release -p quantum -- preimage 5   # elimination preimage attack at R rounds
cargo run --release -p quantum -- qaoa         # QAOA preimage amplification (statevector)
cargo run --release -p quantum -- forge        # second preimage -> tamperable leaf
cargo run --release -p quantum -- margin       # degree-vs-rounds security margin
```

## The architecture (`client/crates/quantum`)

| module | role |
|---|---|
| `poseidon` | models the in-AIR Poseidon permutation (x³ S-box, t=3 MDS) at a tunable round count `R`, both numerically (reusing the real round map) and symbolically over `F_p[b]` |
| `qaoa` | exact statevector QAOA over a diagonal Hamming-distance cost `C(x) = popcount(low_bits(leaf_r(x)) ⊕ low_bits(target))`; the graded landscape lets the circuit concentrate amplitude on the preimage |
| `groebner` | eliminates the round system to one univariate `f(b) = leaf_r(b) − target` (the preimage ideal's Gröbner basis under elimination) and root-finds it: `gcd(f, x^p − x)` then Cantor–Zassenhaus; `fp_roots` enumerates preimages to exhibit collisions |
| `xl` | keeps the interior round states as variables and solves the degree-3 system by XL/Macaulay linearization, reporting the **solving degree** `D*` — the Gröbner-family security metric a round count exists to inflate |
| `attack` | chains it end to end (second preimage → tamperable leaf) and builds the **margin curve**; emits the visual-memory JSON |
| `grover` / `oracle` | real Grover simulation against the *keccak* floors (Merkle truncation, Fiat-Shamir grind) — the non-algebraic baseline the margin compares against |

`viz/index.html` is a self-contained visual-memory page rendering the attack
pipeline, the degree wall, the XL solving-degree table and the QAOA distribution.
See [client/crates/quantum/README.md](client/crates/quantum/README.md).

### What it finds (measured on the testbed)

- **QAOA** amplifies a windowed preimage **7.8×** over the uniform baseline
  (`n = 12`, `p = 2` layers) — the quantum read of the algebraic structure.
- **Elimination** recovers a blind reduced-round preimage from a committed leaf
  alone, verified against the real hash: **R = 5 in 0.7 s, R = 7 in 35 s**.
- **Second preimages** at R = 3 and R = 5 → a wallet value swaps while the leaf
  hash, path and committed root stay fixed, so the verifier's
  commit-before-challenge check passes on a false state.
- **XL** reaches solving degree **D\* = 9 at R = 2** (840×715 Macaulay matrix),
  preimage verified.

### The margin (the research result)

The elimination polynomial has degree `3^r`, so `log2` degree grows `1.585`
bits/round. The attack is feasible only while that polynomial can be built:
degree crosses `2^64` at r = 41, `2^96` at r = 61, and the Grover preimage line
(`2^125`) at r = 80. At the deployed `ROUNDS = 127` the degree is `3^127 ≈ 2^201`
— unbuildable, leaving only a `2^125` Grover search. The round count is the whole
margin, and it is sized correctly.

### Honest scope

- Every preimage is recovered from a committed target alone and verified against
  the genuine permutation. The breaks are real at reduced rounds.
- At full rounds the hash is **not** broken; the deliverable is the margin, not a
  usable exploit, and ivie never fabricates one or weakens the verifier.
- Keccak-256 (the Merkle / Fiat-Shamir hash) has no low-degree structure — it
  stays Grover-only (`2^80`). **Shor is inert**: nothing here has a hidden
  subgroup to recover. Only the arithmetization-friendly hash is algebraically
  attackable.

---

## The testbed (`chain/`, `contracts/`, `client/`)

Where ivie runs: a mainnet-fidelity local chain with a StarkWare-modeled validity
rollup, so the attack targets a real prover, verifier and on-L1 commitment rather
than a toy.

```
npm install
npm run chain:start:fast                         # or chain:start for strict 12 s slots
cd contracts && forge build && forge test        # verifier + rollup tests on Rust-made proofs
cd ../client
cargo run --release -p rollup -- deploy          # CREATE2-deploy the rollup contracts
cargo run --release -p rollup -- run -n 3 -b 4   # sequencer + prover: commit, prove, finalize
cargo run --release -p zknetd                    # light client + plug-in socket
```

Requires foundry (anvil/forge/cast ≥ 1.8), node ≥ 22, and Rust 1.9x.

### The chain (`chain/`)

`chain/snapshot.mjs` freezes mainnet once (EIP-7910 `eth_config`, latest header,
canonical bytecode) into a committed snapshot, so the chain boots offline and
reproducibly. `chain/zknet.mjs start` launches anvil configured to behave like
Ethereum mainnet as of November 2026: chain id 1, Osaka rules, mainnet gas limit
/ base fee / height, 12 s beacon-aligned slots, and mainnet system contracts and
singletons (EIP-4788/2935/7002/7251, Deposit, Multicall3, Permit2, CreateX, Safe
factory, WETH9, CREATE2 deployer) installed with mainnet bytecode.
`chain/fidelity.mjs` checks all of it against known-answer vectors (precompiles,
opcodes, size/gas limits, the EIP-1559 recurrence, system code hashes): currently
**53 pass, 0 fail, 2 known gaps** (anvil's hard-coded blob schedule and absent
consensus layer, reported as `GAP`, not hidden).

### The STARK rollup (`contracts/src/stark/`, `client/`)

A validity rollup verified on L1 the way production zk-rollups verify blocks:
`ZKRollup.commitBatch(txs, claimedRoot)` posts L2 transfers as calldata, then
`finalizeBatch(i, txs, proof)` runs `StarkVerifier` on a STARK proof that applying
those txs to the last finalized root yields the claimed root before `stateRoot`
moves. The proof system is modeled part by part on StarkWare's stack (Stone,
SHARP, Starknet's L1 contracts):

- **Field:** p = 2^251 + 17·2^192 + 1. **LDE:** blowup 16, bit-reversed.
- **Merkle:** keccak truncated to 160 bits, batched multi-proofs.
- **FRI:** layer 0 is the DEEP composition, then fold by 8; last layer as coefficients.
- **Channel:** StarkWare-style rejection sampling + prefixed proof-of-work.
- **Security:** 18 queries, 24-bit grinding, ~96 conjectured bits.
- **AIR:** 18 columns, 55 constraints; each transfer is two Merkle-path updates through a Poseidon-style state tree, balances range-checked to 64 bits, start/end roots pinned.

The Rust prover (`zknet-core::stark`) and a native twin of the verifier report the
same reject reason as the contract. `zknetd` follows the L1 nodes and serves a
Unix socket; `zknet-sdk` is the Rust client and exposes the verifier as a raw
oracle. See [client/README.md](client/README.md).

## Layout

```
client/crates/quantum/   ivie: the attack architecture (poseidon, qaoa, groebner, xl, attack) + viz/
chain/                   zknet.mjs (launcher), snapshot.mjs, mainnet-snapshot.json, fidelity.mjs
contracts/src/stark/     StarkVerifier.sol, ZKRollup.sol, generated/RollupPeriodic.sol
contracts/test/          Stark.t.sol, vectors/stark/ (fixtures from `zkrollup fixture`)
client/crates/           zknet-core (STARK: field, hash, AIR, prover, verifier), zknetd (daemon + socket),
                         zknet-sdk (socket client, oracles), rollup (zkrollup sequencer/prover)
```
