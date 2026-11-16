# zknet: a mainnet-fidelity testnet with a STARK rollup verified on L1

A research testbed for how quantum computing affects STARK verification:

1. **zknet**: an anvil node configured to behave like Ethereum mainnet as of
   November 2026 (Osaka rules, chain id 1, mainnet gas limit / base fee /
   height, 12 s beacon-aligned slots, mainnet system contracts and singletons).
   It is checked by a 55-probe fidelity suite.
2. **A validity rollup**: L2 transfer batches are proven with a STARK, modeled
   part by part on StarkWare's stack, and checked on L1 before they finalize.
   It comes with a Rust prover, a native verifier that matches the contract
   check for check, adversarial-prover knobs, and a raw oracle interface for
   experiments.

```
npm install
npm run chain:start:fast                         # or chain:start for strict 12 s slots
cd contracts && forge build && forge test        # verifier + rollup tests on Rust-made proofs
cd ../client
cargo run --release -p rollup -- deploy          # CREATE2-deploy the rollup contracts
cargo run --release -p rollup -- run -n 3 -b 4   # sequencer + prover: commit, prove, finalize
cargo run --release -p zknetd                    # light client + plug-in socket
cargo run --release -p prover                    # research scratch file (add `-- chain` for the EVM)
```

Requires foundry (anvil/forge/cast >= 1.8), node >= 22, and Rust 1.9x.

## 1. The chain (`chain/`)

`chain/snapshot.mjs` reads mainnet once (EIP-7910 `eth_config`, the latest
header, and the bytecode of canonical contracts) and freezes it in
`chain/mainnet-snapshot.json`. It is committed, so the chain boots offline and
reproducibly. `chain/zknet.mjs start` then launches anvil with:

| Property | zknet | How |
|---|---|---|
| Chain id / net_version | 1 / "1" | `--chain-id` |
| Rules | Osaka (Fusaka), incl. EIP-7825 tx gas cap 2^24 | `--hardfork osaka --enable-tx-gas-limit` |
| Block gas limit | 60,000,000 (mainnet) | snapshot |
| Height | mainnet height at snapshot | boots 64 blocks below, mines 64 real 12 s blocks of history |
| Timestamps | on the beacon slot grid `1606824023 + 12k` | aligned `--timestamp`, `--block-time 12` |
| Base fee | mainnet's at snapshot, then EIP-1559 | pinned after warm-up |
| Coinbase | the snapshot block's builder | `anvil_setCoinbase` (priority fees accrue to it) |
| System contracts | EIP-4788, 2935, 7002, 7251 with **mainnet's deployed bytecode** | anvil's EIP-7251 build differs from mainnet's, so it is replaced |
| Singletons | Deposit contract (+ constructor `zero_hashes`), Multicall3, Permit2, CreateX, Safe factory, WETH9 (+ name/symbol slots), CREATE2 deployer | mainnet bytecode via `anvil_setCode` |
| Tx types | 0 (EIP-155), 1, 2, 3 (EIP-7594 cell-proof blobs), 4 (EIP-7702) | all verified mined |

Modes: `--fast` (also mines on tx arrival, for development), `--fork <rpc>`
(real mainnet state pinned at the snapshot block), `--port`, `--fresh`
(wipe persisted state). State persists in `chain/.run/` across restarts.

`chain/fidelity.mjs` checks all of this against known-answer vectors:
ecrecover, sha256, ripemd, identity, modexp (+ EIP-7823 bound), BN254
add/mul/pairing, blake2f, KZG point evaluation, BLS12-381 G1ADD/G1MSM/G2/
pairing/maps, P256VERIFY (EIP-7951). It also checks the opcodes CLZ (EIP-7939),
PUSH0, MCOPY, TSTORE/TLOAD, CHAINID, BASEFEE and BLOBBASEFEE; the EIP-3860,
EIP-170 and EIP-7825 limits; the EIP-1559 base-fee recurrence block to block;
EIP-2935 parent hashes; system and singleton code hashes against mainnet; and
the deposit contract's empty root.

Current result: **53 pass, 0 fail, 2 known gaps** (in `--fast` mode, the slot
grid check also reports as a gap).

### Known gaps (anvil limitations, reported as `GAP`, not hidden)

- **Blob schedule.** Anvil hard-codes Prague's 6/9 blobs. Mainnet runs BPO2
  14/21 with update fraction 11684671, so blob base-fee dynamics differ.
  `--init` genesis `blobSchedule` is ignored.
- **No consensus layer.** `parentBeaconBlockRoot` is zero, so the EIP-4788
  contract stores zero roots, and there are no withdrawals or EL requests
  from the CL.
- Single sequencer, no p2p or mempool propagation, no reorgs.
- In `--fast` mode, tx-triggered blocks land off the 12 s slot grid.

## 2. The STARK rollup (`contracts/src/stark/`, `client/`)

A validity rollup, verified on L1 the way production zk-rollups verify blocks:

1. The sequencer calls `ZKRollup.commitBatch(txs, claimedRoot)` and posts the
   L2 transfers as calldata (the data-availability layer).
2. Anyone calls `finalizeBatch(i, txs, proof)`. `StarkVerifier` checks a STARK
   proof that applying exactly those txs to the last finalized root yields the
   claimed root. Only then does `stateRoot` move.
3. Batches finalize in order. `revertBatches` drops unproven ones.

The proof system is modeled part by part on StarkWare's stack (Stone prover,
SHARP, and Starknet's L1 contracts):

| part | status | modeled on |
|---|---|---|
| 1. commitments, FRI, channel, parameters | done | Stone + `evm-verifier` (MerkleVerifier, FriLayer, VerifierChannel) |
| 2. verification split across L1 txs + fact registry | next | SHARP: Merkle/FRI statement contracts, GpsStatementVerifier |
| 3. interaction phase (permutation and range-check arguments) | planned | Cairo memory / range-check AIR |
| 4. CPU AIR + public memory + program hash | planned | Cairo VM |
| 5. rollup logic as a program; output = roots + state diff | planned | Starknet OS + `StarknetCore.updateState` |

What Part 1 contains:
- **Field:** p = 2^251 + 17·2^192 + 1.
- **LDE:** blowup 16, rows committed in bit-reversed order.
- **Merkle:** keccak truncated to 160 bits, with batched multi-proofs.
- **FRI:** layer 0 is the DEEP composition (friStepSizes[0] = 0). After that, each layer folds by 8 and keeps one coset per leaf. The last layer is sent as coefficients.
- **Channel:** a StarkWare-style channel with rejection sampling and a prefixed proof-of-work.
- **Security:** 18 queries and 24-bit grinding, about 96 conjectured bits.

The AIR has 18 columns and 55 constraints:
- Each transfer is two Merkle-path updates through a Poseidon-style state tree.
- Balances are range-checked to 64 bits.
- Boundary constraints pin the start and end roots.
- The tx data is interpolated into the constraints.

The Rust prover (`zknet-core::stark`) and a native twin of the verifier report
the same reject reason as the contract. The design follows StarkWare's
architecture; I haven't checked byte-level compatibility with Stone.

```
cd contracts && forge build && cd ../client
cargo run --release -p rollup -- deploy                 # CREATE2: RollupPeriodic, StarkVerifier, ZKRollup
cargo run --release -p rollup -- run -n 3 -b 4          # commit -> prove -> finalize
cargo run --release -p rollup -- attack                 # lies the contract refuses, with the failing check
cargo run --release -p rollup -- status                 # L2 state rebuilt from L1 calldata == L1 root
```

| batch | trace rows | prove (incl. 24-bit grinding) | proof calldata | finalizeBatch gas |
|---|---|---|---|---|
| 4 txs | 8,192 | 0.5–3 s | 48–53 KB | 3.1–3.3M |
| 16 txs | 32,768 | 3 s | 62 KB | 4.16M |

## 3. Rust client and plug-in socket (`client/`)

`zknetd` follows the L1 nodes (heads and the rollup's batch events) and serves
a Unix socket (`chain/.run/zknetd.sock`, newline-delimited JSON-RPC).
`zknet-sdk` is the Rust client for that socket and exposes the STARK verifier
as a raw oracle. See [client/README.md](client/README.md).

## Layout

```
chain/                zknet.mjs (launcher), snapshot.mjs, mainnet-snapshot.json, fidelity.mjs, wallet.mjs, rpc.mjs
contracts/src/stark/  StarkVerifier.sol, ZKRollup.sol, generated/RollupPeriodic.sol
contracts/test/       Stark.t.sol, vectors/stark/ (fixtures from `zkrollup fixture`)
client/crates/        zknet-core (STARK: field, hash, AIR, prover, verifier), zknetd (daemon + socket),
                      zknet-sdk (socket client, oracles, watch example), rollup (zkrollup), prover (scratch)
```
