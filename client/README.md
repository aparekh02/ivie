# zknet client (Rust)

The rollup's STARK prover and verifier, a light client for the L1 nodes, and
a Unix socket that local programs plug into.

```
                      newline-delimited JSON-RPC 2.0
 your program ─┐      over chain/.run/zknetd.sock          ┌── fast   anvil :9545 (mines on tx)
 nc / python ──┼──►  zknetd  ── alloy HTTP JSON-RPC ───────┤
 watch / ...  ─┘     (native STARK verifier,               └── strict anvil :9546 (12 s slots)
                      head + rollup event follower)
 zkrollup (sequencer + prover) ── signs commitBatch / finalizeBatch on L1
```

| crate | what |
|---|---|
| `zknet-core` | `stark`: field, in-AIR hash, L2 state tree, AIR, prover (honest and adversarial), native verifier matching `StarkVerifier.sol`. `api`: socket wire types. No networking. |
| `zknetd` | Read-only daemon: follows both nodes (heads, `BatchCommitted`, `BatchFinalized`, `BatchesReverted`) and serves the socket. It never signs. |
| `zknet-sdk` | Blocking socket client and the STARK verifier as a raw oracle (`Native` / `Chain`), plus the `watch` example. |
| `rollup` | `zkrollup`: deployer, sequencer, prover and attack harness for `ZKRollup.sol`. Signs with anvil dev key 4, and only for nodes that report as anvil. |
| `prover` | Research scratch file. |
| `quantum` | `qattack`: Grover simulation against the verifier's security floors, proof injection, and parameter extrapolation (see `crates/quantum/README.md`). |

It is not a full node. reth can't follow anvil, because anvil has no p2p
and no engine API. So this is a thin client built on **alloy**, the RPC and
primitives stack reth itself uses, with **arkworks** for field arithmetic
and FFTs.

## Run

```
npm run chain:start:fast                        # :9545
ZKNET_PORT=9546 npm run chain:start             # :9546, strict 12 s slots (optional)
cd contracts && forge build && cd ../client
cargo run --release -p rollup -- deploy
cargo run --release -p zknetd                   # socket at chain/.run/zknetd.sock
```

Then:

```
cargo run --release -p rollup -- run -n 3 -b 4          # commit -> prove -> finalize
cargo run --release -p rollup -- attack                 # lies the contract refuses
cargo run --release -p zknet-sdk --example watch        # live heads + batch events
cargo run --release -p prover [-- chain]                # scratch: native or EVM oracle
cargo test --release                                    # prover/verifier + native-vs-chain differential
```

From any language:

```
echo '{"jsonrpc":"2.0","id":1,"method":"zk_rollup"}' | nc -U chain/.run/zknetd.sock
echo '{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","node":"strict"}' | nc -U chain/.run/zknetd.sock
```

Daemon flags: `--node name=url` (repeatable; the first one is the default),
`--socket`, `--root`, `--poll-ms`. Set `RUST_LOG=zknetd=debug` for
per-request timing.

## Protocol

One JSON object per line in each direction. Every `zk_*` method takes an
optional `"node": "fast" | "strict"`, either in its params or at the top
level of the request.

| method | params | result |
|---|---|---|
| `zk_status` | - | nodes, heads, rollup and verifier addresses |
| `zk_rollup` | - | committed / finalized batch counts, `stateRoot`, `headRoot` |
| `zk_verify` | `{calldata}`: `StarkVerifier.verify(prevRoot, newRoot, txs, proof)` | native verdict, on-chain verdict (with gas), `agree` |
| `zk_subscribe` | `["heads" \| "events" \| "all", {node}?]` | sub id, then `zk_subscription` notifications |
| `eth_* net_* web3_* anvil_* evm_* debug_* trace_* txpool_*` | array | forwarded to the node unchanged |

If `agree` is ever `false`, the native and on-chain verifiers diverge, and
the daemon logs a `WARN`.

## The rollup and its STARK

`contracts/src/stark/ZKRollup.sol` is a validity rollup. The sequencer posts
each batch's transfers as calldata with a claimed post-state root
(`commitBatch`). A batch becomes final only when `StarkVerifier` accepts a
proof that those exact txs move the last finalized root to the claimed one
(`finalizeBatch`, permissionless, in order).

```
zkrollup deploy | run -n 3 -b 4 | attack | status | gen-sol | fixture
```

The AIR (`zknet-core/src/stark/air.rs`) has T = 2048·txs rows and 18 columns:

- Each transfer is two Merkle updates (a debit, then a credit) of a depth-7,
  128-account Poseidon-style tree.
- Each update hashes the old leaf to the old root (lane O) and the new leaf to
  the new root (lane N). The two lanes share siblings and direction bits.
- Constraints:
  - Poseidon rounds.
  - Absorbing by direction bit.
  - Root continuity between updates.
  - `bn = bo ± amt`.
  - A 64-bit range check on every new balance.
  - Path bits must equal the tx's account.
  - Boundary constraints: row 0 equals prevRoot, and the last row equals newRoot.
- The tx data is interpolated over the update-end rows. The proof is therefore
  bound to the calldata the verifier hashed.

Raw oracle over the STARK verifier (`zknet_sdk::stark`):

```rust
use zknet_sdk::stark::{self, Chain, Claim, Native, Options, Oracle, State, Tx};
let mut s = State::genesis();
let c = Claim::from_proven(&stark::prove(&mut s, &txs)?);   // honest
let mut o = Native::default();                               // or Chain::new(Zknet::connect()?)?
o.ask(&c);                                                   // Ok(()) or Err(Pow | Ood | TraceMerkle | FriMerkle{layer} | Fold{layer,q} | LastLayer{q} | ...)
// adversarial prover: edit the trace, claim a false root, fake H(z)
let lie = Options { claim_new_root: Some(other.root()), unchecked: true, fake_ood: true };
stark::prove_with(&mut s, &txs, &lie, |trace| { /* trace[col][row] */ })?;
```

`crates/prover/src/main.rs` is the scratch file built on this
(`cargo run --release -p prover [-- chain]`).
`tests/stark_oracle.rs` checks that the native and on-chain verifiers give the
same reason for 25 tamper and forgery cases. `contracts/test/Stark.t.sol` runs
the Rust-generated fixtures through the contracts.

Where lies get caught (from `zkrollup attack`):

| lie | first failing check |
|---|---|
| same proof, different statement (root, txs, prevRoot) | `Pow`: the statement seeds the Fiat-Shamir channel, so every challenge changes |
| opened trace value changed | `TraceMerkle`: not the committed data |
| re-proved with a false newRoot | `Ood`: H(z) ≠ the constraints at z |
| false newRoot, and H(z) faked to pass the OOD check | `LastLayer`: the DEEP quotient isn't low degree, and FRI catches it |
| extra coin written into the trace | `Ood` |

## Notes

- `zkrollup` fetches nonces per transaction and polls receipts directly.
  Both are needed because `evm_revert` (used by `attack`) rewinds account
  nonces and can recreate identical transaction hashes.
- The socket is mode 0600, so only processes running as your user can use it.
- Contract addresses come from CREATE2 over the compiled artifacts
  (`zknet_core::stark::deploy`). Rebuild contracts and rerun `deploy` after
  changing them; the new code gets new addresses.
