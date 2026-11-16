# zknet client (Rust)

A light client for zknet, and a Unix socket that local programs (your prover)
plug into.

```
                      newline-delimited JSON-RPC 2.0
 your prover ──┐      over chain/.run/zknetd.sock          ┌── fast   anvil :9545 (mines on tx)
 nc / python ──┼──►  zknetd  ── alloy HTTP JSON-RPC ───────┤
 watch / ...  ─┘     (native verifier, signer,             └── strict anvil :9546 (12 s slots)
                      head + event follower)
```

| crate | what |
|---|---|
| `zknet-core` | snarkjs JSON into on-chain bytes, circuit ids, and a **native Groth16 verifier** (arkworks) that follows the Solidity rules exactly. It is tested against all 317 vectors in `contracts/test/vectors`. No networking. |
| `zknetd` | The daemon. It follows both nodes (heads, `CircuitRegistered`, `ProofVerified`), deploys the registry via CREATE2 if missing, signs with an anvil dev key, and serves the socket. |
| `zknet-sdk` | Blocking Rust client for the socket (no async runtime needed), plus examples. |

It is not a full node. reth cannot follow anvil, because anvil has no p2p
and no engine API. So this is a thin client built on **alloy**, the RPC and
primitives stack reth itself uses. It also uses **arkworks** for the curve math.

## Run

```
npm run chain:start:fast                        # :9545
ZKNET_PORT=9546 npm run chain:start             # :9546, strict 12 s slots (optional)
cd client && cargo run --release -p zknetd      # socket at chain/.run/zknetd.sock
```

Then, in another terminal:

```
cargo run --release -p zknet-sdk --example playground          # real + tampered proofs, native vs chain
cargo run --release -p zknet-sdk --example playground -- --curve bls12381 --node strict
cargo run --release -p zknet-sdk --example ark_prover          # arkworks prover -> register -> verify -> submit
cargo run --release -p zknet-sdk --example watch               # live heads + registry events
cargo test  --release -p zknet-core                            # native verifier vs all 317 vectors
```

From any language:

```
echo '{"jsonrpc":"2.0","id":1,"method":"zk_status"}' | nc -U chain/.run/zknetd.sock
echo '{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","node":"strict"}' | nc -U chain/.run/zknetd.sock
```

Daemon flags: `--node name=url` (repeatable; the first one is the default),
`--socket`, `--key-index` (default 3, so its nonces never collide with
`e2e/run.mjs` or `submit.mjs`, which use key 0), `--no-deploy`, `--poll-ms`.
Set `RUST_LOG=zknetd=debug` for per-request timing.

## Protocol

One JSON object per line in each direction. Every `zk_*` method takes an
optional `"node": "fast" | "strict"` in its params. For forwarded methods,
put `"node"` at the top level of the request.

| method | params | result |
|---|---|---|
| `zk_status` | - | nodes, heads, registry, signer |
| `zk_circuitId` | `{vk}` or `{rawVk, curve}` | id, raw VK, nPublic, `vkProblem` (would `register` refuse it?) |
| `zk_encode` | `{proof, curve}` | on-chain proof bytes |
| `zk_verifyLocal` | VerifyParams | native verdict only |
| `zk_verify` | VerifyParams | native verdict, `eth_call verify` verdict, gas, `agree` |
| `zk_submit` | VerifyParams | simulated first (not sent if it reverts, unless `force`), then a signed tx |
| `zk_register` | `{vk \| rawVk+curve, label, force}` | id, tx, or the revert reason |
| `zk_circuit` | `{circuitId}` | registration and raw VK (recovered from the stored prepared VK) |
| `zk_subscribe` | `["heads" \| "events" \| "all", {node}?]` | sub id, then `zk_subscription` notifications |
| `eth_* net_* web3_* anvil_* evm_* debug_* trace_* txpool_*` | array | forwarded to the node unchanged |

VerifyParams: `{ vk | rawVk+curve | circuitId, proof: <snarkjs JSON or 0x bytes>,
publicSignals | inputs: [decimal or 0x strings], register?, force?, gas?, node? }`.
Inputs are strings on purpose, so you can send values `>= r` and watch them
get rejected.

A verdict looks like this:

```json
{"circuitId":"0x15fa…","curve":"bn254","local":{"ok":false,"reason":"proof.A: not on curve","reverts":false,"micros":2100},
 "onchain":{"ok":false,"gas":781372,"block":26429604},"agree":true}
```

If `agree` is ever `false`, either the native or the on-chain verifier has a
bug. The daemon logs a `WARN` when it happens.

## Plugging in a Rust prover

Add the SDK as a path dependency:

```toml
[dependencies]
zknet-sdk = { path = "../ivie/client/crates/zknet-sdk" }
```

```rust
use zknet_sdk::{Zknet, Req, core::{Curve, U256, verify::bn254}};

let raw_vk = bn254::vk_bytes(&vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2, &vk.gamma_abc_g1);
let proof  = bn254::proof_bytes(&p.a, &p.b, &p.c);           // ark-groth16 Proof<Bn254>
let mut zk = Zknet::connect()?;                               // or .on("strict")
zk.register_raw(Curve::Bn254, &raw_vk, "my circuit")?;
let v = zk.verify(Req::raw(Curve::Bn254, &raw_vk, &proof, &[U256::from(33)]))?;
let snap = zk.snapshot()?;                                    // try a submit, then roll back
zk.submit(Req::raw(Curve::Bn254, &raw_vk, &proof, &[U256::from(33)]))?;
zk.revert(&snap)?;
```

`zknet_core::verify(curve, raw_vk, proof, inputs)` is the same check with no
daemon. It takes about 2 ms, so you can run it in a test loop or a fuzzer.

## Recommendations for building the prover

1. **Start from `ark-groth16`, then replace it piece by piece.** Its
   equation, VK layout (`gamma_abc_g1` is the registry's `IC`) and point
   types match this verifier exactly (see `examples/ark_prover.rs`). Write
   your own prover in stages: witness → R1CS → QAP (`ark-poly`
   `Radix2EvaluationDomain` for the iFFT/FFT and the coset division by Z) →
   the three MSMs for A, B and C. Keep `ark-ff`/`ark-ec` for field and curve
   arithmetic at first. Check each stage against ark-groth16 **with the same
   r and s blinding values**: the proofs should be byte-identical, which is a
   much sharper check than "it verifies."
2. **Test in three layers.** First `zknet_core::verify` (fast, no chain), then
   `zk_verify` (native vs EVM, plus gas), then `zk_submit` inside
   `evm_snapshot`/`evm_revert`. Use `fast` for iteration and `strict` when
   timing or the 12 s slot behavior matters.
3. **Reuse the circom circuits for cross-checks.** `circuits/build/*/` holds
   real snarkjs proofs and zkeys. A Rust prover that reads the `.r1cs` and the
   zkey (via `ark-circom` or your own parser) and proves `multiplier` should
   produce proofs that verify under the **already registered** circuit id.
   That tests your QAP against an independent implementation.
4. **Setup hygiene.** gamma and delta must be independent. The registry
   refuses gamma == delta, because under such a VK anyone can forge. A seeded
   RNG is fine for tests, but treat the seed as toxic waste.
5. **Public inputs.** Reduce them mod r yourself, because the verifier
   rejects values `>= r` instead of reducing them. Replay protection is
   keyed on the inputs, not the proof (proofs re-randomize). If a statement
   should be submittable more than once, or exactly once per user, put a
   nonce or nullifier in the public inputs.
6. **Keep the public-input count small.** Gas is about 228k for 1 input,
   plus about 6.7k per extra input on BN254. Hashing many values into one
   input trades gas for constraints.
7. **Fuzz the boundary.** Run `proptest` over proof-byte mutations with
   `zk_verify` in the loop, and require `agree == true` every time.
   `tools/zk.mjs mutations()` lists the attack cases already covered.
8. **Performance.** Enable `ark-ec`/`ark-ff`'s `parallel` feature for
   multithreaded MSM and FFT, always build `--release` (the workspace already
   sets opt-level 3 for dependencies), and time the MSM and FFT stages
   separately. MSM usually dominates.
9. **BLS12-381 works the same way** (`verify::bls12381::*`, 512-byte
   proofs). Note that circomlib's Poseidon constants are BN254-only.

## Notes

- Transactions are signed only for nodes that answer `anvil_nodeInfo`.
  zknet uses chain id 1, so this guard keeps a mistyped `--node` from ever
  signing for mainnet.
- Nonces are fetched per transaction and receipts are polled directly. Both
  are needed because `evm_revert` rewinds account nonces and can recreate
  identical transaction hashes.
- The socket is mode 0600. Any local process running as your user can use
  it and sign with the dev key, and nothing else can.
