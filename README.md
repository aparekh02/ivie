# zknet: a mainnet-fidelity testnet and a hardened Groth16 verifier

Two parts:

1. **zknet**: an anvil node configured to behave like Ethereum mainnet as of
   November 2026 (Osaka rules, chain id 1, mainnet gas limit / base fee /
   height, 12 s beacon-aligned slots, mainnet system contracts and singletons).
   It is checked by a 55-probe fidelity suite.
2. **The verifier**: Groth16 on **BN254** (EIP-196/197) and **BLS12-381**
   (EIP-2537), as a content-addressed on-chain registry plus generated
   standalone contracts. It is tested against real circom/snarkjs proofs, a
   trapdoor simulator, an independent JS reference verifier, and snarkjs's own
   Solidity verifier.

The prover comes later. `tools/submit.mjs` is the integration point: any prover
that emits snarkjs-format `proof.json` + `public.json` plugs in unchanged.

```
npm install
npm run chain:start:fast        # or chain:start for strict 12 s slots
npm run test:contracts          # 22 Foundry tests (fuzz included)
npm run fidelity                # 55 chain probes vs mainnet
npm run e2e                     # live-chain differential + attacks, real txs
node tools/submit.mjs --vk vk.json --proof proof.json --public public.json --tx --register
```

Requires foundry (anvil/forge/cast >= 1.8), node >= 22, and circom 2.2 only
to rebuild circuits.

---

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

---

## 2. The verifier (`contracts/src/`)

| File | What |
|---|---|
| `Groth16BN254.sol` | library: `prepare(rawVk)` validates + pre-negates a VK; `verify(vk, proof, inputs)` |
| `Groth16BLS12381.sol` | same over EIP-2537 (64-byte Fp, real-first G2, G1MSM for the input combination) |
| `ZKVerifierRegistry.sol` | permissionless, content-addressed VKs (`id = keccak256(abi.encode(curve, rawVk))`), stored as code (SSTORE2), `verify` (view) and `submit` (records the statement, blocks replay) |
| `generated/*.sol` | standalone per-circuit verifiers from `tools/gen-verifier.mjs` (VK baked in as a constant, snarkjs-ABI drop-in for BN254) |

### Encodings

```
BN254  proof (256 B):  A.x A.y | B.x_im B.x_re B.y_im B.y_re | C.x C.y      (EIP-197 order)
       vk:             alpha | beta | gamma | delta | IC[0..n]              (32-byte words)
BLS    proof (512 B):  A (128) | B = x.c0 x.c1 y.c0 y.c1 (256) | C (128)     (EIP-2537, 64-byte Fp)
       vk:             alpha 128 | beta 256 | gamma 256 | delta 256 | IC[0..n] 128 each
```

The BN254 proof bytes are exactly snarkjs's `verifyProof(a, b, c, pub)`
calldata words, so `tools/zk.mjs` converts snarkjs JSON to either layout.

### What it guarantees, and the test that proves each

| Property | Why it matters | Test |
|---|---|---|
| Every valid proof verifies (circom+snarkjs, both curves; simulated with 0 to 16 inputs; inputs 0 and r-1) | correctness | `test_allFixtures` (76 valid) |
| Every adversarial variant returns `false` without reverting | soundness at the encoding layer | `test_allFixtures` (241 invalid) |
| Public inputs must be `< r` (x and x+r both pass ecMul/MSM otherwise) | input malleability | vectors + `testFuzz_perturbedInputRejected` |
| Proof coordinates are never reduced mod q. The precompiles see them verbatim and reject anything ≥ q, off-curve, or outside the subgroup (G2 twist points, BLS G1 cofactor points) | proof-encoding malleability | vectors, `testFuzz_bitFlipRejected`, `testFuzz_randomProofNeverVerifies_*` |
| VKs with γ == δ are refused (any zkey exported **before a phase-2 contribution**). Under such a VK anyone can forge, which is demonstrated | real deployed-bug class | `test_rejectsVkWithoutPhase2`, `test_gammaEqualsDeltaIsForgeable_libraryLevel` |
| VKs with identity / off-curve / non-canonical / out-of-subgroup points are refused, all with one pairing-precompile call | registry hygiene | `test_register_rejectsMalformedVks` |
| **Bounded gas burn.** Each precompile call gets at most 4x its mainnet price. A failing precompile eats all forwarded gas, so an invalid proof costs ~0.78M gas instead of the whole tx limit | griefing / UX | `test_invalidProofGasIsBounded`, e2e attack with a 2^24 limit |
| **Never a false "invalid" under gas starvation.** If a precompile call fails while it had less than its cap, `verify` reverts `InsufficientGas` instead of returning false. Otherwise a relayer could make valid proofs look invalid by under-supplying gas | consumers that act on `false` | `testFuzz_validProofNeverFalseUnderGasStarvation` (fails without the fix) |
| Replay protection keyed on **public inputs**, not proof bytes. Groth16 proofs re-randomize: `(A/s, sB, C)` is a different valid proof | dedupe on proof hash is broken | `test_submit_recordsAndBlocksReplay_evenReRandomized` |
| On-chain circuit id == JS id; JS-prepared VK == Solidity-prepared VK byte for byte | prover can compute ids off-chain | `test_allFixtures`, `GeneratedTest` |

### Findings vs the snarkjs-generated verifier (what most circom projects deploy)

`SnarkjsDifferential.t.sol` runs every vector through both verifiers:

1. **Encoding malleability.** snarkjs negates A as `mod(sub(q, A.y), q)` in
   256-bit arithmetic. `A.y + q` happens to be rejected, but
   `A.y' = ((A.y + 2^256) mod q) + q` wraps to exactly `q − A.y` and is
   **accepted**. That gives a second byte string for the same proof. Ours
   rejects it. This is the only disagreement across all vectors, and the test
   asserts that.
2. **Unbounded burn.** An off-curve proof costs **16.5M gas** through snarkjs's
   verifier (it forwards `gas()` to the precompiles). Ours costs **0.74M**.

### Gas (Osaka pricing, measured)

| | BN254 | BLS12-381 |
|---|---|---|
| verify, 1 public input (registry) | ~204k | ~211k |
| verify, 1 public input (standalone generated) | ~194k | n/a |
| verify, 9 public inputs (registry) | ~253k | ~269k |
| verify, 16 public inputs (registry) | ~300k | ~323k |
| `submit` tx, 1 input, incl. 21k intrinsic + storage + event | ~251k | ~257k |
| per extra public input | ~6.7k (ecMul + ecAdd) | ~7-11k (MSM, discounted) |

At the snapshot base fee (~0.15 gwei), a `submit` costs about 0.00026 ETH.

---

## 3. Test vectors (`circuits/`, `tools/`)

- `circuits/build.mjs` builds three circom circuits (`multiplier`,
  `sum_of_squares` with 9 public signals, and a Semaphore-style Poseidon
  `nullifier`) on **both curves** (nullifier is BN254 only, since circomlib
  Poseidon constants are BN254's). It runs a real phase-1 + phase-2 setup,
  proves with snarkjs, cross-checks with `snarkjs.groth16.verify` **and** the
  JS reference, and writes fixtures plus the snarkjs Solidity baseline and
  generated verifiers. The ceremony entropy is deterministic and public. **It is
  for testing only.**
- `tools/zk.mjs`:
  - encoders/decoders
  - `circuitId`
  - `referenceVerify`: an independent noble-curves implementation of the same
    rules
  - `simulate`: knows the toxic waste, so it can produce valid proofs for any
    statement, which lets the verifier be fuzzed without a circuit
  - `mutations`: an 18-case adversarial catalogue. Every generated vector's
    expected verdict is checked against the reference before it is written.
- `tools/gen-vectors.mjs`: simulated sets for n ∈ {0, 1, 2, 5, 16} on both
  curves.
- `tools/gen-verifier.mjs vk.json Name out.sol`: standalone verifier. It
  refuses γ == δ.

## 4. Live-chain end-to-end (`e2e/run.mjs`)

Signed raw transactions only (viem), no anvil cheats:

1. Deploys the registry via the canonical CREATE2 deployer (salt
   `zknet.registry.v1`, no CBOR metadata, so the address depends only on the
   code).
2. Registers every fixture and asserts the `CircuitRegistered` id equals the
   JS id.
3. Runs **every** vector through `eth_call verify` and the JS reference, and
   requires full agreement (317/317).
4. Sends `submit` txs and decodes `ProofVerified`.
5. Sends attack txs that must revert: an off-curve proof with a 2^24 gas limit
   (asserts gasUsed < 1M), a re-randomized replay, snarkjs's wrap-malleable
   encoding, and the no-phase-2 VK.
6. Writes `e2e/reports/<ts>.json`.

## 5. Plugging in a prover later

Emit snarkjs-format JSON (snarkjs, rapidsnark, or gnark/arkworks with a JSON
exporter), on curve `bn128` or `bls12381`:

```
node tools/submit.mjs --vk verification_key.json --proof proof.json --public public.json --register --tx
```

It prints the reference verdict, the on-chain verdict, and the `submit`
receipt. For your own circuits, add them to `CIRCUITS` in `circuits/build.mjs`
and every test picks them up automatically.

Before trusting a circuit id from a third party, check it yourself:
registration is permissionless, and a VK proves nothing about which circuit
it came from.

## Layout

```
chain/      zknet.mjs (launcher), snapshot.mjs, mainnet-snapshot.json, fidelity.mjs, wallet.mjs, rpc.mjs
contracts/  src/ (libraries, registry, generated/), test/ (Registry, SnarkjsDifferential, Generated, vectors/, snarkjs/)
circuits/   src/*.circom, build.mjs
tools/      zk.mjs, gen-vectors.mjs, gen-verifier.mjs, submit.mjs
e2e/        run.mjs
```
