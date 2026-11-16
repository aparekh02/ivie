# Attack systems and findings

How the zknet Groth16 verifier was attacked, and what those attacks found.
Everything runs locally: Foundry tests, plus signed transactions on a local
anvil zknet. Nothing was run against a public network.

## 1. Attack systems

| # | System | Where | What it does |
|---|--------|-------|--------------|
| A | Mutation catalogue | `tools/zk.mjs` (`mutations`) | Generates up to 18 crafted bad proofs and inputs from each valid proof |
| B | Independent reference verifier | `tools/zk.mjs` (`referenceVerify`) | A noble-curves pairing check that follows the precompile rules, used to judge every case |
| C | Fixture-wide acceptance test | `Registry.t.sol::test_allFixtures` | Runs every valid and mutated case against the on-chain verifier |
| D | Fuzzers (512 runs by default, 20,000 with `--profile deep`) | `Registry.t.sol::testFuzz_*` | Random proofs, perturbed inputs, bit flips, and gas starvation |
| E | Forgery demo | `test_gammaEqualsDeltaIsForgeable_libraryLevel` | Forges a proof against a VK whose trusted setup skipped phase 2 |
| F | Malformed VK attacks | `test_register_rejectsMalformedVks`, `test_rejectsVkWithoutPhase2` | Wrong lengths, identity points, off-curve points, γ == δ |
| G | Differential test against snarkjs | `SnarkjsDifferential.t.sol` | Runs every vector through snarkjs's generated Solidity verifier and through ours, then compares verdicts and gas |
| H | Live-chain attacks | `e2e/run.mjs` | Sends real attack transactions on zknet and checks the decoded revert reason and gas used |
| I | Live differential test | `e2e/run.mjs` | Compares the result of each `eth_call` to `verify` with the reference verifier, for every vector |

### A. Mutation catalogue (per valid proof)

**Statement attacks**
- `input[0] + 1`: a different public input.
- `input[0] + r`: a non-canonical scalar that aliases the same field element.
- `input[last] = 0`.
- Inputs swapped.
- A valid proof for a different statement.

**Encoding attacks**
- `A.y + p`: a non-canonical coordinate.
- `C.x + p`.
- `B.x.c0 + p`.
- B's Fp2 limbs swapped (the wrong G2 order for the precompile).
- A wrap-malleable encoding of `A.y`, BN254 only: `((y + 2^256) mod q) + q`.

**Algebraic attacks**
- A negated.
- A and C swapped.
- A off curve.
- B off curve.
- A on the curve but outside the r-subgroup.
- B on the twist but outside the r-subgroup.
- An all-identity proof.
- C = identity.

**Malleability control (must still be accepted)**
- A re-randomized proof `(A/s, sB, C)`. It is valid, and it is the reason replay protection cannot be keyed on proof bytes.

### D. Fuzzers
- `testFuzz_randomProofNeverVerifies_bn254` / `_bls`: random proof bytes are never accepted.
- `testFuzz_perturbedInputRejected`: any changed input, including `input + r`, is rejected.
- `testFuzz_bitFlipRejected`: any single bit flip in the proof is rejected.
- `testFuzz_validProofNeverFalseUnderGasStarvation`: for any gas budget, a valid proof either returns true or reverts. It never returns false.

### H. Live-chain attacks (latest run)

| Attack transaction | Gas limit | Result | Gas used |
|---|---|---|---|
| `submit` an off-curve proof | 2^24 (the EIP-7825 maximum) | revert `InvalidProof` | 783,058 |
| `submit` a re-randomized proof of a statement that is already consumed | 1M | revert `AlreadyConsumed` | 242,594 |
| `submit` the snarkjs wrap-malleable `A.y` encoding | 2M | revert `InvalidProof` | 783,058 |
| `register` a VK with no phase-2 contribution (γ == δ) | 3M | revert `InvalidVK` | 51,390 |

Each attack passes only if it reverts **for the expected reason**. The reason is decoded from an `eth_call` replay of the same transaction, so a revert for an unrelated reason (for example `UnknownCircuit`) counts as a failure.

### Totals
- Fixtures: 76 valid proofs accepted, 241 invalid proofs rejected, on both BN254 and BLS12-381.
- Live differential: 317/317 agree in fast mode and 107/107 in `--quick` mode with 12 s blocks.
- All 22 Forge tests pass, and all 5 fuzzers pass at 20,000 runs.

## 2. Issues found

### In my own verifier (all fixed)

| # | Severity | Issue | Found by | Fix |
|---|----------|-------|----------|-----|
| 1 | **High** | **Gas-starvation griefing.** With too little gas the precompile call failed and `verify` returned `false` for a *valid* proof. A relayer could pick a gas limit that makes a contract record a good proof as bad. `eth_estimateGas` reported about 54k, which shows the false path was reachable. | Fuzzer D (gas starvation) | The `pcall` helper reverts with `InsufficientGas` when a call fails while it had less than its cap. The fuzzer fails without the fix and passes with it. |
| 2 | **Medium** | **Unbounded gas burn.** A failing precompile consumes all gas forwarded to it, so one invalid proof could burn the whole block's worth of gas. | Fuzzer D (runs used about 1e9 gas) | Each precompile call is capped at 4x its mainnet price. An invalid proof now burns at most about 0.78M gas, even with a 2^24 gas limit (attack H1). |
| 3 | **Medium** | **SSTORE2 initcode offset bug.** The offset was `0x0c`, but the header is 10 bytes, so stored VKs were corrupted. | Fixture test C | The offset is now `0x0a`, plus an EIP-170 size check. |
| 4 | Low | **VK minimum length check off by 2 words** (18 instead of 16), so circuits with 0 public inputs were rejected. | Simulated n=0 fixtures | The minimum is now `16 + 2n` words. |
| 5 | Low | **Replay protection keyed on proof bytes would be bypassable.** Groth16 proofs can be re-randomized into different valid bytes. | Re-randomization control case | Replay protection is keyed on `keccak256(inputs)` (attack H2). |

### In snarkjs's generated Solidity verifier (third-party, not fixed upstream)

| # | Severity | Issue | Evidence |
|---|----------|-------|----------|
| 6 | **Medium** | **Proof malleability.** snarkjs accepts `A.y' = ((y + 2^256) mod q) + q` as a second encoding of the same proof, because its arithmetic wraps mod 2^256. The simpler `y + q` is rejected. Contracts that use proof bytes as a nullifier can be replayed. | `SnarkjsDifferential.t.sol` asserts this is the **only** case where snarkjs and our verifier disagree. Attack H3 shows ours rejects it. |
| 7 | **Medium** | **Unbounded gas on invalid proofs.** One malformed proof uses **16,518,195 gas** in snarkjs's verifier, versus 742,489 in ours. | `test_invalidProofGasIsBounded` |
| 8 | **High (setup)** | **A VK exported without a phase-2 contribution is forgeable.** It has γ == δ, and anyone can then build a passing proof with `A = α, B = β, C = −vk_x`. snarkjs will export such a key and generate a verifier for it. | Forgery demo E succeeds at the library level. `register` and `gen-verifier.mjs` both refuse γ == δ (attack H4). |

### Chain-fidelity issues found along the way (not security)

| Issue | Fix |
|---|---|
| Anvil's built-in EIP-7251 (consolidation) bytecode differs from mainnet's | Mainnet's bytecode is installed at boot |
| The snapshot's storage overwrote the deposit contract's zero-hash marker, which gave a wrong `deposit_root` | Renamed the marker to `storageRule` |
| ERC-4337 EntryPoints copied from mainnet have a broken `SenderCreator` immutable | Removed from the predeploys |
| Coinbase, prevrandao and fee history were wrong at genesis | Boot 64 blocks early and mine them in a warm-up |
| The base fee decayed after warm-up | Pinned with `anvil_setNextBlockBaseFeePerGas` |
| **Known gaps (anvil limits):** the blob schedule is 6/9 (mainnet runs 14/21), and beacon roots are zero | Reported as `GAP` by `npm run fidelity` |

### Test-harness bugs found (false passes)
- In quick mode the e2e attacks reverted with `UnknownCircuit` at 37k gas and were counted as blocked. The run now checks the expected revert reason and keeps the targeted circuit in quick mode.
- A first claim that snarkjs accepts `A.y + q` was wrong. The real malleable encoding (#6) was found by exporting snarkjs's actual verifiers and comparing against them.

## 3. Reproduce

```
npm run test:contracts      # A–G (Forge, 512 fuzz runs)
npm run test:deep           # fuzzers at 20,000 runs
npm run chain:start:fast && npm run e2e   # H, I on a live zknet
npm run fidelity            # chain-fidelity checks
```
