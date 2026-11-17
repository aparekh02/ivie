# quantum: algebraic attack lab for the in-AIR Poseidon hash

The hash that commits the STARK state tree (`zknet_core::stark::hash` — a
width-3, x³-S-box Poseidon over `F_p`, `p = 2^251 + 17·2^192 + 1`) is
*arithmetization-friendly*, i.e. low algebraic degree per round. That is exactly
the surface a structured quantum/algebraic attack targets. This crate builds the
attack, recovers **verified** reduced-round preimages, and measures the round
count at which it becomes infeasible.

```
cargo run --release -p quantum                 # full lab + margin curve + viz JSON
cargo run --release -p quantum -- preimage 5   # elimination preimage attack at R rounds
cargo run --release -p quantum -- xl 2         # XL/Macaulay solving degree at R rounds
cargo run --release -p quantum -- qaoa         # QAOA statevector preimage amplification
cargo run --release -p quantum -- forge        # second preimage -> tamperable leaf
cargo run --release -p quantum -- margin       # degree-vs-rounds security margin
cargo run --release -p quantum -- floors       # Grover baseline on the keccak floors
cargo run --release -p quantum -- emit viz/viz.json   # visual-memory data
```

## The attack (break the hash with math, not search)

For the single-input leaf domain the iterated round system has one true unknown
`b`. The attack runs in two equivalent views:

1. **Elimination** (`groebner`, `poseidon`). Compose the `r` rounds symbolically
   over `F_p[b]`; the interior states cancel and leave one univariate
   `f(b) = leaf_r(b) − target` of degree `3^r`. This *is* the Gröbner basis of
   the preimage ideal under an elimination order. Its `F_p`-roots are found
   classically: `g = gcd(f, x^p − x)` keeps the base-field roots, then
   Cantor–Zassenhaus splits out a preimage `b*`. It is checked against the real
   round map — so the break is genuine, not a re-implementation.

2. **Linearization** (`xl`). Keep the interior round states as variables; the
   preimage is a system of degree-3 equations. XL / Macaulay builds the Macaulay
   matrix at increasing degree `D` and row-reduces over `F_p`; at the **solving
   degree** `D*` the elimination relation in `b` appears and is root-found. `D*`
   is the Gröbner-family security metric — the number a round count exists to
   blow up. Measured: `D* = 9` at `R = 2` (840×715 matrix).

`attack::forge_leaf` extends this to a **second preimage** `b' ≠ b` with
`leaf(b') = leaf(b)`: the opened wallet value changes while the leaf hash, path
and committed root do not, so the verifier's commit-before-challenge check
passes on a false state. Found at `R = 3` and `R = 5` on the testbed.

## QAOA (`qaoa`)

A full exact statevector QAOA run (no `sqrt(N)` formula) over an `n`-qubit window
of candidate inputs, with a diagonal cost `C(x) = Hamming(low_bits(leaf_r(x)),
low_bits(target))`. The graded landscape — a near-miss scores low, unlike a flat
Grover oracle — gives the phase/mixer layers real structure to amplify. Measured:
`7.8×` amplification of the preimage over the uniform baseline at `n = 12`,
`p = 2`. On a structureless hash this degenerates to Grover; the lift here is the
algebraic structure leaking into the cost surface.

## The margin (`attack::margin`, `margin` subcommand)

The elimination polynomial has degree `3^r`, so `log2` degree grows `1.585`
bits/round. The attack is feasible only while that polynomial can be built and
root-found. The curve:

- degree crosses `2^64` at `r = 41`, `2^96` at `r = 61`, the Grover preimage
  line (`2^125.5`) at `r = 80`;
- at the real `ROUNDS = 127`, degree is `3^127 ≈ 2^201` — unbuildable, leaving
  only a `~2^125` Grover preimage search. The round count is the whole margin,
  and it is sized correctly.

Measured runtimes (naïve `O(d²)` multiply): 5-round preimage in `0.7 s`,
7-round in `35 s`. FFT multiplication would push the feasible `r` higher without
moving the wall.

## The visual-memory system (`viz/`)

`viz/index.html` is a self-contained page (open in a browser, or publish as an
artifact) rendering the attack pipeline, the degree-vs-rounds wall, the XL
solving-degree table, and the QAOA distribution from `viz/viz.json` (regenerate
with the `emit` subcommand).

## Honest scope

- Every preimage is recovered from a *committed target alone* and verified
  against `zknet_core::stark::hash`. The breaks are real at reduced rounds.
- At full rounds the attack does **not** break the hash; the deliverable is the
  margin, not a usable exploit.
- Keccak-256 (Merkle / Fiat-Shamir) has no algebraic shortcut — it stays
  Grover-only (`2^80` / `2^48`). **Shor is inert**: nothing here has a hidden
  subgroup to recover.
