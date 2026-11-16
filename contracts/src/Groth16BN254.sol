// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Groth16 verifier core over BN254 (alt_bn128), using the EIP-196/197
///        precompiles at 0x06 (ecAdd), 0x07 (ecMul), 0x08 (ecPairing).
///
/// Encodings (all big-endian 32-byte words, G2 in EIP-197 order: imaginary
/// part first, i.e. x = x_im*u + x_re is written x_im, x_re):
///
///   raw VK    : alpha1(x,y) | beta2(4) | gamma2(4) | delta2(4) | IC[0..n](x,y)
///   prepared  : same layout with beta2, gamma2, delta2 NEGATED, so the check
///               e(A,B) * e(alpha,-beta) * e(vk_x,-gamma) * e(C,-delta) == 1
///               uses proof points exactly as submitted.
///   proof     : A(x,y) | B(x_im,x_re,y_im,y_re) | C(x,y)   = 256 bytes
///
/// Soundness-relevant checks:
///   * every public input must be < r. ecMul reduces scalars mod r, so
///     accepting x and x + r would make the same proof valid for two input
///     encodings.
///   * proof coordinates go to the precompiles untouched, and the precompiles
///     reject any coordinate >= q, points off the curve, and G2 points outside
///     the order-r subgroup. No proof coordinate is ever reduced mod q here.
///     snarkjs negates A.y with mod(q - y, q), which also accepts A.y + q.
///   * VK validation (prepare) rejects identity points and gamma == delta.
///     With gamma == delta (phase 2 of the setup skipped) anyone can forge.
library Groth16BN254 {
    /// Base field modulus q.
    uint256 internal constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    /// Scalar field modulus r (public inputs live here).
    uint256 internal constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 internal constant PROOF_BYTES = 256;

    /// Gas forwarded to each precompile call: 4x the current mainnet price
    /// (EIP-1108: ecAdd 150, ecMul 6000, pairing 45000 + 34000k). A FAILING
    /// precompile consumes all gas it was given. Forwarding gas() would let an
    /// invalid proof burn the caller's whole tx gas limit. 4x headroom keeps
    /// the verifier live if a future fork reprices these upward.
    uint256 internal constant GAS_ADD = 600;
    uint256 internal constant GAS_MUL = 24000;
    function gasPairing(uint256 k) internal pure returns (uint256) {
        return 4 * (45000 + 34000 * k);
    }
    /// VK size in words: alpha 2 + three G2 points 12 + IC 2(n+1).
    function vkWords(uint256 nPublic) internal pure returns (uint256) {
        return 16 + 2 * nPublic;
    }

    error BadVKLength();
    error BadProofLength();
    error InputCountMismatch(uint256 expected, uint256 got);
    error InvalidVK(string why);
    /// Too little gas to tell an invalid proof from an out-of-gas failure.
    error InsufficientGas();

    /// @notice Verify `proof` against a PREPARED vk. Returns false for any
    ///         invalid proof or input; reverts only on malformed lengths.
    function verify(bytes memory vk, bytes memory proof, uint256[] memory inputs) internal view returns (bool ok) {
        if (proof.length != PROOF_BYTES) revert BadProofLength();
        if (vk.length < 16 * 32 || (vk.length / 32 - 16) % 2 != 0 || vk.length % 32 != 0) revert BadVKLength();
        uint256 n = (vk.length / 32 - 16) / 2;
        if (inputs.length != n) revert InputCountMismatch(n, inputs.length);

        uint256 PAIRING_GAS_4 = gasPairing(4);
        assembly ("memory-safe") {
            // CALL forwards min(cap, gasleft - gasleft/64). When that is below the
            // cap, a failed call may mean out-of-gas, not an invalid input, so
            // revert rather than return a false "invalid proof" verdict.
            // Otherwise a relayer could make a valid proof read as invalid by
            // supplying too little gas.
            function pcall(cap, addr, inPtr, inLen, outPtr, outLen) -> s {
                let short := lt(gas(), add(add(cap, div(cap, 63)), 2000))
                s := staticcall(cap, addr, inPtr, inLen, outPtr, outLen)
                if and(iszero(s), short) {
                    mstore(0x00, 0x1c26714c) // InsufficientGas()
                    revert(0x1c, 0x04)
                }
            }
            let vkp := add(vk, 0x20)
            let pp := add(proof, 0x20)
            let ip := add(inputs, 0x20)
            let f := mload(0x40) // scratch: [0x00..0x40) acc, [0x40..0xa0) mul in, then pairing

            ok := 1
            // vk_x = IC0 + sum(input_i * IC_{i+1})
            let ic := add(vkp, 0x1c0) // 14 words in: after alpha(2) + 3 G2 (12)
            mstore(f, mload(ic))
            mstore(add(f, 0x20), mload(add(ic, 0x20)))
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                let s := mload(add(ip, mul(i, 0x20)))
                if iszero(lt(s, R)) { ok := 0 }
                let pt := add(ic, mul(add(i, 1), 0x40))
                mstore(add(f, 0x40), mload(pt))
                mstore(add(f, 0x60), mload(add(pt, 0x20)))
                mstore(add(f, 0x80), s)
                // ecMul(IC_i, s) -> f[0x40..0x80)
                if iszero(pcall(GAS_MUL, 0x07, add(f, 0x40), 0x60, add(f, 0x40), 0x40)) { ok := 0 }
                // ecAdd(acc, prod) -> acc
                if iszero(pcall(GAS_ADD, 0x06, f, 0x80, f, 0x40)) { ok := 0 }
            }

            if ok {
                let vx := mload(f)
                let vy := mload(add(f, 0x20))
                let p := f
                // pair 1: A, B (from the proof, verbatim)
                mstore(p, mload(pp))
                mstore(add(p, 0x20), mload(add(pp, 0x20)))
                mstore(add(p, 0x40), mload(add(pp, 0x40)))
                mstore(add(p, 0x60), mload(add(pp, 0x60)))
                mstore(add(p, 0x80), mload(add(pp, 0x80)))
                mstore(add(p, 0xa0), mload(add(pp, 0xa0)))
                // pair 2: alpha, -beta
                mstore(add(p, 0xc0), mload(vkp))
                mstore(add(p, 0xe0), mload(add(vkp, 0x20)))
                mstore(add(p, 0x100), mload(add(vkp, 0x40)))
                mstore(add(p, 0x120), mload(add(vkp, 0x60)))
                mstore(add(p, 0x140), mload(add(vkp, 0x80)))
                mstore(add(p, 0x160), mload(add(vkp, 0xa0)))
                // pair 3: vk_x, -gamma
                mstore(add(p, 0x180), vx)
                mstore(add(p, 0x1a0), vy)
                mstore(add(p, 0x1c0), mload(add(vkp, 0xc0)))
                mstore(add(p, 0x1e0), mload(add(vkp, 0xe0)))
                mstore(add(p, 0x200), mload(add(vkp, 0x100)))
                mstore(add(p, 0x220), mload(add(vkp, 0x120)))
                // pair 4: C, -delta
                mstore(add(p, 0x240), mload(add(pp, 0xc0)))
                mstore(add(p, 0x260), mload(add(pp, 0xe0)))
                mstore(add(p, 0x280), mload(add(vkp, 0x140)))
                mstore(add(p, 0x2a0), mload(add(vkp, 0x160)))
                mstore(add(p, 0x2c0), mload(add(vkp, 0x180)))
                mstore(add(p, 0x2e0), mload(add(vkp, 0x1a0)))
                let success := pcall(PAIRING_GAS_4, 0x08, p, 0x300, p, 0x20)
                ok := and(and(success, eq(returndatasize(), 0x20)), eq(mload(p), 1))
            }
        }
    }

    /// @notice Validate a RAW vk and return its prepared form.
    function prepare(bytes memory raw) internal view returns (bytes memory vk) {
        if (raw.length < 16 * 32 || raw.length % 32 != 0 || (raw.length / 32 - 16) % 2 != 0) revert BadVKLength();
        uint256 nIC = (raw.length / 32 - 14) / 2;
        uint256[] memory w = _words(raw);

        if (w[0] == 0 && w[1] == 0) revert InvalidVK("alpha is identity");
        for (uint256 g = 0; g < 3; g++) {
            uint256 o = 2 + 4 * g;
            if (w[o] == 0 && w[o + 1] == 0 && w[o + 2] == 0 && w[o + 3] == 0) revert InvalidVK("G2 point is identity");
        }
        // gamma (words 6..9) == delta (words 10..13) breaks soundness.
        if (w[6] == w[10] && w[7] == w[11] && w[8] == w[12] && w[9] == w[13]) revert InvalidVK("gamma == delta");

        // One pairing call validates every point: G1 points (alpha, IC_i) are
        // paired with the G2 generator, G2 points with the G1 generator. The
        // precompile fails on coordinates >= q, off-curve points and G2 points
        // outside the subgroup. (BN254 G1 has cofactor 1.)
        uint256 pairs = 1 + nIC + 3;
        uint256[] memory buf = new uint256[](pairs * 6);
        uint256 k = 0;
        k = _pairG1(buf, k, w[0], w[1]);
        for (uint256 i = 0; i < nIC; i++) k = _pairG1(buf, k, w[14 + 2 * i], w[15 + 2 * i]);
        for (uint256 g = 0; g < 3; g++) {
            uint256 o = 2 + 4 * g;
            buf[k++] = 1;
            buf[k++] = 2;
            buf[k++] = w[o];
            buf[k++] = w[o + 1];
            buf[k++] = w[o + 2];
            buf[k++] = w[o + 3];
        }
        bool success;
        uint256 g = gasPairing(pairs);
        assembly ("memory-safe") {
            success := staticcall(g, 0x08, add(buf, 0x20), mul(mload(buf), 0x20), 0x00, 0x20)
        }
        if (!success) revert InvalidVK("point not on curve / not in subgroup / non-canonical");

        // Negate beta, gamma, delta: -(x, y) = (x, -y), -y = (q - y_im, q - y_re).
        for (uint256 g = 0; g < 3; g++) {
            uint256 o = 2 + 4 * g;
            w[o + 2] = (Q - w[o + 2]) % Q;
            w[o + 3] = (Q - w[o + 3]) % Q;
        }
        vk = abi.encodePacked(w);
    }

    function _pairG1(uint256[] memory buf, uint256 k, uint256 x, uint256 y) private pure returns (uint256) {
        buf[k++] = x;
        buf[k++] = y;
        // G2 generator, EIP-197 order (x_im, x_re, y_im, y_re)
        buf[k++] = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2;
        buf[k++] = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed;
        buf[k++] = 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b;
        buf[k++] = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa;
        return k;
    }

    function _words(bytes memory b) private pure returns (uint256[] memory w) {
        w = new uint256[](b.length / 32);
        for (uint256 i = 0; i < w.length; i++) {
            uint256 v;
            assembly ("memory-safe") {
                v := mload(add(add(b, 0x20), mul(i, 0x20)))
            }
            w[i] = v;
        }
    }
}
