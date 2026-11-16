// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Groth16 verifier core over BLS12-381, using the EIP-2537 precompiles
///        (live on mainnet since Pectra): 0x0c G1MSM, 0x0f PAIRING_CHECK.
///
/// EIP-2537 encodings: an Fp element is 64 bytes big-endian (top 16 bytes
/// zero, value < p). G1 = x | y (128 B). G2 = x.c0 | x.c1 | y.c0 | y.c1 (256 B,
/// real part first, the opposite of EIP-197). Infinity is all zeros.
///
///   raw VK   : alpha1 128 | beta2 256 | gamma2 256 | delta2 256 | IC[0..n] 128 each
///   prepared : same layout with beta2, gamma2, delta2 negated
///   proof    : A 128 | B 256 | C 128 = 512 bytes
///
/// Checks: public inputs < r (G1MSM accepts any 32-byte scalar, so x and
/// x + r would both pass otherwise). Proof points are forwarded verbatim. The
/// pairing precompile enforces canonical Fp encodings, on-curve and subgroup
/// membership for both G1 and G2. prepare() rejects identity points and
/// gamma == delta.
library Groth16BLS12381 {
    uint256 internal constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;
    // p = P_HI * 2^256 + P_LO
    uint256 internal constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 internal constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    address internal constant G1MSM = address(0x0c);
    address internal constant PAIRING = address(0x0f);

    uint256 internal constant PROOF_BYTES = 512;

    /// Gas caps (4x current EIP-2537 prices; see Groth16BN254 for why).
    /// G1MSM costs k * 12000 * discount(k) / 1000 with discount <= 1000, so
    /// k * 12000 bounds it. Pairing costs 37700 + 32600k.
    function gasMsm(uint256 k) internal pure returns (uint256) {
        return 4 * 12000 * k;
    }
    function gasPairing(uint256 k) internal pure returns (uint256) {
        return 4 * (37700 + 32600 * k);
    }
    uint256 internal constant HEADER_BYTES = 896; // alpha + 3 * G2

    function vkBytes(uint256 nPublic) internal pure returns (uint256) {
        return HEADER_BYTES + 128 * (nPublic + 1);
    }

    error BadVKLength();
    error BadProofLength();
    error InputCountMismatch(uint256 expected, uint256 got);
    error InvalidVK(string why);
    error InsufficientGas();

    function verify(bytes memory vk, bytes memory proof, uint256[] memory inputs) internal view returns (bool ok) {
        if (proof.length != PROOF_BYTES) revert BadProofLength();
        if (vk.length < HEADER_BYTES + 128 || (vk.length - HEADER_BYTES) % 128 != 0) revert BadVKLength();
        uint256 n = (vk.length - HEADER_BYTES) / 128 - 1;
        if (inputs.length != n) revert InputCountMismatch(n, inputs.length);

        uint256 msmGas = gasMsm(n + 1);
        uint256 pairGas = gasPairing(4);
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
            let f := mload(0x40)
            ok := 1

            // MSM input: (IC_0, 1), (IC_1, in_0), ... each 160 bytes
            let ic := add(vkp, 896)
            let k := add(n, 1)
            for { let i := 0 } lt(i, k) { i := add(i, 1) } {
                let dst := add(f, mul(i, 160))
                mcopy(dst, add(ic, mul(i, 128)), 128)
                let s := 1
                if i { s := mload(add(ip, mul(sub(i, 1), 0x20))) }
                if iszero(lt(s, R)) { ok := 0 }
                mstore(add(dst, 128), s)
            }
            // pairing buffer lives after the MSM buffer; vk_x lands in pair 3 directly
            let p := add(f, mul(k, 160))
            if iszero(pcall(msmGas, 0x0c, f, mul(k, 160), add(p, 768), 128)) { ok := 0 }

            if ok {
                mcopy(p, pp, 384) //                         A | B
                mcopy(add(p, 384), vkp, 384) //              alpha | -beta
                mcopy(add(p, 896), add(vkp, 384), 256) //    vk_x (already at p+768) | -gamma
                mcopy(add(p, 1152), add(pp, 384), 128) //    C
                mcopy(add(p, 1280), add(vkp, 640), 256) //   -delta
                let success := pcall(pairGas, 0x0f, p, 1536, p, 0x20)
                ok := and(and(success, eq(returndatasize(), 0x20)), eq(mload(p), 1))
            }
        }
    }

    function prepare(bytes memory raw) internal view returns (bytes memory vk) {
        if (raw.length < HEADER_BYTES + 128 || (raw.length - HEADER_BYTES) % 128 != 0) revert BadVKLength();
        uint256 nIC = (raw.length - HEADER_BYTES) / 128;

        if (_isZero(raw, 0, 128)) revert InvalidVK("alpha is identity");
        for (uint256 g = 0; g < 3; g++) {
            if (_isZero(raw, 128 + 256 * g, 256)) revert InvalidVK("G2 point is identity");
        }
        if (keccak256(_slice(raw, 384, 256)) == keccak256(_slice(raw, 640, 256))) revert InvalidVK("gamma == delta");

        // Single pairing call as a validator: (G1 point, G2 gen) for alpha and
        // each IC, (G1 gen, G2 point) for beta/gamma/delta. The precompile
        // fails on non-canonical, off-curve or out-of-subgroup inputs.
        uint256 pairs = 1 + nIC + 3;
        bytes memory buf = new bytes(pairs * 384);
        uint256 off = 0;
        off = _pairG1(buf, off, raw, 0);
        for (uint256 i = 0; i < nIC; i++) off = _pairG1(buf, off, raw, HEADER_BYTES + 128 * i);
        for (uint256 g = 0; g < 3; g++) {
            _put(buf, off, _g1Gen());
            _copy(buf, off + 128, raw, 128 + 256 * g, 256);
            off += 384;
        }
        (bool success, bytes memory ret) = PAIRING.staticcall{gas: gasPairing(pairs)}(buf);
        if (!success || ret.length != 32) revert InvalidVK("point not on curve / not in subgroup / non-canonical");

        vk = _slice(raw, 0, raw.length);
        // negate y = (y.c0, y.c1) of beta, gamma, delta: y fields at +128 and +192
        for (uint256 g = 0; g < 3; g++) {
            uint256 base = 128 + 256 * g;
            _negFp(vk, base + 128);
            _negFp(vk, base + 192);
        }
    }

    /// In-place p - y for the 64-byte Fp element at byte offset `o` (0 stays 0).
    function _negFp(bytes memory b, uint256 o) private pure {
        uint256 hi;
        uint256 lo;
        assembly ("memory-safe") {
            hi := mload(add(add(b, 0x20), o))
            lo := mload(add(add(b, 0x20), add(o, 32)))
        }
        if (hi == 0 && lo == 0) return;
        uint256 borrow = lo > P_LO ? 1 : 0;
        uint256 nlo;
        unchecked {
            nlo = P_LO - lo;
        }
        uint256 nhi = P_HI - hi - borrow; // checked: reverts if y >= p
        assembly ("memory-safe") {
            mstore(add(add(b, 0x20), o), nhi)
            mstore(add(add(b, 0x20), add(o, 32)), nlo)
        }
    }

    function _pairG1(bytes memory buf, uint256 off, bytes memory raw, uint256 src) private pure returns (uint256) {
        _copy(buf, off, raw, src, 128);
        _put(buf, off + 128, _g2Gen());
        return off + 384;
    }

    function _g1Gen() private pure returns (bytes memory) {
        return abi.encodePacked(
            uint256(0x17f1d3a73197d7942695638c4fa9ac0f), uint256(0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb),
            uint256(0x08b3f481e3aaa0f1a09e30ed741d8ae4), uint256(0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1)
        );
    }

    function _g2Gen() private pure returns (bytes memory) {
        return abi.encodePacked(
            uint256(0x024aa2b2f08f0a91260805272dc51051), uint256(0xc6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8),
            uint256(0x13e02b6052719f607dacd3a088274f65), uint256(0x596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e),
            uint256(0x0ce5d527727d6e118cc9cdc6da2e351a), uint256(0xadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801),
            uint256(0x0606c4a02ea734cc32acd2b02bc28b99), uint256(0xcb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be)
        );
    }

    function _isZero(bytes memory b, uint256 o, uint256 len) private pure returns (bool z) {
        z = true;
        for (uint256 i = 0; i < len; i += 32) {
            uint256 v;
            assembly ("memory-safe") {
                v := mload(add(add(b, 0x20), add(o, i)))
            }
            if (v != 0) return false;
        }
    }

    function _slice(bytes memory b, uint256 o, uint256 len) private pure returns (bytes memory out) {
        out = new bytes(len);
        assembly ("memory-safe") {
            mcopy(add(out, 0x20), add(add(b, 0x20), o), len)
        }
    }

    function _copy(bytes memory dst, uint256 dOff, bytes memory src, uint256 sOff, uint256 len) private pure {
        assembly ("memory-safe") {
            mcopy(add(add(dst, 0x20), dOff), add(add(src, 0x20), sOff), len)
        }
    }

    function _put(bytes memory dst, uint256 dOff, bytes memory src) private pure {
        _copy(dst, dOff, src, 0, src.length);
    }
}
