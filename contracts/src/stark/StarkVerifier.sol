// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {RollupConstants as K, RollupPeriodic} from "./generated/RollupPeriodic.sol";

/// @title StarkVerifier: checks a STARK proof that a batch of L2 transfers
///        moves the rollup's state root from `prevRoot` to `newRoot`.
///
/// Modeled part by part on StarkWare's L1 verifier (starkex-contracts
/// `evm-verifier`) and the Stone prover:
///   field      p = 2^251 + 17·2^192 + 1, as in Starknet
///   channel    VerifierChannel: digest' = keccak(digest + 1 ‖ data), randomness
///              keccak(digest ‖ counter), rejection sampling below 31·p, PoW with
///              the 0x0123456789abcded prefix
///   Merkle     keccak truncated to 160 bits, batched multi-proof decommitments
///   LDE        blowup 16, evaluations committed in bit-reversed order
///   FRI        layer 0 = DEEP composition (friStepSizes[0] = 0), then fold by 8
///              per layer with one coset per Merkle leaf; last layer as coefficients
///   security   18 queries · log2(16) + 24 PoW bits ≈ 96 bits (conjectured)
/// The AIR (rollup state transition) is fixed in this contract. The off-chain
/// twin is `client/crates/zknet-core/src/stark/verifier.rs`: the same checks
/// in the same order, so both revert with the same error.
contract StarkVerifier {
    uint256 internal constant P = 0x0800000000000011000000000000000000000000000000000000000000000001;
    uint256 internal constant BOUND = 31 * P; // largest multiple of p below 2^256
    uint256 internal constant HALF = (P + 1) / 2;
    bytes32 internal constant MASK160 = 0xffffffffffffffffffffffffffffffffffffffff000000000000000000000000;
    uint256 internal constant W = 18;
    uint256 internal constant SEG = 3;
    uint256 internal constant QUERIES = 18;
    uint8 internal constant POW_BITS = 24;
    uint256 internal constant TX_BYTES = 10;
    uint256 internal constant MAX_BATCH = 16;
    uint256 internal constant ACCOUNTS = 128;
    uint256 internal constant NC = 55;

    RollupPeriodic public immutable periodic;

    struct StarkProof {
        bytes32 traceRoot;
        bytes32 compRoot;
        uint256[] ood; // trace(z)[18] | trace(gz)[18] | H_s(z)[3]
        bytes32[] friRoots; // one per committed layer, layer 0 = DEEP composition
        uint256[] lastLayer; // coefficients of the last FRI polynomial
        uint256 powNonce;
        uint256[] traceVals; // per unique query (sorted): 18
        bytes32[] traceDecommit; // batched multi-proof
        uint256[] compVals; // per unique query: 3
        bytes32[] compDecommit;
        uint256[] friVals; // per layer, per queried coset: 8
        bytes32[] friDecommit; // all layers' multi-proofs, concatenated
        uint256[] friDecommitLen; // length of each layer's multi-proof
    }

    error BatchSize(uint256 n);
    error BadAccount(uint256 index);
    error Shape(uint8 what);
    error NonCanonical(uint8 what);
    error Pow();
    error Ood();
    error Degenerate();
    error TraceMerkle();
    error CompMerkle();
    error FriMerkle(uint256 layer);
    error Deep(uint256 q);
    error Fold(uint256 layer, uint256 q);
    error LastLayer(uint256 q);

    struct Ctx {
        uint256 t;
        uint256 logT;
        uint256 n;
        uint256 logN;
        uint256 nl; // committed FRI layers
        uint256 lastLog; // log2 of last-layer coefficient count
        uint256 alpha;
        uint256 z;
        uint256 gamma;
        uint256 g;
        bytes32 digest;
        uint256 counter;
        uint256[] betas;
        uint256[] qs; // sorted, deduplicated query positions
    }

    constructor(RollupPeriodic p) {
        periodic = p;
    }

    /// @notice Reverts with the first failed check; returns true otherwise.
    function verify(bytes32 prevRoot, bytes32 newRoot, bytes calldata txs, StarkProof calldata p)
        external
        view
        returns (bool)
    {
        Ctx memory c = _batch(txs);
        _staticShapes(c, p);
        _canonical(prevRoot, newRoot, p);
        _channel(c, prevRoot, newRoot, txs, p);
        _dynamicShapes(c, p);
        _ood(c, uint256(prevRoot), uint256(newRoot), txs, p.ood);
        _decommitRows(c, p);
        _friLayers(c, p, _deep(c, p));
        return true;
    }

    // ------------------------------------------------------------ 1. statement

    function _batch(bytes calldata txs) private pure returns (Ctx memory c) {
        if (txs.length % TX_BYTES != 0) revert BatchSize(txs.length);
        uint256 b = txs.length / TX_BYTES;
        if (b == 0 || b & (b - 1) != 0 || b > MAX_BATCH) revert BatchSize(b);
        for (uint256 i = 0; i < b; i++) {
            if (uint8(txs[i * TX_BYTES]) >= ACCOUNTS || uint8(txs[i * TX_BYTES + 1]) >= ACCOUNTS) revert BadAccount(i);
        }
        c.t = 2048 * b;
        uint256 lt = 11;
        while ((1 << lt) < c.t) lt++;
        c.logT = lt;
        c.n = 16 * c.t;
        c.logN = lt + 4;
        c.nl = (lt - 6 + 2) / 3; // ceil((logT - 6) / 3) folds by 8
        c.lastLog = lt - 3 * c.nl;
    }

    function _staticShapes(Ctx memory c, StarkProof calldata p) private pure {
        if (p.ood.length != 2 * W + SEG) revert Shape(0);
        if (p.friRoots.length != c.nl) revert Shape(1);
        if (p.lastLayer.length != 1 << c.lastLog) revert Shape(2);
        if (p.friDecommitLen.length != c.nl) revert Shape(3);
    }

    function _canon(uint256[] calldata v) private pure returns (bool ok) {
        assembly ("memory-safe") {
            ok := 1
            for { let i := 0 } lt(i, v.length) { i := add(i, 1) } {
                if iszero(lt(calldataload(add(v.offset, shl(5, i))), P)) {
                    ok := 0
                    break
                }
            }
        }
    }

    function _canonical(bytes32 prevRoot, bytes32 newRoot, StarkProof calldata p) private pure {
        if (uint256(prevRoot) >= P || uint256(newRoot) >= P) revert NonCanonical(0);
        if (!_canon(p.ood)) revert NonCanonical(1);
        if (!_canon(p.lastLayer)) revert NonCanonical(2);
        if (p.powNonce >= 1 << 64) revert NonCanonical(3);
        if (!_canon(p.traceVals)) revert NonCanonical(4);
        if (!_canon(p.compVals)) revert NonCanonical(5);
        if (!_canon(p.friVals)) revert NonCanonical(6);
    }

    // ------------------------------------------------------------ 2. channel

    function _mix(Ctx memory c, bytes memory data) private pure {
        unchecked {
            c.digest = keccak256(abi.encodePacked(uint256(c.digest) + 1, data));
        }
        c.counter = 0;
    }

    function _random(Ctx memory c) private pure returns (uint256 r) {
        r = uint256(keccak256(abi.encodePacked(c.digest, c.counter)));
        c.counter++;
    }

    function _field(Ctx memory c) private pure returns (uint256 r) {
        do {
            r = _random(c);
        } while (r >= BOUND);
        r %= P;
    }

    function _channel(Ctx memory c, bytes32 prevRoot, bytes32 newRoot, bytes calldata txs, StarkProof calldata p)
        private
        pure
    {
        c.digest = keccak256(abi.encodePacked("zknet.stark.v2", uint8(c.logT), prevRoot, newRoot, keccak256(txs)));
        _mix(c, abi.encodePacked(p.traceRoot));
        c.alpha = _field(c);
        _mix(c, abi.encodePacked(p.compRoot));
        c.z = _field(c);
        _mix(c, abi.encodePacked(p.ood));
        c.gamma = _field(c);
        c.betas = new uint256[](c.nl);
        for (uint256 i = 0; i < c.nl; i++) {
            _mix(c, abi.encodePacked(p.friRoots[i]));
            c.betas[i] = _field(c);
        }
        _mix(c, abi.encodePacked(p.lastLayer));
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 nonce = uint64(p.powNonce);
        bytes32 seed = keccak256(abi.encodePacked(bytes8(0x0123456789abcded), c.digest, POW_BITS));
        if (uint256(keccak256(abi.encodePacked(seed, nonce))) >> (256 - POW_BITS) != 0) revert Pow();
        _mix(c, abi.encodePacked(nonce));
        c.qs = _queriesSorted(c);
    }

    /// Four 64-bit words per random hash, masked to [0, N), then sorted + deduped.
    function _queriesSorted(Ctx memory c) private pure returns (uint256[] memory q) {
        q = new uint256[](QUERIES);
        uint256 k = 0;
        while (k < QUERIES) {
            uint256 r = _random(c);
            for (uint256 w = 0; w < 4 && k < QUERIES; w++) {
                q[k++] = (r >> (192 - 64 * w)) & (c.n - 1);
            }
        }
        for (uint256 i = 1; i < QUERIES; i++) {
            uint256 x = q[i];
            uint256 j = i;
            while (j > 0 && q[j - 1] > x) {
                q[j] = q[j - 1];
                j--;
            }
            q[j] = x;
        }
        uint256 u = 1;
        for (uint256 i = 1; i < QUERIES; i++) {
            if (q[i] != q[u - 1]) q[u++] = q[i];
        }
        assembly ("memory-safe") {
            mstore(q, u)
        }
    }

    function _dynamicShapes(Ctx memory c, StarkProof calldata p) private pure {
        uint256 uq = c.qs.length;
        if (p.traceVals.length != uq * W) revert Shape(4);
        if (p.compVals.length != uq * SEG) revert Shape(5);
        uint256 total;
        uint256[] memory pos = _copy(c.qs);
        uint256 len = uq;
        for (uint256 l = 0; l < c.nl; l++) {
            uint256 nc = 0;
            for (uint256 i = 0; i < len; i++) {
                uint256 cc = pos[i] >> 3;
                if (nc == 0 || pos[nc - 1] != cc) pos[nc++] = cc;
            }
            total += nc;
            len = nc;
        }
        if (p.friVals.length != total * 8) revert Shape(6);
        uint256 sum;
        uint256 dl = p.friDecommit.length;
        for (uint256 l = 0; l < c.nl; l++) {
            if (p.friDecommitLen[l] > dl) revert Shape(7);
            sum += p.friDecommitLen[l];
        }
        if (sum != dl) revert Shape(7);
    }

    function _copy(uint256[] memory a) private pure returns (uint256[] memory b) {
        b = new uint256[](a.length);
        for (uint256 i = 0; i < a.length; i++) {
            b[i] = a[i];
        }
    }

    // ------------------------------------------------------------ field helpers

    function _expmod(uint256 b, uint256 e) private view returns (uint256 r) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 0x20)
            mstore(add(m, 0x20), 0x20)
            mstore(add(m, 0x40), 0x20)
            mstore(add(m, 0x60), b)
            mstore(add(m, 0x80), e)
            mstore(add(m, 0xa0), P)
            if iszero(staticcall(gas(), 0x05, m, 0xc0, m, 0x20)) { revert(0, 0) }
            r := mload(m)
        }
    }

    /// x^e for a small exponent (square and multiply, no precompile).
    function _pow(uint256 x, uint256 e) private pure returns (uint256 r) {
        r = 1;
        while (e != 0) {
            if (e & 1 != 0) r = mulmod(r, x, P);
            x = mulmod(x, x, P);
            e >>= 1;
        }
    }

    function _sub(uint256 a, uint256 b) private pure returns (uint256) {
        return addmod(a, P - b, P);
    }

    /// In-place batch inversion (Montgomery's trick); reverts on a zero.
    function _invertAll(uint256[] memory v) private view {
        uint256 n = v.length;
        uint256[] memory pre = new uint256[](n);
        uint256 acc = 1;
        for (uint256 i = 0; i < n; i++) {
            pre[i] = acc;
            acc = mulmod(acc, v[i], P);
        }
        if (acc == 0) revert Degenerate();
        uint256 inv = _expmod(acc, P - 2);
        for (uint256 i = n; i > 0;) {
            i--;
            uint256 vi = v[i];
            v[i] = mulmod(inv, pre[i], P);
            inv = mulmod(inv, vi, P);
        }
    }

    // ------------------------------------------------------------ 3. OOD check

    struct Zp {
        uint256 u; // T / 1024 = number of Merkle updates
        uint256 gInv;
        uint256 x1024; // z^(T/1024)
        uint256 x128;
        uint256 x64;
        uint256 xt; // z^T
    }

    function _ood(Ctx memory c, uint256 prevRoot, uint256 newRoot, bytes calldata txs, uint256[] calldata o)
        private
        view
    {
        Zp memory v = _zpowers(c);
        (uint256[] memory d, uint256[] memory pts) = _denominators(c, v);
        _invertAll(d);
        uint256[11] memory f = _factors(c.z, v, d);
        // e = [c0, c1, c2, V_acct(z), V_amt(z), prevRoot, newRoot]
        uint256[7] memory e;
        (e[3], e[4]) = _interpolate(txs, v, d, pts);
        (e[0], e[1], e[2]) = periodic.eval(v.x128);
        e[5] = prevRoot;
        e[6] = newRoot;
        uint256 expect = _combine(_numerators(o, e), f, c.alpha);
        uint256 xt = v.xt;
        uint256 actual = addmod(o[2 * W], mulmod(xt, addmod(o[2 * W + 1], mulmod(xt, o[2 * W + 2], P), P), P), P);
        if (actual != expect) revert Ood();
    }

    function _zpowers(Ctx memory c) private view returns (Zp memory v) {
        c.g = _expmod(3, (P - 1) / c.t);
        v.gInv = _pow(c.g, c.t - 1);
        v.u = c.t / 1024;
        v.x1024 = _pow(c.z, v.u);
        v.x128 = _pow(v.x1024, 8);
        v.x64 = mulmod(v.x128, v.x128, P);
        v.xt = _pow(v.x64, 64);
    }

    /// Zerofier denominators [z^T-1, Z128, Z1024, Z64, Z63, z-1, z-g^-1], then
    /// U·ω^-1, then z - x_u for the U update-end points x_u = g^(1024u+1023).
    function _denominators(Ctx memory c, Zp memory v) private pure returns (uint256[] memory d, uint256[] memory pts) {
        uint256 z = c.z;
        d = new uint256[](8 + v.u);
        d[0] = _sub(v.xt, 1);
        d[1] = _sub(v.x128, K.W128_INV);
        d[2] = _sub(v.x1024, K.W1024_INV);
        d[3] = _sub(v.x64, K.W64_INV);
        d[4] = _sub(v.x1024, K.W1024_63);
        d[5] = _sub(z, 1);
        d[6] = _sub(z, v.gInv);
        d[7] = mulmod(v.u, K.W1024_INV, P);
        pts = new uint256[](v.u);
        uint256 xu = _pow(c.g, 1023);
        uint256 h = _pow(c.g, 1024);
        for (uint256 i = 0; i < v.u; i++) {
            pts[i] = xu;
            d[8 + i] = _sub(z, xu);
            xu = mulmod(xu, h, P);
        }
    }

    /// Multipliers per constraint group (numerator · this = numerator / zerofier).
    function _factors(uint256 z, Zp memory v, uint256[] memory d) private pure returns (uint256[11] memory f) {
        uint256 z128 = _sub(v.x128, K.W128_INV);
        uint256 z1024 = _sub(v.x1024, K.W1024_INV);
        f[0] = mulmod(z128, d[0], P); // A: rows != 127 mod 128
        f[1] = mulmod(z1024, d[0], P); // C: rows != 1023 mod 1024
        f[2] = mulmod(z1024, d[1], P); // D: 127 mod 128, not 1023 mod 1024
        f[3] = mulmod(_sub(z, v.gInv), d[2], P); // E: 1023 mod 1024, not last
        f[4] = d[2]; // F, H: 1023 mod 1024
        f[5] = d[0]; // I: all rows
        f[6] = mulmod(_sub(v.x64, K.W64_INV), d[0], P); // J: rows != 63 mod 64
        f[7] = d[3]; // K: 63 mod 64
        f[8] = d[4]; // L: 63 mod 1024
        f[9] = d[5]; // M: first row
        f[10] = d[6]; // N: last row
    }

    /// V_acct(z), V_amt(z): the batch's tx data interpolated over the
    /// update-end rows (barycentric). This binds the proof to the exact
    /// calldata the sequencer committed.
    function _interpolate(bytes calldata txs, Zp memory v, uint256[] memory d, uint256[] memory pts)
        private
        pure
        returns (uint256 va, uint256 vm)
    {
        for (uint256 i = 0; i < v.u; i++) {
            uint256 ti = (i / 2) * TX_BYTES;
            uint256 acct = i % 2 == 0 ? uint8(txs[ti]) : uint8(txs[ti + 1]);
            uint256 amt = uint64(bytes8(txs[ti + 2:ti + 10]));
            uint256 l = mulmod(pts[i], d[8 + i], P);
            va = addmod(va, mulmod(acct, l, P), P);
            vm = addmod(vm, mulmod(amt, l, P), P);
        }
        uint256 sc = mulmod(_sub(v.x1024, K.W1024_INV), d[7], P);
        va = mulmod(va, sc, P);
        vm = mulmod(vm, sc, P);
    }

    function _combine(uint256[NC] memory num, uint256[11] memory f, uint256 alpha) private pure returns (uint256 acc) {
        uint8[11] memory sizes = [10, 6, 8, 9, 6, 2, 1, 1, 1, 10, 1];
        uint256 ap = 1;
        uint256 i = 0;
        for (uint256 g = 0; g < 11; g++) {
            uint256 s = 0;
            for (uint256 k = 0; k < sizes[g]; k++) {
                s = addmod(s, mulmod(ap, num[i], P), P);
                ap = mulmod(ap, alpha, P);
                i++;
            }
            acc = addmod(acc, mulmod(s, f[g], P), P);
        }
    }

    function _cube(uint256 x) private pure returns (uint256) {
        return mulmod(x, mulmod(x, x, P), P);
    }

    /// The 55 constraint numerators on the OOD frame (cur = o[0..18], nxt = o[18..36]).
    /// Same order as `air::numerators` in Rust.
    /// e = [c0, c1, c2, V_acct(z), V_amt(z), prevRoot, newRoot].
    function _numerators(uint256[] calldata o, uint256[7] memory e) private pure returns (uint256[NC] memory n) {
        // A: Poseidon rounds, both lanes
        for (uint256 l = 0; l < 2; l++) {
            uint256 b = 3 * l;
            uint256 t0 = _cube(addmod(o[b], e[0], P));
            uint256 t1 = _cube(addmod(o[b + 1], e[1], P));
            uint256 t2 = _cube(addmod(o[b + 2], e[2], P));
            uint256 s = addmod(addmod(t0, t1, P), t2, P);
            n[b] = _sub(o[W + b], addmod(s, addmod(t0, t0, P), P));
            n[b + 1] = _sub(o[W + b + 1], _sub(s, addmod(t1, t1, P)));
            n[b + 2] = _sub(o[W + b + 2], _sub(s, mulmod(3, t2, P)));
        }
        // B: sib, dir, idx, pw constant in a cycle
        for (uint256 j = 0; j < 4; j++) {
            n[6 + j] = _sub(o[W + 6 + j], o[6 + j]);
        }
        // C: bo, bn, amt, acct, sgn, root constant in an update
        for (uint256 j = 0; j < 6; j++) {
            n[10 + j] = _sub(o[W + 10 + j], o[10 + j]);
        }
        // D: absorb (out, sib) by dir into the next cycle
        {
            uint256 s = o[W + 6];
            uint256 d = o[W + 7];
            for (uint256 l = 0; l < 2; l++) {
                uint256 b = 3 * l;
                uint256 out = o[b];
                n[16 + b] = _sub(o[W + b], addmod(out, mulmod(d, _sub(s, out), P), P));
                n[17 + b] = _sub(o[W + b + 1], addmod(s, mulmod(d, _sub(out, s), P), P));
                n[18 + b] = _sub(o[W + b + 2], 2);
            }
            n[22] = _sub(o[W + 8], addmod(o[8], mulmod(d, o[9], P), P));
            n[23] = _sub(o[W + 9], addmod(o[9], o[9], P));
        }
        // E: the next update starts from (bo | bn, 0, 1) and the new root
        n[24] = _sub(o[W + 0], o[W + 10]);
        n[25] = o[W + 1];
        n[26] = _sub(o[W + 2], 1);
        n[27] = _sub(o[W + 3], o[W + 11]);
        n[28] = o[W + 4];
        n[29] = _sub(o[W + 5], 1);
        n[30] = o[W + 8];
        n[31] = _sub(o[W + 9], 1);
        n[32] = _sub(o[W + 15], o[3]);
        // F: sign alternates (debit, credit, ...)
        n[33] = addmod(o[W + 14], o[14], P);
        // H: update-end checks
        n[34] = _sub(o[0], o[15]);
        n[35] = _sub(_sub(o[11], o[10]), mulmod(o[14], o[12], P));
        n[36] = _sub(o[13], o[8]);
        n[37] = _sub(o[13], e[3]);
        n[38] = _sub(o[12], e[4]);
        // I: binary
        n[39] = mulmod(o[7], _sub(o[7], 1), P);
        n[40] = mulmod(o[17], _sub(o[17], 1), P);
        // J, K, L: range check of bn
        n[41] = _sub(_sub(o[W + 16], addmod(o[16], o[16], P)), o[W + 17]);
        n[42] = _sub(o[W + 16], o[W + 17]);
        n[43] = _sub(o[16], o[11]);
        // M: first row
        n[44] = _sub(o[0], o[10]);
        n[45] = o[1];
        n[46] = _sub(o[2], 1);
        n[47] = _sub(o[3], o[11]);
        n[48] = o[4];
        n[49] = _sub(o[5], 1);
        n[50] = o[8];
        n[51] = _sub(o[9], 1);
        n[52] = addmod(o[14], 1, P);
        n[53] = _sub(o[15], e[5]);
        // N: last row
        n[54] = _sub(o[3], e[6]);
    }

    // ------------------------------------------------------------ 4. decommitments

    function _hash2(bytes32 a, bytes32 b) private pure returns (bytes32 h) {
        assembly ("memory-safe") {
            mstore(0x00, a)
            mstore(0x20, b)
            h := and(keccak256(0x00, 0x40), MASK160)
        }
    }

    function _hashSlice(uint256[] calldata v, uint256 from, uint256 len) private pure returns (bytes32 h) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            calldatacopy(m, add(v.offset, shl(5, from)), shl(5, len))
            h := and(keccak256(m, shl(5, len)), MASK160)
        }
    }

    /// Batched Merkle decommitment: `idx` sorted and unique, `h` their leaf
    /// hashes. Siblings come from `stream` in queue order, each at most once,
    /// and the stream must be used up. Same algorithm as `merkle::verify_multi`.
    function _merkleMulti(bytes32 root, uint256 depth, uint256[] memory idx, bytes32[] memory h, bytes32[] calldata stream)
        private
        pure
        returns (bool)
    {
        uint256 len = idx.length;
        uint256 s = 0;
        for (uint256 d = 0; d < depth; d++) {
            uint256 w = 0;
            uint256 i = 0;
            while (i < len) {
                uint256 k = idx[i];
                if (k >> depth != 0) return false;
                bytes32 hk = h[i];
                bytes32 sib;
                if (k & 1 == 0 && i + 1 < len && idx[i + 1] == k + 1) {
                    sib = h[i + 1];
                    i += 2;
                } else {
                    if (s >= stream.length) return false;
                    sib = stream[s++];
                    i++;
                }
                idx[w] = k >> 1;
                h[w] = k & 1 == 0 ? _hash2(hk, sib) : _hash2(sib, hk);
                w++;
            }
            len = w;
        }
        return s == stream.length && len == 1 && idx[0] == 0 && h[0] == root;
    }

    function _rowLeaves(Ctx memory c, uint256[] calldata vals, uint256 width)
        private
        pure
        returns (uint256[] memory idx, bytes32[] memory h)
    {
        uint256 uq = c.qs.length;
        idx = _copy(c.qs);
        h = new bytes32[](uq);
        for (uint256 i = 0; i < uq; i++) {
            h[i] = _hashSlice(vals, i * width, width);
        }
    }

    /// The opened trace and composition rows must be in the roots committed
    /// before z was drawn.
    function _decommitRows(Ctx memory c, StarkProof calldata p) private pure {
        (uint256[] memory idx, bytes32[] memory h) = _rowLeaves(c, p.traceVals, W);
        if (!_merkleMulti(p.traceRoot, c.logN, idx, h, p.traceDecommit)) revert TraceMerkle();
        (idx, h) = _rowLeaves(c, p.compVals, SEG);
        if (!_merkleMulti(p.compRoot, c.logN, idx, h, p.compDecommit)) revert CompMerkle();
    }

    function _bitrev(uint256 i, uint256 log) private pure returns (uint256 r) {
        for (uint256 b = 0; b < log; b++) {
            r = (r << 1) | (i & 1);
            i >>= 1;
        }
    }

    /// D(x_q) for every query: the DEEP quotients of every trace column (at z
    /// and gz) and every composition segment (at z), batched by γ.
    function _deep(Ctx memory c, StarkProof calldata p) private view returns (uint256[] memory val) {
        uint256 uq = c.qs.length;
        uint256 z = c.z;
        uint256 gz = mulmod(c.g, z, P);
        uint256 wN = _expmod(3, (P - 1) / c.n);
        uint256[] memory inv = new uint256[](2 * uq);
        for (uint256 i = 0; i < uq; i++) {
            uint256 x = mulmod(3, _pow(wN, _bitrev(c.qs[i], c.logN)), P);
            inv[2 * i] = _sub(x, z);
            inv[2 * i + 1] = _sub(x, gz);
        }
        _invertAll(inv);
        uint256[] memory gp = new uint256[](2 * W + SEG);
        gp[0] = 1;
        for (uint256 i = 1; i < gp.length; i++) {
            gp[i] = mulmod(gp[i - 1], c.gamma, P);
        }
        val = new uint256[](uq);
        for (uint256 i = 0; i < uq; i++) {
            (uint256 a, uint256 b) = _deepSums(p, i, gp);
            val[i] = addmod(mulmod(a, inv[2 * i], P), mulmod(b, inv[2 * i + 1], P), P);
        }
    }

    function _deepSums(StarkProof calldata p, uint256 q, uint256[] memory gp) private pure returns (uint256 a, uint256 b) {
        uint256[] calldata o = p.ood;
        uint256[] calldata tv = p.traceVals;
        for (uint256 j = 0; j < W; j++) {
            uint256 v = tv[q * W + j];
            a = addmod(a, mulmod(gp[2 * j], _sub(v, o[j]), P), P);
            b = addmod(b, mulmod(gp[2 * j + 1], _sub(v, o[W + j]), P), P);
        }
        for (uint256 s = 0; s < SEG; s++) {
            a = addmod(a, mulmod(gp[2 * W + s], _sub(p.compVals[q * SEG + s], o[2 * W + s]), P), P);
        }
    }

    // ------------------------------------------------------------ 5. FRI

    /// State carried from one FRI layer to the next.
    struct Fri {
        uint256 off; // coset offset of the current layer's domain
        uint256 wM; // generator of the current layer's domain
        uint256 logM; // log2 of its size
        uint256 fo; // offset into friVals
        uint256 doff; // offset into friDecommit
        uint256 len; // live items
    }

    function _friLayers(Ctx memory c, StarkProof calldata p, uint256[] memory val) private view {
        uint256[] memory pos = _copy(c.qs);
        Fri memory f = Fri(3, _expmod(3, (P - 1) / c.n), c.logN, 0, 0, pos.length);
        for (uint256 layer = 0; layer < c.nl; layer++) {
            _friLayer(c, p, f, layer, pos, val);
        }
        for (uint256 i = 0; i < f.len; i++) {
            uint256 x = mulmod(f.off, _pow(f.wM, _bitrev(pos[i], f.logM)), P);
            uint256 r;
            for (uint256 j = p.lastLayer.length; j > 0;) {
                j--;
                r = addmod(mulmod(r, x, P), p.lastLayer[j], P);
            }
            if (r != val[i]) revert LastLayer(i);
        }
    }

    /// One layer: the queried cosets must be in friRoots[layer] and hold the
    /// values the previous layer (or D, for layer 0) predicts; then each coset
    /// is folded by 8 into one value of the next layer.
    function _friLayer(
        Ctx memory c,
        StarkProof calldata p,
        Fri memory f,
        uint256 layer,
        uint256[] memory pos,
        uint256[] memory val
    ) private view {
        uint256[] memory cs = _cosets(pos, f.len);
        _cosetMerkle(p, f, layer, cs);
        _cosetValues(p, f, layer, cs, pos, val);
        uint256 nc = cs.length;
        uint256[] memory xi = new uint256[](nc);
        for (uint256 j = 0; j < nc; j++) {
            xi[j] = mulmod(f.off, _pow(f.wM, _bitrev(8 * cs[j], f.logM)), P);
        }
        _invertAll(xi);
        uint256 beta = c.betas[layer];
        for (uint256 j = 0; j < nc; j++) {
            val[j] = _foldCoset(p.friVals, f.fo + 8 * j, xi[j], beta);
            pos[j] = cs[j];
        }
        f.fo += 8 * nc;
        f.len = nc;
        f.off = _pow(f.off, 8);
        f.wM = _pow(f.wM, 8);
        f.logM -= 3;
    }

    /// Distinct cosets (pos / 8) of the first `len` sorted positions.
    function _cosets(uint256[] memory pos, uint256 len) private pure returns (uint256[] memory cs) {
        cs = new uint256[](len);
        uint256 nc = 0;
        for (uint256 i = 0; i < len; i++) {
            uint256 cc = pos[i] >> 3;
            if (nc == 0 || cs[nc - 1] != cc) cs[nc++] = cc;
        }
        assembly ("memory-safe") {
            mstore(cs, nc)
        }
    }

    function _cosetMerkle(StarkProof calldata p, Fri memory f, uint256 layer, uint256[] memory cs) private pure {
        uint256 nc = cs.length;
        bytes32[] memory h = new bytes32[](nc);
        for (uint256 j = 0; j < nc; j++) {
            h[j] = _hashSlice(p.friVals, f.fo + 8 * j, 8);
        }
        uint256 dl = p.friDecommitLen[layer];
        uint256 d0 = f.doff;
        if (!_merkleMulti(p.friRoots[layer], f.logM - 3, _copy(cs), h, p.friDecommit[d0:d0 + dl])) revert FriMerkle(layer);
        f.doff = d0 + dl;
    }

    function _cosetValues(
        StarkProof calldata p,
        Fri memory f,
        uint256 layer,
        uint256[] memory cs,
        uint256[] memory pos,
        uint256[] memory val
    ) private pure {
        uint256 ci = 0;
        for (uint256 i = 0; i < f.len; i++) {
            while (cs[ci] != pos[i] >> 3) ci++;
            if (p.friVals[f.fo + 8 * ci + (pos[i] & 7)] != val[i]) {
                if (layer == 0) revert Deep(i);
                revert Fold(layer, i);
            }
        }
    }

    function _fold2(uint256 a, uint256 b, uint256 xInv, uint256 beta) private pure returns (uint256) {
        return addmod(
            mulmod(addmod(a, b, P), HALF, P), mulmod(mulmod(beta, _sub(a, b), P), mulmod(HALF, xInv, P), P), P
        );
    }

    /// Folds a bit-reversed coset (slot j = f(x0·ω_8^bitrev3(j))) to f'(x0^8):
    /// three folds by 2 with β, β², β⁴, as in StarkWare's FriLayer.
    function _foldCoset(uint256[] calldata v, uint256 o, uint256 xi, uint256 beta) private pure returns (uint256) {
        uint256 r0 = _fold2(v[o], v[o + 1], xi, beta);
        uint256 r1 = _fold2(v[o + 2], v[o + 3], mulmod(xi, K.W8_INV_2, P), beta);
        uint256 r2 = _fold2(v[o + 4], v[o + 5], mulmod(xi, K.W8_INV_1, P), beta);
        uint256 r3 = _fold2(v[o + 6], v[o + 7], mulmod(xi, K.W8_INV_3, P), beta);
        uint256 x2 = mulmod(xi, xi, P);
        uint256 b2 = mulmod(beta, beta, P);
        uint256 s0 = _fold2(r0, r1, x2, b2);
        uint256 s1 = _fold2(r2, r3, mulmod(x2, K.W8_INV_2, P), b2);
        return _fold2(s0, s1, mulmod(x2, x2, P), mulmod(b2, b2, P));
    }
}
