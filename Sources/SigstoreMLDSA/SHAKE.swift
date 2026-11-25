import Foundation


// SHAKE128 / SHAKE256 (FIPS 202) on top of Keccak-f[1600].
//
// FIPS 204 uses SHAKE256 as H and SHAKE128 as G (FIPS 204 §3.7), both in an
// incremental absorb-then-squeeze mode (FIPS 204 §3.7, "H.Init / H.Absorb /
// H.Squeeze"). Only what ML-DSA verification needs is implemented: absorb any
// number of times, then squeeze any number of times.

/// Keccak-f[1600] round constants RC[ir] (FIPS 202 §3.2.5, Algorithm 5/6).
private let keccakRoundConstants: [UInt64] = [
    0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
    0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
    0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
    0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
    0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
    0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
]

@inline(__always)
private func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 {
    (x << n) | (x >> (64 &- n))
}

/// Keccak-f[1600] (FIPS 202 §3.3, Algorithm 7) on 25 lanes, lane (x, y) at
/// index x + 5y. Unrolled over lanes so debug builds stay fast.
private func keccakF1600(_ s: inout [UInt64]) {
    precondition(s.count == 25)
    var a0 = s[0], a1 = s[1], a2 = s[2], a3 = s[3], a4 = s[4]
    var a5 = s[5], a6 = s[6], a7 = s[7], a8 = s[8], a9 = s[9]
    var a10 = s[10], a11 = s[11], a12 = s[12], a13 = s[13], a14 = s[14]
    var a15 = s[15], a16 = s[16], a17 = s[17], a18 = s[18], a19 = s[19]
    var a20 = s[20], a21 = s[21], a22 = s[22], a23 = s[23], a24 = s[24]
        for round in 0..<24 {
            // θ
            let c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20
            let c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21
            let c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22
            let c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23
            let c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24
            let d0 = c4 ^ rotl(c1, 1)
            let d1 = c0 ^ rotl(c2, 1)
            let d2 = c1 ^ rotl(c3, 1)
            let d3 = c2 ^ rotl(c4, 1)
            let d4 = c3 ^ rotl(c0, 1)
            // ρ and π: B[y, 2x+3y] = rotl(A[x, y], r[x, y])
            let b0 = a0 ^ d0
            let b16 = rotl(a5 ^ d0, 36)
            let b7 = rotl(a10 ^ d0, 3)
            let b23 = rotl(a15 ^ d0, 41)
            let b14 = rotl(a20 ^ d0, 18)
            let b10 = rotl(a1 ^ d1, 1)
            let b1 = rotl(a6 ^ d1, 44)
            let b17 = rotl(a11 ^ d1, 10)
            let b8 = rotl(a16 ^ d1, 45)
            let b24 = rotl(a21 ^ d1, 2)
            let b20 = rotl(a2 ^ d2, 62)
            let b11 = rotl(a7 ^ d2, 6)
            let b2 = rotl(a12 ^ d2, 43)
            let b18 = rotl(a17 ^ d2, 15)
            let b9 = rotl(a22 ^ d2, 61)
            let b5 = rotl(a3 ^ d3, 28)
            let b21 = rotl(a8 ^ d3, 55)
            let b12 = rotl(a13 ^ d3, 25)
            let b3 = rotl(a18 ^ d3, 21)
            let b19 = rotl(a23 ^ d3, 56)
            let b15 = rotl(a4 ^ d4, 27)
            let b6 = rotl(a9 ^ d4, 20)
            let b22 = rotl(a14 ^ d4, 39)
            let b13 = rotl(a19 ^ d4, 8)
            let b4 = rotl(a24 ^ d4, 14)
            // χ
            a0 = b0 ^ (~b1 & b2)
            a1 = b1 ^ (~b2 & b3)
            a2 = b2 ^ (~b3 & b4)
            a3 = b3 ^ (~b4 & b0)
            a4 = b4 ^ (~b0 & b1)
            a5 = b5 ^ (~b6 & b7)
            a6 = b6 ^ (~b7 & b8)
            a7 = b7 ^ (~b8 & b9)
            a8 = b8 ^ (~b9 & b5)
            a9 = b9 ^ (~b5 & b6)
            a10 = b10 ^ (~b11 & b12)
            a11 = b11 ^ (~b12 & b13)
            a12 = b12 ^ (~b13 & b14)
            a13 = b13 ^ (~b14 & b10)
            a14 = b14 ^ (~b10 & b11)
            a15 = b15 ^ (~b16 & b17)
            a16 = b16 ^ (~b17 & b18)
            a17 = b17 ^ (~b18 & b19)
            a18 = b18 ^ (~b19 & b15)
            a19 = b19 ^ (~b15 & b16)
            a20 = b20 ^ (~b21 & b22)
            a21 = b21 ^ (~b22 & b23)
            a22 = b22 ^ (~b23 & b24)
            a23 = b23 ^ (~b24 & b20)
            a24 = b24 ^ (~b20 & b21)
            // ι
            a0 ^= keccakRoundConstants[round]
        }
    s[0] = a0; s[1] = a1; s[2] = a2; s[3] = a3; s[4] = a4
    s[5] = a5; s[6] = a6; s[7] = a7; s[8] = a8; s[9] = a9
    s[10] = a10; s[11] = a11; s[12] = a12; s[13] = a13; s[14] = a14
    s[15] = a15; s[16] = a16; s[17] = a17; s[18] = a18; s[19] = a19
    s[20] = a20; s[21] = a21; s[22] = a22; s[23] = a23; s[24] = a24
}

/// A Keccak sponge with SHAKE's domain separation (suffix 1111, FIPS 202 §6.2)
/// and pad10*1.
struct KeccakSponge {
    private var state = [UInt64](repeating: 0, count: 25)
    /// Rate in bytes: 168 for SHAKE128, 136 for SHAKE256.
    private let rate: Int
    /// Byte position inside the current rate-sized block.
    private var offset = 0
    private var squeezing = false

    init(rate: Int) {
        self.rate = rate
    }

    @inline(__always)
    private mutating func xorByte(_ b: UInt8, at i: Int) {
        state[i >> 3] ^= UInt64(b) << UInt64((i & 7) << 3)
    }

    mutating func absorb(_ bytes: UnsafeRawBufferPointer) {
        precondition(!squeezing, "absorb after squeeze")
        for b in bytes {
            xorByte(b, at: offset)
            offset += 1
            if offset == rate {
                keccakF1600(&state)
                offset = 0
            }
        }
    }

    mutating func absorb(_ bytes: [UInt8]) {
        bytes.withUnsafeBytes { absorb($0) }
    }

    mutating func absorb<D: DataProtocol>(contentsOf data: D) {
        for region in data.regions {
            region.withUnsafeBytes { absorb($0) }
        }
    }

    mutating func squeeze(count: Int) -> [UInt8] {
        if !squeezing {
            // SHAKE suffix 1111 followed by pad10*1 (FIPS 202 §5.1, §6.2).
            xorByte(0x1F, at: offset)
            xorByte(0x80, at: rate - 1)
            keccakF1600(&state)
            offset = 0
            squeezing = true
        }
        var out = [UInt8](repeating: 0, count: count)
        for i in 0..<count {
            if offset == rate {
                keccakF1600(&state)
                offset = 0
            }
            out[i] = UInt8(truncatingIfNeeded: state[offset >> 3] >> UInt64((offset & 7) << 3))
            offset += 1
        }
        return out
    }
}

/// SHAKE128 (FIPS 202 §6.2); G in FIPS 204.
struct SHAKE128 {
    private var sponge = KeccakSponge(rate: 168)
    init() {}
    mutating func update<D: DataProtocol>(_ data: D) { sponge.absorb(contentsOf: data) }
    mutating func update(_ bytes: [UInt8]) { sponge.absorb(bytes) }
    mutating func squeeze(count: Int) -> [UInt8] { sponge.squeeze(count: count) }
    static func hash<D: DataProtocol>(_ data: D, outputLength: Int) -> [UInt8] {
        var h = SHAKE128()
        h.update(data)
        return h.squeeze(count: outputLength)
    }
}

/// SHAKE256 (FIPS 202 §6.2); H in FIPS 204.
struct SHAKE256 {
    private var sponge = KeccakSponge(rate: 136)
    init() {}
    mutating func update<D: DataProtocol>(_ data: D) { sponge.absorb(contentsOf: data) }
    mutating func update(_ bytes: [UInt8]) { sponge.absorb(bytes) }
    mutating func squeeze(count: Int) -> [UInt8] { sponge.squeeze(count: count) }
    static func hash<D: DataProtocol>(_ data: D, outputLength: Int) -> [UInt8] {
        var h = SHAKE256()
        h.update(data)
        return h.squeeze(count: outputLength)
    }
}
