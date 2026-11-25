// Arithmetic in GF(p), p = 2^255 - 19 (RFC 8032 §5.1).
//
// Elements are five unsigned 51-bit limbs (radix 2^51), the representation
// used by Go's crypto/internal/fips140/edwards25519/field (generic code).
// Only verification of public data uses this, so nothing here is constant
// time. All operations are total: there is no input that can trap.

struct FieldElement: Sendable {
    var l0: UInt64
    var l1: UInt64
    var l2: UInt64
    var l3: UInt64
    var l4: UInt64

    static let mask51: UInt64 = (1 << 51) - 1

    static let zero = FieldElement(l0: 0, l1: 0, l2: 0, l3: 0, l4: 0)
    static let one = FieldElement(l0: 1, l1: 0, l2: 0, l3: 0, l4: 0)

    init(l0: UInt64, l1: UInt64, l2: UInt64, l3: UInt64, l4: UInt64) {
        self.l0 = l0
        self.l1 = l1
        self.l2 = l2
        self.l3 = l3
        self.l4 = l4
    }

    /// A small constant (< 2^51).
    init(small value: UInt64) {
        precondition(value <= Self.mask51)
        self.init(l0: value, l1: 0, l2: 0, l3: 0, l4: 0)
    }

    /// Decodes a 32-byte little-endian integer, ignoring bit 255. Returns nil
    /// when the 255-bit value is not canonical, i.e. it is >= p
    /// (RFC 8032 §5.1.3 step 1: "If the resulting value is >= p, decoding
    /// fails"). Go's field.Element.SetBytes accepts such values; we do not.
    init?(canonicalBytes b: [UInt8]) {
        guard b.count == 32 else { return nil }
        // Values in [p, 2^255 - 1] are 0x7fff...ff{ed..ff} (little endian).
        var allOnes = (b[31] & 0x7f) == 0x7f
        for i in 1..<31 where b[i] != 0xff {
            allOnes = false
        }
        if allOnes && b[0] >= 0xed { return nil }

        func word(_ i: Int) -> UInt64 {
            var w: UInt64 = 0
            for j in 0..<8 { w |= UInt64(b[8 * i + j]) << (8 * j) }
            return w
        }
        let w0 = word(0), w1 = word(1), w2 = word(2), w3 = word(3)
        self.init(
            l0: w0 & Self.mask51,
            l1: ((w0 >> 51) | (w1 << 13)) & Self.mask51,
            l2: ((w1 >> 38) | (w2 << 26)) & Self.mask51,
            l3: ((w2 >> 25) | (w3 << 39)) & Self.mask51,
            l4: (w3 >> 12) & Self.mask51 // drops bit 255
        )
    }

    /// Brings every limb below 2^51 (l0 below 2^51 + 19·2^13), keeping the
    /// value mod p. Limbs may be any UInt64 on input.
    func carried() -> FieldElement {
        let c0 = l0 >> 51, c1 = l1 >> 51, c2 = l2 >> 51, c3 = l3 >> 51, c4 = l4 >> 51
        return FieldElement(
            l0: (l0 & Self.mask51) + c4 * 19, // 2^255 ≡ 19 (mod p)
            l1: (l1 & Self.mask51) + c0,
            l2: (l2 & Self.mask51) + c1,
            l3: (l3 & Self.mask51) + c2,
            l4: (l4 & Self.mask51) + c3
        )
    }

    /// The unique representative in [0, p) as 32 little-endian bytes.
    var bytes: [UInt8] {
        var v = carried().carried()
        // c = 1 iff v >= p: v + 19 overflows 2^255 exactly then.
        var c = (v.l0 + 19) >> 51
        c = (v.l1 + c) >> 51
        c = (v.l2 + c) >> 51
        c = (v.l3 + c) >> 51
        c = (v.l4 + c) >> 51
        // Subtract p = add 19 and drop 2^255.
        v.l0 += 19 * c
        v.l1 += v.l0 >> 51
        v.l0 &= Self.mask51
        v.l2 += v.l1 >> 51
        v.l1 &= Self.mask51
        v.l3 += v.l2 >> 51
        v.l2 &= Self.mask51
        v.l4 += v.l3 >> 51
        v.l3 &= Self.mask51
        v.l4 &= Self.mask51

        let words: [UInt64] = [
            v.l0 | (v.l1 << 51),
            (v.l1 >> 13) | (v.l2 << 38),
            (v.l2 >> 26) | (v.l3 << 25),
            (v.l3 >> 39) | (v.l4 << 12),
        ]
        var out = [UInt8](repeating: 0, count: 32)
        for i in 0..<4 {
            for j in 0..<8 { out[8 * i + j] = UInt8(truncatingIfNeeded: words[i] >> (8 * j)) }
        }
        return out
    }

    var isZero: Bool { bytes.allSatisfy { $0 == 0 } }

    /// The low bit of the canonical value ("negative" in RFC 8032 §5.1.2).
    var isOdd: Bool { bytes[0] & 1 == 1 }

    func equals(_ other: FieldElement) -> Bool { bytes == other.bytes }

    static func + (a: FieldElement, b: FieldElement) -> FieldElement {
        let a = a.carried(), b = b.carried()
        return FieldElement(l0: a.l0 + b.l0, l1: a.l1 + b.l1, l2: a.l2 + b.l2, l3: a.l3 + b.l3, l4: a.l4 + b.l4)
            .carried()
    }

    static func - (a: FieldElement, b: FieldElement) -> FieldElement {
        // a + 2p - b; after carried() every limb of b is below 2p's limbs.
        let a = a.carried(), b = b.carried()
        return FieldElement(
            l0: (a.l0 + 0xFFFFFFFFFFFDA) - b.l0,
            l1: (a.l1 + 0xFFFFFFFFFFFFE) - b.l1,
            l2: (a.l2 + 0xFFFFFFFFFFFFE) - b.l2,
            l3: (a.l3 + 0xFFFFFFFFFFFFE) - b.l3,
            l4: (a.l4 + 0xFFFFFFFFFFFFE) - b.l4
        ).carried()
    }

    static prefix func - (a: FieldElement) -> FieldElement { .zero - a }

    static func * (a: FieldElement, b: FieldElement) -> FieldElement {
        let a = a.carried(), b = b.carried()
        @inline(__always) func m(_ x: UInt64, _ y: UInt64) -> UInt128 { UInt128(x) * UInt128(y) }
        let b1_19 = b.l1 * 19, b2_19 = b.l2 * 19, b3_19 = b.l3 * 19, b4_19 = b.l4 * 19
        // Limbs < 2^52, so each product < 2^109 and each sum < 2^112.
        var r0 = m(a.l0, b.l0) + m(a.l1, b4_19) + m(a.l2, b3_19) + m(a.l3, b2_19) + m(a.l4, b1_19)
        var r1 = m(a.l0, b.l1) + m(a.l1, b.l0) + m(a.l2, b4_19) + m(a.l3, b3_19) + m(a.l4, b2_19)
        var r2 = m(a.l0, b.l2) + m(a.l1, b.l1) + m(a.l2, b.l0) + m(a.l3, b4_19) + m(a.l4, b3_19)
        var r3 = m(a.l0, b.l3) + m(a.l1, b.l2) + m(a.l2, b.l1) + m(a.l3, b.l0) + m(a.l4, b4_19)
        var r4 = m(a.l0, b.l4) + m(a.l1, b.l3) + m(a.l2, b.l2) + m(a.l3, b.l1) + m(a.l4, b.l0)
        let mask = UInt128(mask51)
        r1 += r0 >> 51
        r0 &= mask
        r2 += r1 >> 51
        r1 &= mask
        r3 += r2 >> 51
        r2 &= mask
        r4 += r3 >> 51
        r3 &= mask
        r0 += (r4 >> 51) * 19
        r4 &= mask
        r1 += r0 >> 51
        r0 &= mask
        return FieldElement(
            l0: UInt64(r0), l1: UInt64(r1), l2: UInt64(r2), l3: UInt64(r3), l4: UInt64(r4)
        ).carried()
    }

    var squared: FieldElement { self * self }

    /// self^e for a 256-bit little-endian exponent (square-and-multiply).
    func power(_ exponentLE: [UInt8]) -> FieldElement {
        var result = FieldElement.one
        for bit in stride(from: exponentLE.count * 8 - 1, through: 0, by: -1) {
            result = result.squared
            if (exponentLE[bit / 8] >> (bit % 8)) & 1 == 1 {
                result = result * self
            }
        }
        return result
    }

    private static func exponent(low: UInt8, high: UInt8) -> [UInt8] {
        var e = [UInt8](repeating: 0xff, count: 32)
        e[0] = low
        e[31] = high
        return e
    }

    /// p - 2 = 2^255 - 21 (inversion by Fermat's little theorem).
    static let pMinus2 = exponent(low: 0xeb, high: 0x7f)
    /// (p - 5) / 8 = 2^252 - 3 (RFC 8032 §5.1.3 step 2).
    static let pMinus5Over8 = exponent(low: 0xfd, high: 0x0f)
    /// (p - 1) / 4 = 2^253 - 5.
    static let pMinus1Over4 = exponent(low: 0xfb, high: 0x1f)

    var inverted: FieldElement { power(Self.pMinus2) }

    /// sqrt(-1) = 2^((p-1)/4) mod p (RFC 8032 §5.1.3 step 3).
    static let sqrtMinusOne = FieldElement(small: 2).power(pMinus1Over4)

    /// d = -121665 / 121666 (RFC 8032 §5.1).
    static let d = -FieldElement(small: 121_665) * FieldElement(small: 121_666).inverted
}
