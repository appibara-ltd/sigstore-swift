// Minimal unsigned multi-precision arithmetic for public-key verification:
// big-endian conversion, comparison, generic reduction and Montgomery
// exponentiation modulo an odd modulus. Little-endian 64-bit limbs.
// Variable time; only used on public data. No operation can trap on any
// input the callers in this module pass.

enum BigUInt {
    typealias Limbs = [UInt64]

    /// Big-endian bytes to `count` little-endian limbs (count defaults to the
    /// minimum needed). Returns nil when the value does not fit.
    static func limbs(bigEndian bytes: [UInt8], count: Int? = nil) -> Limbs? {
        let needed = (bytes.count + 7) / 8
        let n = count ?? max(needed, 1)
        var out = Limbs(repeating: 0, count: n)
        for (i, byte) in bytes.reversed().enumerated() {
            let limb = i / 8
            if limb >= n {
                if byte != 0 { return nil }
                continue
            }
            out[limb] |= UInt64(byte) << (8 * (i % 8))
        }
        return out
    }

    /// Limbs to exactly `count` big-endian bytes; nil if the value is larger.
    static func bigEndian(_ a: Limbs, count: Int) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: count)
        for i in 0..<(a.count * 8) {
            let byte = UInt8(truncatingIfNeeded: a[i / 8] >> (8 * (i % 8)))
            if i < count {
                out[count - 1 - i] = byte
            } else if byte != 0 {
                return nil
            }
        }
        return out
    }

    static func bitLength(_ a: Limbs) -> Int {
        for i in stride(from: a.count - 1, through: 0, by: -1) where a[i] != 0 {
            return i * 64 + (64 - a[i].leadingZeroBitCount)
        }
        return 0
    }

    /// Compares a and b as numbers (lengths may differ).
    static func compare(_ a: Limbs, _ b: Limbs) -> Int {
        for i in stride(from: max(a.count, b.count) - 1, through: 0, by: -1) {
            let x = i < a.count ? a[i] : 0
            let y = i < b.count ? b[i] : 0
            if x != y { return x < y ? -1 : 1 }
        }
        return 0
    }

    /// a -= b in place, where a >= b and b.count <= a.count.
    static func subtract(_ a: inout Limbs, _ b: Limbs) {
        var borrow: UInt64 = 0
        for i in 0..<a.count {
            let y = i < b.count ? b[i] : 0
            let (d1, o1) = a[i].subtractingReportingOverflow(y)
            let (d2, o2) = d1.subtractingReportingOverflow(borrow)
            a[i] = d2
            borrow = (o1 ? 1 : 0) + (o2 ? 1 : 0)
        }
    }

    /// a mod m by binary long division (m non-zero). Result has m.count limbs.
    static func remainder(_ a: Limbs, _ m: Limbs) -> Limbs {
        // Internal invariant: callers pass a validated RSA modulus or the Ed25519 order, never zero.
        // nosemgrep: swift-trap-in-library
        precondition(bitLength(m) > 0, "modulus must be non-zero")
        // r stays < m, so r << 1 | bit < 2m fits in m.count + 1 limbs.
        var r = Limbs(repeating: 0, count: m.count + 1)
        for bit in stride(from: a.count * 64 - 1, through: 0, by: -1) {
            var carry = (a[bit / 64] >> (bit % 64)) & 1
            for i in 0..<r.count {
                let next = r[i] >> 63
                r[i] = (r[i] << 1) | carry
                carry = next
            }
            if compare(r, m) >= 0 { subtract(&r, m) }
        }
        return Array(r[0..<m.count])
    }
}

/// Precomputed values for Montgomery multiplication modulo an odd n.
struct MontgomeryContext: Sendable {
    let n: BigUInt.Limbs
    /// -n^-1 mod 2^64.
    let n0Inverse: UInt64
    /// R^2 mod n, R = 2^(64·n.count).
    let rSquared: BigUInt.Limbs

    /// n must be odd and normalized (top limb non-zero).
    init(modulus n: BigUInt.Limbs) {
        // Internal invariant: RSAPublicKeyComponents rejects even, empty and short moduli before this.
        // nosemgrep: swift-trap-in-library
        precondition(!n.isEmpty && n[0] & 1 == 1 && n[n.count - 1] != 0)
        self.n = n
        // Newton iteration for n0^-1 mod 2^64: each step doubles the number
        // of correct low bits; x = n0 is correct to 3 bits for odd n0.
        var x = n[0]
        for _ in 0..<5 { x = x &* (2 &- n[0] &* x) }
        n0Inverse = 0 &- x
        var r2 = BigUInt.Limbs(repeating: 0, count: 2 * n.count + 1)
        r2[2 * n.count] = 1
        rSquared = BigUInt.remainder(r2, n)
    }

    /// a · b · R^-1 mod n for a, b < n (CIOS Montgomery multiplication).
    func multiply(_ a: BigUInt.Limbs, _ b: BigUInt.Limbs) -> BigUInt.Limbs {
        let s = n.count
        var t = BigUInt.Limbs(repeating: 0, count: s + 2)
        for i in 0..<s {
            var c: UInt64 = 0
            let bi = UInt128(b[i])
            for j in 0..<s {
                // (2^64-1)^2 + 2(2^64-1) = 2^128 - 1: never overflows.
                let p = UInt128(a[j]) * bi + UInt128(t[j]) + UInt128(c)
                t[j] = UInt64(truncatingIfNeeded: p)
                c = UInt64(truncatingIfNeeded: p >> 64)
            }
            var sum = UInt128(t[s]) + UInt128(c)
            t[s] = UInt64(truncatingIfNeeded: sum)
            t[s + 1] = UInt64(truncatingIfNeeded: sum >> 64)

            let m = UInt128(t[0] &* n0Inverse)
            var p = m * UInt128(n[0]) + UInt128(t[0])
            c = UInt64(truncatingIfNeeded: p >> 64)
            for j in 1..<s {
                p = m * UInt128(n[j]) + UInt128(t[j]) + UInt128(c)
                t[j - 1] = UInt64(truncatingIfNeeded: p)
                c = UInt64(truncatingIfNeeded: p >> 64)
            }
            sum = UInt128(t[s]) + UInt128(c)
            t[s - 1] = UInt64(truncatingIfNeeded: sum)
            t[s] = t[s + 1] + UInt64(truncatingIfNeeded: sum >> 64)
            t[s + 1] = 0
        }
        var r = Array(t[0...s])
        if BigUInt.compare(r, n) >= 0 { BigUInt.subtract(&r, n) }
        return Array(r[0..<s])
    }

    /// base^e mod n for base < n and e >= 1.
    func power(_ base: BigUInt.Limbs, exponent e: UInt64) -> BigUInt.Limbs {
        // Internal invariant: callers pass a validated public exponent (>= 3).
        // nosemgrep: swift-trap-in-library
        precondition(e >= 1)
        let baseM = multiply(base, rSquared)
        var acc = baseM
        for bit in stride(from: 62 - e.leadingZeroBitCount, through: 0, by: -1) {
            acc = multiply(acc, acc)
            if (e >> UInt64(bit)) & 1 == 1 { acc = multiply(acc, baseM) }
        }
        var one = BigUInt.Limbs(repeating: 0, count: n.count)
        one[0] = 1
        return multiply(acc, one)
    }
}
