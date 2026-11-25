// Polynomial arithmetic in R_q = Z_q[X]/(X^256 + 1) for FIPS 204.
//
// Polynomials are 256 Int64 coefficients kept in [0, q). Products of two such
// values are < 2^46, so plain Int64 arithmetic never overflows.

typealias Poly = [Int64]

let polyZero: Poly = Poly(repeating: 0, count: 256)

/// zetas[m] = ζ^BitRev8(m) mod q with ζ = 1753 (FIPS 204 §7.5, Appendix B).
let nttZetas: [Int64] = {
    var zetas = [Int64](repeating: 0, count: 256)
    for m in 0..<256 {
        var rev = 0
        for bit in 0..<8 where m & (1 << bit) != 0 {
            rev |= 1 << (7 - bit)
        }
        var result: Int64 = 1
        var base: Int64 = 1753
        var e = rev
        while e > 0 {
            if e & 1 == 1 { result = result * base % mldsaQ }
            base = base * base % mldsaQ
            e >>= 1
        }
        zetas[m] = result
    }
    return zetas
}()

/// FIPS 204 Algorithm 41, NTT(w).
func ntt(_ w: inout Poly) {
    w.withUnsafeMutableBufferPointer { w in
        nttZetas.withUnsafeBufferPointer { zetas in
            var m = 0
            var len = 128
            while len >= 1 {
                var start = 0
                while start < 256 {
                    m += 1
                    let z = zetas[m]
                    for j in start..<(start + len) {
                        let t = z * w[j + len] % mldsaQ
                        w[j + len] = (w[j] - t + mldsaQ) % mldsaQ
                        w[j] = (w[j] + t) % mldsaQ
                    }
                    start += 2 * len
                }
                len /= 2
            }
        }
    }
}

/// FIPS 204 Algorithm 42, NTT⁻¹(ŵ).
func inverseNTT(_ w: inout Poly) {
    w.withUnsafeMutableBufferPointer { w in
        nttZetas.withUnsafeBufferPointer { zetas in
            var m = 256
            var len = 1
            while len < 256 {
                var start = 0
                while start < 256 {
                    m -= 1
                    let z = mldsaQ - zetas[m]  // −zetas[m] mod q
                    for j in start..<(start + len) {
                        let t = w[j]
                        w[j] = (t + w[j + len]) % mldsaQ
                        let diff = (t - w[j + len] + mldsaQ) % mldsaQ
                        w[j + len] = z * diff % mldsaQ
                    }
                    start += 2 * len
                }
                len *= 2
            }
            // f = 256^−1 mod q = 8347681.
            let f: Int64 = 8_347_681
            for j in 0..<256 {
                w[j] = f * w[j] % mldsaQ
            }
        }
    }
}

/// FIPS 204 Algorithm 36, Decompose(r) for r ∈ [0, q): returns (r1, r0) with
/// r ≡ r1·2γ2 + r0 (mod q) and r0 ∈ (−γ2, γ2] (or the q − 1 corner case).
func decompose(_ r: Int64, gamma2: Int64) -> (r1: Int64, r0: Int64) {
    // r0 ← r+ mod± (2γ2): the representative in (−γ2, γ2].
    var r0 = r % (2 * gamma2)
    if r0 > gamma2 { r0 -= 2 * gamma2 }
    if r - r0 == mldsaQ - 1 {
        return (0, r0 - 1)
    }
    return ((r - r0) / (2 * gamma2), r0)
}

/// FIPS 204 Algorithm 40, UseHint(h, r) for r ∈ [0, q), h ∈ {0, 1}.
func useHint(_ h: Bool, _ r: Int64, gamma2: Int64) -> Int64 {
    let m = (mldsaQ - 1) / (2 * gamma2)
    let (r1, r0) = decompose(r, gamma2: gamma2)
    guard h else { return r1 }
    if r0 > 0 {
        return (r1 + 1) % m
    }
    return (r1 - 1 + m) % m
}
