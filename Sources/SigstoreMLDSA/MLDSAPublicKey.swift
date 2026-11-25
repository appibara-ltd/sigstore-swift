import Foundation

/// Errors thrown by `SigstoreMLDSA`.
public enum MLDSAError: Error, Sendable, Equatable {
    /// The public-key encoding does not have the parameter set's length
    /// (FIPS 204 Table 2).
    case invalidPublicKeyLength(parameterSet: MLDSAParameterSet, expected: Int, actual: Int)
}

/// An ML-DSA public key (FIPS 204), verification only.
///
/// Stands in for Go's `crypto/mldsa` `PublicKey`: `init(rawRepresentation:parameterSet:)`
/// mirrors `NewPublicKey(params, encoding)` and `isValidSignature` mirrors
/// `Verify(pk, message, signature, &Options{Context: ...})`.
public struct MLDSAPublicKey: Sendable, Hashable {
    public let parameterSet: MLDSAParameterSet
    private let encoded: [UInt8]

    /// The FIPS 204 pkEncode bytes (Algorithm 22), as Go's `PublicKey.Bytes()`.
    public var rawRepresentation: Data { Data(encoded) }

    /// Creates a key from its FIPS 204 pkEncode bytes. Throws on wrong length;
    /// every correctly sized byte string is a valid encoding (pkDecode,
    /// Algorithm 23, has no failure cases).
    public init<D: DataProtocol>(rawRepresentation: D, parameterSet: MLDSAParameterSet) throws {
        let bytes = [UInt8](rawRepresentation)
        let expected = parameterSet.publicKeySize
        guard bytes.count == expected else {
            throw MLDSAError.invalidPublicKeyLength(
                parameterSet: parameterSet, expected: expected, actual: bytes.count)
        }
        self.parameterSet = parameterSet
        self.encoded = bytes
    }

    /// FIPS 204 Algorithm 3, ML-DSA.Verify(pk, M, σ, ctx) with an empty context.
    public func isValidSignature<S: DataProtocol, M: DataProtocol>(_ signature: S, for message: M) -> Bool {
        isValidSignature(signature, for: message, context: [UInt8]())
    }

    /// FIPS 204 Algorithm 3, ML-DSA.Verify(pk, M, σ, ctx) (pure ML-DSA).
    ///
    /// Returns false for a context longer than 255 bytes, a signature of the
    /// wrong length, a malformed hint encoding, or a signature that does not
    /// verify.
    public func isValidSignature<S: DataProtocol, M: DataProtocol, C: DataProtocol>(
        _ signature: S, for message: M, context: C
    ) -> Bool {
        // Algorithm 3 steps 1–3: |ctx| > 255 → error.
        let ctx = [UInt8](context)
        guard ctx.count <= 255 else { return false }
        let p = parameterSet.parameters
        // Check the length before copying an arbitrarily large input.
        guard signature.count == p.signatureLength else { return false }
        // Step 5: M′ ← IntegerToBytes(0, 1) ∥ IntegerToBytes(|ctx|, 1) ∥ ctx ∥ M.
        // M′ is only ever absorbed into H, so it is streamed rather than built.
        return verifyInternal(signature: [UInt8](signature), p) { h in
            h.update([0, UInt8(ctx.count)])
            h.update(ctx)
            h.update(message)
        }
    }

    /// FIPS 204 Algorithm 8, ML-DSA.Verify_internal(pk, M′, σ). `absorbMessage`
    /// absorbs M′ into H.
    func verifyInternal(
        signature: [UInt8], _ p: MLDSAParameters, absorbMessage: (inout SHAKE256) -> Void
    ) -> Bool {
        // Step 1: (ρ, t1) ← pkDecode(pk).
        let (rho, t1) = pkDecode(encoded, p)
        // Steps 2–4: (c̃, z, h) ← sigDecode(σ); if h = ⊥ return false.
        guard let sig = sigDecode(signature, p) else { return false }
        // Step 13 (first conjunct): ‖z‖∞ < γ1 − β. Checked early; the result
        // is the same as evaluating it last.
        guard infinityNormBelow(sig.z, p.gamma1 - p.beta) else { return false }

        // Step 6: tr ← H(pk, 64).
        let tr = SHAKE256.hash(encoded, outputLength: 64)
        // Step 7: μ ← H(BytesToBits(tr) ∥ M′, 64).
        var hMu = SHAKE256()
        hMu.update(tr)
        absorbMessage(&hMu)
        let mu = hMu.squeeze(count: 64)

        // Step 8: c ← SampleInBall(c̃); ĉ ← NTT(c).
        var cHat = sampleInBall(sig.cTilde, tau: p.tau)
        ntt(&cHat)
        // NTT(z), with z mapped into [0, q).
        let zHat: [Poly] = sig.z.map { zi in
            var poly = zi.map { $0 < 0 ? $0 + mldsaQ : $0 }
            ntt(&poly)
            return poly
        }

        // Steps 5 and 9: w′Approx ← NTT⁻¹(Â ∘ NTT(z) − NTT(c) ∘ NTT(t1 · 2^d)),
        // with Â ← ExpandA(ρ) generated row by row. Step 10: w1′ ← UseHint(h, w′Approx).
        var w1: [[Int64]] = []
        w1.reserveCapacity(p.k)
        for r in 0..<p.k {
            var acc = polyZero
            for s in 0..<p.l {
                let a = rejNTTPoly(rho + [UInt8(s), UInt8(r)])
                let zs = zHat[s]
                for i in 0..<256 {
                    acc[i] = (acc[i] + a[i] * zs[i]) % mldsaQ
                }
            }
            // t1 < 2^10, so t1 · 2^13 ≤ q − 1 needs no reduction.
            var t = t1[r].map { $0 << Int64(mldsaD) }
            ntt(&t)
            for i in 0..<256 {
                acc[i] = (acc[i] - cHat[i] * t[i] % mldsaQ + mldsaQ) % mldsaQ
            }
            inverseNTT(&acc)
            let hr = sig.h[r]
            w1.append((0..<256).map { useHint(hr[$0], acc[$0], gamma2: p.gamma2) })
        }

        // Step 12: c̃′ ← H(μ ∥ w1Encode(w1′), λ/4).
        var hC = SHAKE256()
        hC.update(mu)
        hC.update(w1Encode(w1, p))
        let cTildePrime = hC.squeeze(count: p.cTildeLength)
        // Step 13 (second conjunct): c̃ = c̃′.
        var diff: UInt8 = 0
        for (x, y) in zip(sig.cTilde, cTildePrime) { diff |= x ^ y }
        return diff == 0 && sig.cTilde.count == cTildePrime.count
    }
}

/// ‖z‖∞ < bound for z given as signed coefficients (FIPS 204 §2.3).
func infinityNormBelow(_ z: [[Int64]], _ bound: Int64) -> Bool {
    for poly in z {
        for c in poly where c >= bound || c <= -bound {
            return false
        }
    }
    return true
}

/// FIPS 204 Algorithm 29, SampleInBall(ρ): a polynomial with τ coefficients in
/// {−1, 1} (stored mod q) and the rest 0. ρ is the full c̃ (λ/4 bytes).
func sampleInBall(_ rho: [UInt8], tau: Int) -> Poly {
    var c = polyZero
    var h = SHAKE256()
    h.update(rho)
    // H.Squeeze is a single byte stream; reading it in rate-sized chunks
    // yields the same bytes as squeezing one byte at a time.
    var stream = h.squeeze(count: 136)
    var pos = 0
    func next() -> UInt8 {
        if pos == stream.count {
            stream = h.squeeze(count: 136)
            pos = 0
        }
        defer { pos += 1 }
        return stream[pos]
    }
    // Steps 3–4: s ← H.Squeeze(8); h ← BytesToBits(s).
    var signs: UInt64 = 0
    for i in 0..<8 {
        signs |= UInt64(next()) << UInt64(8 * i)
    }
    // Steps 5–12.
    for i in (256 - tau)..<256 {
        var j = Int(next())
        while j > i {
            j = Int(next())
        }
        c[i] = c[j]
        // c_j ← (−1)^h[i+τ−256].
        c[j] = (signs >> UInt64(i + tau - 256)) & 1 == 1 ? mldsaQ - 1 : 1
    }
    return c
}

/// FIPS 204 Algorithm 30, RejNTTPoly(ρ) for a 34-byte seed: a uniformly
/// random element of T_q by rejection sampling from G = SHAKE128.
func rejNTTPoly(_ rho: [UInt8]) -> Poly {
    var a = polyZero
    var g = SHAKE128()
    g.update(rho)
    var j = 0
    // Squeeze in multiples of the rate (168 = 56 · 3); the stream is identical
    // to the 3-byte squeezes of Algorithm 30.
    while j < 256 {
        let block = g.squeeze(count: 168 * 3)
        var k = 0
        while k < block.count, j < 256 {
            // Algorithm 14, CoeffFromThreeBytes: clear the top bit of b2.
            let z = Int64(block[k]) | Int64(block[k + 1]) << 8 | Int64(block[k + 2] & 0x7F) << 16
            if z < mldsaQ {
                a[j] = z
                j += 1
            }
            k += 3
        }
    }
    return a
}
