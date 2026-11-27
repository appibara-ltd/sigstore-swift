import Foundation
import Testing

@testable import SigstoreMLDSA

// MARK: - Vector loading

struct VectorCase: Decodable, CustomTestStringConvertible {
    let name: String
    let pk: String?
    let msg: String
    let ctx: String
    let sig: String
    let valid: Bool
    var parameterSet = ""
    var groupPublicKey: String?
    var source = ""

    enum CodingKeys: String, CodingKey { case name, pk, msg, ctx, sig, valid }

    var testDescription: String { "\(source) \(parameterSet): \(name)" }
}

struct VectorGroup: Decodable {
    let parameterSet: String
    let publicKey: String?
    let cases: [VectorCase]
}

struct VectorFile: Decodable {
    let source: String
    let groups: [VectorGroup]
}

struct ShakeCase: Decodable {
    let function: String
    let input: String
    let output: String
}

func vectorData(_ name: String) throws -> Data {
    try EmbeddedTestData.data("Vectors/\(name).json")
}

/// Empty when the file is missing or malformed; tests assert the case counts.
func loadCases(_ file: String) -> [VectorCase] {
    guard let data = try? vectorData(file),
        let vf = try? JSONDecoder().decode(VectorFile.self, from: data)
    else { return [] }
    return vf.groups.flatMap { g in
        g.cases.map { c in
            var c = c
            c.parameterSet = g.parameterSet
            c.groupPublicKey = g.publicKey
            c.source = file
            return c
        }
    }
}

func hex(_ s: String) -> [UInt8] {
    var out: [UInt8] = []
    out.reserveCapacity(s.count / 2)
    var it = s.utf8.makeIterator()
    func nibble(_ c: UInt8) -> UInt8 {
        switch c {
        case 48...57: c - 48
        case 97...102: c - 87
        case 65...70: c - 55
        default: fatalError("bad hex")
        }
    }
    while let hi = it.next(), let lo = it.next() {
        out.append(nibble(hi) << 4 | nibble(lo))
    }
    return out
}

func parameterSet(named name: String) -> MLDSAParameterSet {
    switch name {
    case "ML-DSA-44": .mlDSA44
    case "ML-DSA-65": .mlDSA65
    case "ML-DSA-87": .mlDSA87
    default: fatalError("unknown parameter set \(name)")
    }
}

let goCases = loadCases("go-mldsa")
let acvpCases = loadCases("acvp-mldsa-sigver-pure")

func check(_ c: VectorCase) throws {
    let ps = parameterSet(named: c.parameterSet)
    let pkHex = try #require(c.pk ?? c.groupPublicKey)
    let pk = try MLDSAPublicKey(rawRepresentation: hex(pkHex), parameterSet: ps)
    let msg = hex(c.msg)
    let ctx = hex(c.ctx)
    let sig = hex(c.sig)
    #expect(pk.isValidSignature(sig, for: msg, context: ctx) == c.valid)
    if ctx.isEmpty {
        #expect(pk.isValidSignature(sig, for: msg) == c.valid)
    }
    // Non-contiguous DataProtocol input must give the same verdict.
    let msgData = DispatchData.from(msg)
    #expect(pk.isValidSignature(Data(sig), for: msgData, context: Data(ctx)) == c.valid)
}

extension DispatchData {
    /// Splits `bytes` over two regions to exercise multi-region absorption.
    static func from(_ bytes: [UInt8]) -> DispatchData {
        var d = DispatchData.empty
        let mid = bytes.count / 2
        bytes[..<mid].withUnsafeBytes { d.append($0) }
        bytes[mid...].withUnsafeBytes { d.append($0) }
        return d
    }
}

// MARK: - Known-answer vectors

@Suite struct MLDSAVectorTests {
    @Test func vectorFilesLoad() {
        // Go: 24 cases per parameter set; ACVP: 15 pure external per set.
        #expect(goCases.count == 3 * 24)
        #expect(acvpCases.count == 3 * 15)
        for ps in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] {
            #expect(goCases.contains { $0.parameterSet == ps && $0.valid })
            #expect(goCases.contains { $0.parameterSet == ps && !$0.valid })
            #expect(acvpCases.contains { $0.parameterSet == ps && $0.valid })
        }
    }

    @Test(arguments: goCases) func goVector(_ c: VectorCase) throws {
        try check(c)
    }

    @Test(arguments: acvpCases) func acvpVector(_ c: VectorCase) throws {
        try check(c)
    }
}

// MARK: - SHAKE

@Suite struct SHAKETests {
    @Test func emptyInputKnownAnswers() {
        // FIPS 202 / NIST example values for the empty message.
        #expect(SHAKE128.hash([UInt8](), outputLength: 32)
            == hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"))
        #expect(SHAKE256.hash([UInt8](), outputLength: 64) == hex(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
                + "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"))
    }

    @Test func goCrossCheck() throws {
        let cases = try JSONDecoder().decode([ShakeCase].self, from: vectorData("go-shake"))
        #expect(cases.count == 60)
        for c in cases {
            let input = hex(c.input)
            let expected = hex(c.output)
            let got = c.function == "SHAKE128"
                ? SHAKE128.hash(input, outputLength: expected.count)
                : SHAKE256.hash(input, outputLength: expected.count)
            #expect(got == expected, "\(c.function) in=\(input.count) out=\(expected.count)")
        }
    }

    @Test func incrementalMatchesOneShot() {
        let input = (0..<600).map { UInt8(truncatingIfNeeded: $0 &* 7) }
        let oneShot = SHAKE256.hash(input, outputLength: 700)
        var h = SHAKE256()
        h.update(Array(input[..<1]))
        h.update(Array(input[1..<137]))
        h.update(Array(input[137...]))
        var out: [UInt8] = []
        for n in [1, 135, 1, 300, 263] {
            out += h.squeeze(count: n)
        }
        #expect(out == oneShot)
    }
}

// MARK: - Malformed input

@Suite struct MLDSAMalformedInputTests {
    func validCase(_ ps: String) throws -> (MLDSAPublicKey, [UInt8], [UInt8], [UInt8]) {
        let c = try #require(goCases.first { $0.parameterSet == ps && $0.valid && !$0.ctx.isEmpty })
        let pk = try MLDSAPublicKey(
            rawRepresentation: hex(try #require(c.groupPublicKey)), parameterSet: parameterSet(named: ps))
        return (pk, hex(c.sig), hex(c.msg), hex(c.ctx))
    }

    @Test(arguments: MLDSAParameterSet.allCases) func publicKeyLength(_ ps: MLDSAParameterSet) throws {
        let n = ps.publicKeySize
        for bad in [0, 1, n - 1, n + 1] {
            #expect(throws: MLDSAError.invalidPublicKeyLength(parameterSet: ps, expected: n, actual: bad)) {
                try MLDSAPublicKey(rawRepresentation: [UInt8](repeating: 0, count: bad), parameterSet: ps)
            }
        }
        let pk = try MLDSAPublicKey(rawRepresentation: [UInt8](repeating: 7, count: n), parameterSet: ps)
        #expect(pk.rawRepresentation == Data(repeating: 7, count: n))
        #expect(pk.parameterSet == ps)
    }

    @Test func sizesMatchFIPS204Table2() {
        #expect(MLDSAParameterSet.mlDSA44.publicKeySize == 1312)
        #expect(MLDSAParameterSet.mlDSA65.publicKeySize == 1952)
        #expect(MLDSAParameterSet.mlDSA87.publicKeySize == 2592)
        #expect(MLDSAParameterSet.mlDSA44.signatureSize == 2420)
        #expect(MLDSAParameterSet.mlDSA65.signatureSize == 3309)
        #expect(MLDSAParameterSet.mlDSA87.signatureSize == 4627)
    }

    @Test(arguments: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]) func contextTooLong(_ ps: String) throws {
        let (pk, sig, msg, _) = try validCase(ps)
        // A 256-byte context is rejected outright (Algorithm 3 step 1), even
        // when its first 255 bytes would match.
        #expect(!pk.isValidSignature(sig, for: msg, context: [UInt8](repeating: 0, count: 256)))
        #expect(!pk.isValidSignature(sig, for: msg, context: [UInt8](repeating: 0, count: 10_000)))
    }

    @Test(arguments: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]) func wrongLengthsAndGarbage(_ ps: String) throws {
        let (pk, sig, msg, ctx) = try validCase(ps)
        #expect(pk.isValidSignature(sig, for: msg, context: ctx))
        let n = sig.count
        for len in [0, 1, n - 1, n + 1, 2 * n] {
            #expect(!pk.isValidSignature([UInt8](repeating: 0, count: len), for: msg, context: ctx))
        }
        // Wrong parameter set: another set's valid signature has the wrong length.
        for other in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] where other != ps {
            let (_, otherSig, _, _) = try validCase(other)
            #expect(!pk.isValidSignature(otherSig, for: msg, context: ctx))
        }
        #expect(!pk.isValidSignature([UInt8](repeating: 0xFF, count: n), for: msg, context: ctx))
        var rng = SplitMix64(seed: 0x5157_5354_4F52_45)
        for _ in 0..<50 {
            let garbage = (0..<n).map { _ in UInt8(truncatingIfNeeded: rng.next()) }
            #expect(!pk.isValidSignature(garbage, for: msg, context: ctx))
            // Random bytes with a well-formed (empty) hint section reach the
            // full verification path.
            var shaped = garbage
            let p = pk.parameterSet.parameters
            for i in (n - p.omega - p.k)..<n { shaped[i] = 0 }
            #expect(!pk.isValidSignature(shaped, for: msg, context: ctx))
        }
        // A random public key of the right length is accepted but verifies nothing.
        let randomPK = try MLDSAPublicKey(
            rawRepresentation: (0..<pk.parameterSet.publicKeySize).map { _ in UInt8(truncatingIfNeeded: rng.next()) },
            parameterSet: pk.parameterSet)
        #expect(!randomPK.isValidSignature(sig, for: msg, context: ctx))
    }

    @Test(arguments: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]) func zBoundary(_ ps: String) throws {
        // Every coefficient value at and beyond ±(γ1 − β) must fail the norm
        // check; values just inside pass it (FIPS 204 Algorithm 8 step 13).
        let p = parameterSet(named: ps).parameters
        let bound = p.gamma1 - p.beta
        var z = [[Int64]](repeating: [Int64](repeating: 0, count: 256), count: p.l)
        #expect(infinityNormBelow(z, bound))
        for v in [bound - 1, -(bound - 1)] {
            z[p.l - 1][255] = v
            #expect(infinityNormBelow(z, bound))
        }
        for v in [bound, -bound, p.gamma1, -p.gamma1 + 1] {
            z[p.l - 1][255] = v
            #expect(!infinityNormBelow(z, bound))
        }
        // And via sigDecode: an all-zero z field decodes to γ1.
        let (pk, sig, msg, ctx) = try validCase(ps)
        var bad = sig
        let off = p.cTildeLength + 32 * p.zBits * (p.l - 1)
        for i in off..<(off + 32 * p.zBits) { bad[i] = 0 }
        let decoded = try #require(sigDecode(bad, p))
        #expect(decoded.z[p.l - 1].allSatisfy { $0 == p.gamma1 })
        #expect(!pk.isValidSignature(bad, for: msg, context: ctx))
    }
}

// MARK: - HintBitUnpack (FIPS 204 Algorithm 21)

@Suite struct HintBitUnpackTests {
    let p = MLDSAParameters.mlDSA44  // ω = 80, k = 4

    func encode(_ positions: [[UInt8]]) -> [UInt8] {
        var y = [UInt8](repeating: 0, count: p.omega + p.k)
        var idx = 0
        for (i, poly) in positions.enumerated() {
            for pos in poly {
                y[idx] = pos
                idx += 1
            }
            y[p.omega + i] = UInt8(idx)
        }
        return y
    }

    @Test func wellFormed() throws {
        let y = encode([[0, 5, 255], [], [1], [2, 3]])
        let h = try #require(hintBitUnpack(y, p))
        #expect(h[0].indices.filter { h[0][$0] } == [0, 5, 255])
        #expect(h[1].allSatisfy { !$0 })
        #expect(h[2].indices.filter { h[2][$0] } == [1])
        #expect(h[3].indices.filter { h[3][$0] } == [2, 3])
        #expect(hintBitUnpack(encode([[], [], [], []]), p) != nil)
        // Exactly ω hints is allowed.
        let full = (0..<4).map { i in (0..<20).map { UInt8($0 + i) } }
        #expect(hintBitUnpack(encode(full), p) != nil)
    }

    @Test func indicesMayRestartAcrossPolynomials() {
        // Ordering is only required within one polynomial.
        #expect(hintBitUnpack(encode([[200], [100], [100], [0]]), p) != nil)
    }

    @Test func rejectsCountAboveOmega() {
        var y = encode([[], [], [], []])
        y[p.omega + 3] = UInt8(p.omega + 1)
        #expect(hintBitUnpack(y, p) == nil)
        y[p.omega + 3] = 0xFF
        #expect(hintBitUnpack(y, p) == nil)
    }

    @Test func rejectsDecreasingCounts() {
        var y = encode([[1, 2], [3], [], []])
        y[p.omega + 1] = 1  // count[1] < count[0] = 2
        #expect(hintBitUnpack(y, p) == nil)
    }

    @Test func rejectsRepeatedPosition() {
        #expect(hintBitUnpack(encode([[4, 4], [], [], []]), p) == nil)
    }

    @Test func rejectsDecreasingPosition() {
        #expect(hintBitUnpack(encode([[], [9, 8], [], []]), p) == nil)
    }

    @Test func rejectsNonZeroPadding() {
        var y = encode([[1], [], [], []])
        y[p.omega - 1] = 1
        #expect(hintBitUnpack(y, p) == nil)
        y = encode([[1], [], [], []])
        y[1] = 0x80  // first unused position byte
        #expect(hintBitUnpack(y, p) == nil)
    }

    @Test func rejectsWrongLength() {
        #expect(hintBitUnpack([UInt8](repeating: 0, count: p.omega + p.k - 1), p) == nil)
    }
}

// MARK: - Arithmetic

@Suite struct MLDSAArithmeticTests {
    @Test func zetas() {
        // FIPS 204 Appendix B: zetas[k] = ζ^BitRev8(k) mod q; zetas[1] = ζ^128,
        // zetas[2] = ζ^64. (zetas[0] is never used by Algorithms 41/42.)
        #expect(nttZetas[1] == 4_808_194)
        #expect(nttZetas[2] == 3_765_607)
        // ζ = 1753 is a primitive 512th root of unity: ζ^256 ≡ −1 (mod q).
        #expect(nttZetas[1] * nttZetas[1] % mldsaQ == mldsaQ - 1)
    }

    @Test func nttRoundTripAndMultiplication() {
        var rng = SplitMix64(seed: 42)
        let a: Poly = (0..<256).map { _ in Int64(rng.next() % UInt64(mldsaQ)) }
        let b: Poly = (0..<256).map { _ in Int64(rng.next() % UInt64(mldsaQ)) }
        var x = a
        ntt(&x)
        inverseNTT(&x)
        #expect(x == a)
        // NTT⁻¹(NTT(a) ∘ NTT(b)) equals negacyclic schoolbook multiplication.
        var ah = a, bh = b
        ntt(&ah)
        ntt(&bh)
        var prod = (0..<256).map { ah[$0] * bh[$0] % mldsaQ }
        inverseNTT(&prod)
        var expected = Poly(repeating: 0, count: 256)
        for i in 0..<256 {
            for j in 0..<256 {
                let t = a[i] * b[j] % mldsaQ
                if i + j < 256 {
                    expected[i + j] = (expected[i + j] + t) % mldsaQ
                } else {
                    expected[i + j - 256] = (expected[i + j - 256] - t + mldsaQ) % mldsaQ
                }
            }
        }
        #expect(prod == expected)
    }

    @Test(arguments: [MLDSAParameters.mlDSA44.gamma2, MLDSAParameters.mlDSA65.gamma2])
    func decomposeAndUseHint(_ gamma2: Int64) {
        let m = (mldsaQ - 1) / (2 * gamma2)
        var rng = SplitMix64(seed: UInt64(gamma2))
        let samples = [0, 1, gamma2, gamma2 + 1, mldsaQ - gamma2, mldsaQ - 2, mldsaQ - 1]
            + (0..<2000).map { _ in Int64(rng.next() % UInt64(mldsaQ)) }
        for r in samples {
            let (r1, r0) = decompose(r, gamma2: gamma2)
            #expect(r1 >= 0 && r1 < m)
            #expect(r0 >= -gamma2 && r0 <= gamma2)
            #expect(((r1 * 2 * gamma2 + r0) % mldsaQ + mldsaQ) % mldsaQ == r)
            #expect(useHint(false, r, gamma2: gamma2) == r1)
            let hinted = useHint(true, r, gamma2: gamma2)
            #expect(hinted == (r0 > 0 ? (r1 + 1) % m : (r1 - 1 + m) % m))
        }
        // Corner case of Algorithm 36: r = q − 1 gives r1 = 0, r0 = −1.
        #expect(decompose(mldsaQ - 1, gamma2: gamma2) == (0, -1))
    }

    @Test func sampleInBallShape() {
        for (tau, len) in [(39, 32), (49, 48), (60, 64)] {
            let c = sampleInBall([UInt8](repeating: 0xA5, count: len), tau: tau)
            #expect(c.filter { $0 != 0 }.count == tau)
            #expect(c.allSatisfy { $0 == 0 || $0 == 1 || $0 == mldsaQ - 1 })
        }
    }
}

// MARK: - Timing

@Suite struct MLDSATimingTests {
    @Test(arguments: ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]) func verifyTiming(_ ps: String) throws {
        let c = try #require(goCases.first { $0.parameterSet == ps && $0.valid })
        let pk = try MLDSAPublicKey(
            rawRepresentation: hex(try #require(c.groupPublicKey)), parameterSet: parameterSet(named: ps))
        let sig = hex(c.sig), msg = hex(c.msg), ctx = hex(c.ctx)
        let clock = ContinuousClock()
        let iterations = 5
        var ok = true
        let elapsed = clock.measure {
            for _ in 0..<iterations {
                ok = ok && pk.isValidSignature(sig, for: msg, context: ctx)
            }
        }
        #expect(ok)
        let perVerify = elapsed / iterations
        print("\(ps) verify: \(perVerify)")
        // Generous bound so slow CI machines do not flake.
        #expect(perVerify < .seconds(1))
    }
}

/// Small deterministic PRNG for test inputs.
struct SplitMix64: RandomNumberGenerator {
    var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
