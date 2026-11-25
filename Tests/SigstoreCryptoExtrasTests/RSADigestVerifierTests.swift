import Foundation
@testable import SigstoreCryptoExtras
import Testing

private struct RSAFile: Decodable {
    struct Key: Decodable {
        let name: String
        let bits: Int
        let n: String
        let e: Int
        let pkcs1: String
    }

    struct Case: Decodable {
        let name: String
        let key: String
        let scheme: String
        let hash: String
        let digest: String
        let signature: String
        let saltLength: Int?
        let valid: Bool
        let goValid: Bool?
        let note: String?
    }

    let keys: [Key]
    let tests: [Case]
}

private func hash(_ name: String) -> RSADigestVerifier.Hash {
    switch name {
    case "sha256": .sha256
    case "sha384": .sha384
    case "sha512": .sha512
    default: fatalError("unknown hash \(name)")
    }
}

private func exponentBytes(_ e: Int) -> [UInt8] {
    var b = withUnsafeBytes(of: UInt64(e).bigEndian, Array.init)
    while b.first == 0 { b.removeFirst() }
    return b
}

@Suite struct RSADigestVerifierTests {
    private static func loadKeys() throws -> (RSAFile, [String: RSAPublicKeyComponents]) {
        let file = try Vectors.load("rsa", as: RSAFile.self)
        var keys: [String: RSAPublicKeyComponents] = [:]
        for k in file.keys {
            let fromDER = try RSAPublicKeyComponents(pkcs1DER: [UInt8](hex: k.pkcs1))
            let fromParts = try RSAPublicKeyComponents(modulus: [UInt8](hex: k.n), exponent: exponentBytes(k.e))
            #expect(fromDER.modulus == fromParts.modulus && fromDER.exponent == k.e, "\(k.name)")
            #expect(fromDER.bitLength == k.bits, "\(k.name)")
            keys[k.name] = fromDER
        }
        return (file, keys)
    }

    @Test func goVectors() throws {
        let (file, keys) = try Self.loadKeys()
        #expect(file.tests.count >= 400)
        var valid = 0
        for c in file.tests {
            let key = try #require(keys[c.key])
            let sig = [UInt8](hex: c.signature)
            let digest = [UInt8](hex: c.digest)
            let got: Bool
            switch c.scheme {
            case "pkcs1v15":
                got = RSADigestVerifier.isValidPKCS1v15(sig, digest: digest, hash: hash(c.hash), key: key)
            case "pss":
                got = RSADigestVerifier.isValidPSS(sig, digest: digest, hash: hash(c.hash), key: key, saltLength: c.saltLength)
            default:
                Issue.record("unknown scheme \(c.scheme)")
                continue
            }
            #expect(got == c.valid, "\(c.name)")
            if let goValid = c.goValid, c.note == nil {
                #expect(goValid == c.valid, "\(c.name): vector disagrees with Go without a note")
            }
            if c.valid { valid += 1 }
        }
        #expect(valid >= 80)
    }

    @Test func keyValidation() throws {
        let (file, _) = try Self.loadKeys()
        let n2048 = [UInt8](hex: try #require(file.keys.first { $0.name == "rsa2048" }).n)
        let f4 = exponentBytes(65537)
        // Leading zero bytes are ignored.
        #expect(try RSAPublicKeyComponents(modulus: [0, 0] + n2048, exponent: [0] + f4).bitLength == 2048)

        // Even modulus (Go: "public modulus is even").
        var even = n2048
        even[even.count - 1] &= 0xfe
        #expect(throws: RSAPublicKeyComponents.Error.modulusEven) {
            try RSAPublicKeyComponents(modulus: even, exponent: f4)
        }
        // Below 1024 bits (Go's rsa1024min default).
        #expect(throws: RSAPublicKeyComponents.Error.modulusTooSmall(bits: 1016)) {
            try RSAPublicKeyComponents(modulus: Array(n2048[0..<127]), exponent: f4)
        }
        #expect(throws: RSAPublicKeyComponents.Error.modulusTooSmall(bits: 1023)) {
            try RSAPublicKeyComponents(modulus: [0x7f] + [UInt8](repeating: 0xff, count: 127), exponent: f4)
        }
        #expect(throws: RSAPublicKeyComponents.Error.modulusTooSmall(bits: 0)) {
            try RSAPublicKeyComponents(modulus: [], exponent: f4)
        }
        #expect(throws: RSAPublicKeyComponents.Error.modulusTooSmall(bits: 0)) {
            try RSAPublicKeyComponents(modulus: [0, 0, 0], exponent: f4)
        }
        // 1024 bits exactly is accepted.
        #expect(try RSAPublicKeyComponents(modulus: [UInt8](repeating: 0xff, count: 128), exponent: f4).bitLength == 1024)
        // Above the 16384-bit cap.
        #expect(throws: RSAPublicKeyComponents.Error.modulusTooLarge(bits: 16385)) {
            try RSAPublicKeyComponents(modulus: [1] + [UInt8](repeating: 0xff, count: 2048), exponent: f4)
        }
        // Exponents: < 3, even, > 2^31 - 1.
        for e: [UInt8] in [[], [0], [1], [0, 1], [2]] {
            #expect(throws: RSAPublicKeyComponents.Error.exponentTooSmall) {
                try RSAPublicKeyComponents(modulus: n2048, exponent: e)
            }
        }
        for e: [UInt8] in [[4], [1, 0, 0], [0x7f, 0xff, 0xff, 0xfe]] {
            #expect(throws: RSAPublicKeyComponents.Error.exponentEven) {
                try RSAPublicKeyComponents(modulus: n2048, exponent: e)
            }
        }
        for e: [UInt8] in [[0x80, 0, 0, 1], [0xff, 0xff, 0xff, 0xff], [1, 0, 0, 0, 1]] {
            #expect(throws: RSAPublicKeyComponents.Error.exponentTooLarge) {
                try RSAPublicKeyComponents(modulus: n2048, exponent: e)
            }
        }
        #expect(try RSAPublicKeyComponents(modulus: n2048, exponent: [3]).exponent == 3)
        #expect(try RSAPublicKeyComponents(modulus: n2048, exponent: [0x7f, 0xff, 0xff, 0xff]).exponent == Int(Int32.max))
    }

    @Test func strictDER() throws {
        let (file, _) = try Self.loadKeys()
        let der = [UInt8](hex: try #require(file.keys.first { $0.name == "rsa2048" }).pkcs1)
        // 30 82 01 0a | 02 82 01 01 00 <n: 256 bytes> | 02 03 01 00 01
        #expect(der.count == 270)
        _ = try RSAPublicKeyComponents(pkcs1DER: der)
        _ = try RSAPublicKeyComponents(pkcs1DER: Data(der))

        func rejects(_ bytes: [UInt8], _ comment: Comment) {
            #expect(throws: RSAPublicKeyComponents.Error.self, comment) {
                try RSAPublicKeyComponents(pkcs1DER: bytes)
            }
        }
        rejects([], "empty")
        rejects(der + [0], "trailing data after the SEQUENCE")
        rejects(Array(der.dropLast()), "truncated")
        rejects([0x31] + der.dropFirst(), "SET instead of SEQUENCE")
        var badIntTag = der
        badIntTag[4] = 0x03
        rejects(badIntTag, "BIT STRING instead of INTEGER")
        // Indefinite length.
        rejects([0x30, 0x80] + der[4...] + [0, 0], "indefinite length")
        // Non-minimal long-form length: 30 83 00 01 0a.
        rejects([0x30, 0x83, 0x00, 0x01, 0x0a] + der[4...], "length with leading zero")
        // Long form for a short length: 02 81 03 01 00 01.
        let n = Array(der[4..<265])
        let shortLong: [UInt8] = [0x02, 0x81, 0x03, 0x01, 0x00, 0x01]
        rejects([0x30, 0x82, 0x01, 0x0b] + n + shortLong, "long form for length < 128")
        // Non-minimal INTEGER: exponent 02 04 00 01 00 01.
        rejects([0x30, 0x82, 0x01, 0x0b] + n + [0x02, 0x04, 0x00, 0x01, 0x00, 0x01], "non-minimal INTEGER")
        // Negative exponent: 02 01 ff and 02 03 ff 00 01.
        rejects([0x30, 0x82, 0x01, 0x08] + n + [0x02, 0x01, 0xff], "negative INTEGER")
        rejects([0x30, 0x82, 0x01, 0x0a] + n + [0x02, 0x03, 0xff, 0x00, 0x01], "negative INTEGER")
        // Empty INTEGER.
        rejects([0x30, 0x82, 0x01, 0x07] + n + [0x02, 0x00], "empty INTEGER")
        // Missing exponent / extra element inside the SEQUENCE.
        rejects([0x30, 0x82, 0x01, 0x05] + n, "missing exponent")
        rejects([0x30, 0x82, 0x01, 0x0c] + der[4...] + [0x05, 0x00], "extra element")
        // Modulus without its sign octet would be negative: 02 82 01 00 <n>.
        rejects([0x30, 0x82, 0x01, 0x09, 0x02, 0x82, 0x01, 0x00] + der[9..<265] + [0x02, 0x03, 0x01, 0x00, 0x01],
                "negative modulus")
        // Too many length octets.
        rejects([0x30, 0x85, 0, 0, 0, 1, 0x0a] + der[4...], "five length octets")
        // Rebuilding the valid encoding by hand parses (sanity for the cases above).
        _ = try RSAPublicKeyComponents(pkcs1DER: [0x30, 0x82, 0x01, 0x0a] + n + [0x02, 0x03, 0x01, 0x00, 0x01])
    }

    @Test func malformedInputsReturnFalse() throws {
        let (file, keys) = try Self.loadKeys()
        let key = try #require(keys["rsa2048"])
        let valid = try #require(file.tests.first { $0.name == "rsa2048 sha256 pkcs1v15 valid" })
        let sig = [UInt8](hex: valid.signature)
        let digest = [UInt8](hex: valid.digest)
        #expect(RSADigestVerifier.isValidPKCS1v15(sig, digest: digest, hash: .sha256, key: key))
        #expect(RSADigestVerifier.isValidPKCS1v15(Data(sig), digest: Data(digest), hash: .sha256, key: key))

        for h in RSADigestVerifier.Hash.allCases {
            // Empty, short and over-long signatures; leading zero padding.
            for s in [[], [0], Array(sig.dropFirst()), [0] + sig, sig + sig] as [[UInt8]] {
                #expect(!RSADigestVerifier.isValidPKCS1v15(s, digest: digest, hash: h, key: key))
                #expect(!RSADigestVerifier.isValidPSS(s, digest: digest, hash: h, key: key, saltLength: nil))
            }
            // Digest of the wrong length.
            for d in [[], Array(digest.dropLast()), digest + [0], [UInt8](repeating: 0, count: 1000)] as [[UInt8]] {
                #expect(!RSADigestVerifier.isValidPKCS1v15(sig, digest: d, hash: h, key: key))
                #expect(!RSADigestVerifier.isValidPSS(sig, digest: d, hash: h, key: key, saltLength: nil))
            }
            // Out-of-range salt lengths.
            for salt in [-1, Int.min, Int.max, 256, 1000] {
                #expect(!RSADigestVerifier.isValidPSS(sig, digest: digest, hash: h, key: key, saltLength: salt))
            }
        }
        // s = n - 1 is in range but produces garbage; s = 1 gives m = 1.
        var nMinus1 = key.modulus
        nMinus1[nMinus1.count - 1] -= 1
        var one = [UInt8](repeating: 0, count: 256)
        one[255] = 1
        for s in [nMinus1, one] {
            #expect(!RSADigestVerifier.isValidPKCS1v15(s, digest: digest, hash: .sha256, key: key))
            #expect(!RSADigestVerifier.isValidPSS(s, digest: digest, hash: .sha256, key: key, saltLength: nil))
            #expect(!RSADigestVerifier.isValidPSS(s, digest: digest, hash: .sha256, key: key, saltLength: 0))
        }
    }

    @Test func randomSignaturesNeverTrap() throws {
        let (_, keys) = try Self.loadKeys()
        var rng = XorShift(state: 0x0123_4567_89ab_cdef)
        for name in ["rsa2048", "rsa2049", "rsa3072"] {
            let key = try #require(keys[name])
            let k = (key.bitLength + 7) / 8
            for _ in 0..<10 {
                let sig = rng.bytes(k)
                for h in RSADigestVerifier.Hash.allCases {
                    let d = rng.bytes(h.digestLength)
                    #expect(!RSADigestVerifier.isValidPKCS1v15(sig, digest: d, hash: h, key: key))
                    #expect(!RSADigestVerifier.isValidPSS(sig, digest: d, hash: h, key: key, saltLength: nil))
                    #expect(!RSADigestVerifier.isValidPSS(sig, digest: d, hash: h, key: key, saltLength: h.digestLength))
                }
            }
        }
    }

    @Test func modularExponentiation() {
        // 3^65537 mod 1000003 (odd modulus, single limb) = pow(3, 65537, 1000003).
        let ctx = MontgomeryContext(modulus: [1_000_003])
        #expect(ctx.power([3], exponent: 65537) == [UInt64(Self.powmod(3, 65537, 1_000_003))])
        #expect(ctx.power([0], exponent: 3) == [0])
        #expect(ctx.power([1_000_002], exponent: 3) == [1_000_002]) // (-1)^3
        // Multi-limb: n = 2^128 - 159 (prime); (n - 1)^e = n - 1 for odd e.
        let n: [UInt64] = [UInt64.max - 158, UInt64.max]
        let c2 = MontgomeryContext(modulus: n)
        #expect(c2.power([UInt64.max - 159, UInt64.max], exponent: 65537) == [UInt64.max - 159, UInt64.max])
        #expect(c2.power([2, 0], exponent: 127) == [0, 1 << 63])
    }

    private static func powmod(_ b: UInt64, _ e: UInt64, _ m: UInt64) -> UInt64 {
        var result: UInt64 = 1, base = b % m, e = e
        while e > 0 {
            if e & 1 == 1 { result = result * base % m }
            base = base * base % m
            e >>= 1
        }
        return result
    }

    @Test func timing() throws {
        let (file, keys) = try Self.loadKeys()
        let key = try #require(keys["rsa4096"])
        let c = try #require(file.tests.first { $0.name == "rsa4096 sha512 pkcs1v15 valid" })
        let p = try #require(file.tests.first { $0.name == "rsa4096 sha512 pss salt hLen auto" })
        let sig = [UInt8](hex: c.signature), digest = [UInt8](hex: c.digest)
        let pssSig = [UInt8](hex: p.signature)
        let clock = ContinuousClock()
        let n = 10
        let pkcs = clock.measure {
            for _ in 0..<n { #expect(RSADigestVerifier.isValidPKCS1v15(sig, digest: digest, hash: .sha512, key: key)) }
        }
        let pss = clock.measure {
            for _ in 0..<n { #expect(RSADigestVerifier.isValidPSS(pssSig, digest: digest, hash: .sha512, key: key, saltLength: nil)) }
        }
        let keyInit = clock.measure {
            for _ in 0..<n { _ = try? RSAPublicKeyComponents(modulus: key.modulus, exponent: [1, 0, 1]) }
        }
        print("RSA-4096 PKCS#1 v1.5 verify: \(pkcs / n); PSS verify: \(pss / n); key init: \(keyInit / n)")
    }
}
