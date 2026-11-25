import Crypto
import Foundation

/// An RSA public key (n, e) validated the way Go's crypto/rsa validates keys
/// before verification (`checkPublicKey` in crypto/internal/fips140/rsa and
/// `checkKeySize` in crypto/rsa, Go 1.27):
/// - n odd ("public modulus is even");
/// - n at least 1024 bits (Go's default `rsa1024min=1`);
/// - e odd and >= 3 (Go: e >= 2 and odd), at most 2^31 - 1.
///
/// Additionally n is capped at 16384 bits to bound verification cost; Go has
/// no upper bound.
public struct RSAPublicKeyComponents: Sendable {
    public enum Error: Swift.Error, Sendable, Equatable {
        case modulusEven
        case modulusTooSmall(bits: Int)
        case modulusTooLarge(bits: Int)
        case exponentTooSmall
        case exponentEven
        case exponentTooLarge
        case malformedDER(String)
    }

    public static let minimumModulusBits = 1024
    public static let maximumModulusBits = 16384
    public static let maximumExponent = (1 << 31) - 1

    /// Big-endian modulus without leading zero bytes.
    public let modulus: [UInt8]
    public let exponent: Int
    public var bitLength: Int { BigUInt.bitLength(context.n) }
    /// Length of the modulus in bytes (k in RFC 8017).
    var modulusByteCount: Int { (bitLength + 7) / 8 }

    let context: MontgomeryContext

    /// `modulus` and `exponent` are unsigned big-endian integers; leading zero
    /// bytes are ignored.
    public init(modulus: [UInt8], exponent: [UInt8]) throws {
        let n = Array(modulus.drop(while: { $0 == 0 }))
        let e = Array(exponent.drop(while: { $0 == 0 }))

        let bits = n.isEmpty ? 0 : (n.count - 1) * 8 + (8 - n[0].leadingZeroBitCount)
        // Size checks first so the cost of what follows is bounded.
        guard bits <= Self.maximumModulusBits else { throw Error.modulusTooLarge(bits: bits) }
        guard bits >= Self.minimumModulusBits else { throw Error.modulusTooSmall(bits: bits) }
        guard n[n.count - 1] & 1 == 1 else { throw Error.modulusEven }

        guard e.count <= 4 else { throw Error.exponentTooLarge }
        let eValue = e.reduce(0) { $0 << 8 | Int($1) }
        guard eValue <= Self.maximumExponent else { throw Error.exponentTooLarge }
        guard eValue >= 3 else { throw Error.exponentTooSmall }
        guard eValue & 1 == 1 else { throw Error.exponentEven }

        guard let limbs = BigUInt.limbs(bigEndian: n) else { throw Error.modulusTooLarge(bits: bits) }
        self.modulus = n
        self.exponent = eValue
        self.context = MontgomeryContext(modulus: limbs)
    }

    /// Parses a DER `RSAPublicKey ::= SEQUENCE { modulus INTEGER,
    /// publicExponent INTEGER }` (RFC 8017 Appendix A.1.1) strictly:
    /// definite minimal lengths, minimal positive INTEGERs, no trailing data.
    public init(pkcs1DER: some DataProtocol) throws {
        var outer = DERReader(Array(pkcs1DER))
        var seq = try outer.read(tag: 0x30)
        guard outer.isAtEnd else { throw Error.malformedDER("trailing data after RSAPublicKey") }
        let n = try seq.readUnsignedInteger()
        let e = try seq.readUnsignedInteger()
        guard seq.isAtEnd else { throw Error.malformedDER("trailing data in RSAPublicKey") }
        try self.init(modulus: n, exponent: e)
    }

    /// s^e mod n as exactly k bytes (RSAVP1, RFC 8017 §5.2.2). Nil if
    /// s >= n ("signature representative out of range").
    func publicOperation(_ signature: [UInt8]) -> [UInt8]? {
        let n = context.n
        guard let s = BigUInt.limbs(bigEndian: signature, count: n.count),
              BigUInt.compare(s, n) < 0
        else { return nil }
        let m = context.power(s, exponent: UInt64(exponent))
        return BigUInt.bigEndian(m, count: modulusByteCount)
    }
}

/// RSA signature verification over a precomputed digest, mirroring Go's
/// `crypto/rsa.VerifyPKCS1v15` and `VerifyPSS` (Go 1.27). swift-crypto's
/// `_RSA.Signing.PublicKey` only accepts its own `Digest` values.
public enum RSADigestVerifier {
    public enum Hash: Sendable, CaseIterable {
        case sha256, sha384, sha512

        public var digestLength: Int {
            switch self {
            case .sha256: 32
            case .sha384: 48
            case .sha512: 64
            }
        }

        /// DER of DigestInfo up to the digest (RFC 8017 §9.2 note 1).
        var digestInfoPrefix: [UInt8] {
            switch self {
            case .sha256:
                [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
            case .sha384:
                [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
            case .sha512:
                [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
            }
        }

        func hash(_ parts: [UInt8]...) -> [UInt8] {
            switch self {
            case .sha256:
                var h = SHA256()
                for p in parts { h.update(data: p) }
                return Array(h.finalize())
            case .sha384:
                var h = SHA384()
                for p in parts { h.update(data: p) }
                return Array(h.finalize())
            case .sha512:
                var h = SHA512()
                for p in parts { h.update(data: p) }
                return Array(h.finalize())
            }
        }
    }

    /// RSASSA-PKCS1-v1_5 verification (RFC 8017 §8.2.2) with EMSA-PKCS1-v1_5
    /// encoding (§9.2) of a precomputed digest. Returns false on any
    /// malformed input.
    public static func isValidPKCS1v15(
        _ signature: some DataProtocol,
        digest: some DataProtocol,
        hash: Hash,
        key: RSAPublicKeyComponents
    ) -> Bool {
        let signature = Array(signature)
        let digest = Array(digest)
        let k = key.modulusByteCount
        // Go's VerifyPKCS1v15: "input must be hashed message".
        guard digest.count == hash.digestLength else { return false }

        // §8.2.2 step 1: length check.
        guard signature.count == k else { return false }

        // §8.2.2 step 2: s = OS2IP(S); m = RSAVP1((n, e), s) (fails if
        // s >= n); EM = I2OSP(m, k).
        guard let em = key.publicOperation(signature) else { return false }

        // §8.2.2 step 3 / §9.2: EM' = 0x00 || 0x01 || PS || 0x00 || T with
        // T = DigestInfo || H and PS at least 8 octets of 0xff (step 3:
        // "intended encoded message length too short" if k < tLen + 11).
        let t = hash.digestInfoPrefix + digest
        guard k >= t.count + 11 else { return false }
        var expected = [UInt8](repeating: 0xff, count: k)
        expected[0] = 0x00
        expected[1] = 0x01
        expected[k - t.count - 1] = 0x00
        expected.replaceSubrange((k - t.count)..<k, with: t)

        // §8.2.2 step 4: compare EM and EM'.
        return em == expected
    }

    /// RSASSA-PSS verification (RFC 8017 §8.1.2) with EMSA-PSS (§9.1.2) and
    /// MGF1 (§B.2.1) using `hash`, of a precomputed digest. `saltLength` nil
    /// auto-detects the salt length (Go's `PSSSaltLengthAuto`); otherwise it
    /// must match exactly. Returns false on any malformed input.
    public static func isValidPSS(
        _ signature: some DataProtocol,
        digest: some DataProtocol,
        hash: Hash,
        key: RSAPublicKeyComponents,
        saltLength: Int?
    ) -> Bool {
        let signature = Array(signature)
        let mHash = Array(digest)
        let k = key.modulusByteCount
        if let saltLength, saltLength < 0 { return false }

        // §8.1.2 step 1: length check.
        guard signature.count == k else { return false }

        // §8.1.2 step 2: m = RSAVP1((n, e), s); EM = I2OSP(m, emLen) with
        // emBits = modBits - 1. As in Go, compute k octets and strip leading
        // zeros down to emLen (emLen = k - 1 when modBits ≡ 1 mod 8); a
        // non-zero stripped octet means m does not fit and is invalid.
        guard var em = key.publicOperation(signature) else { return false }
        let emBits = key.bitLength - 1
        let emLen = (emBits + 7) / 8
        while em.count > emLen {
            guard em[0] == 0 else { return false }
            em.removeFirst()
        }

        return emsaPSSVerify(mHash: mHash, em: em, emBits: emBits, saltLength: saltLength, hash: hash)
    }

    /// EMSA-PSS-VERIFY (RFC 8017 §9.1.2) following Go's `emsaPSSVerify`.
    static func emsaPSSVerify(mHash: [UInt8], em: [UInt8], emBits: Int, saltLength: Int?, hash: Hash) -> Bool {
        let hLen = hash.digestLength
        let emLen = (emBits + 7) / 8
        guard em.count == emLen else { return false }
        // Bound the requested salt length before any arithmetic on it.
        if let saltLength, saltLength < 0 || saltLength > emLen { return false }

        // Steps 1-2: mHash is given; it must be hLen octets.
        guard mHash.count == hLen else { return false }

        // Step 3: emLen < hLen + sLen + 2 is "inconsistent". With an unknown
        // salt length, sLen >= 0 is required (Go passes sLen = -1 here and
        // fails later on an empty DB; the outcome is the same).
        guard emLen >= hLen + (saltLength ?? 0) + 2 else { return false }

        // Step 4: rightmost octet must be 0xbc.
        guard em[emLen - 1] == 0xbc else { return false }

        // Step 5: maskedDB = first emLen - hLen - 1 octets; H = next hLen.
        var db = Array(em[0..<(emLen - hLen - 1)])
        let h = Array(em[(emLen - hLen - 1)..<(emLen - 1)])

        // Step 6: the leftmost 8·emLen - emBits bits of maskedDB must be 0.
        let bitMask = UInt8(0xff) >> (8 * emLen - emBits)
        guard em[0] & ~bitMask == 0 else { return false }

        // Steps 7-8: DB = maskedDB XOR MGF1(H, emLen - hLen - 1).
        mgf1XOR(&db, seed: h, hash: hash)

        // Step 9: clear the leftmost 8·emLen - emBits bits of DB.
        db[0] &= bitMask

        // Auto-detect (Go's PSSSaltLengthAuto): the salt starts after the
        // first 0x01 octet.
        let sLen: Int
        if let saltLength {
            sLen = saltLength
        } else {
            guard let psLen = db.firstIndex(of: 0x01) else { return false }
            sLen = db.count - psLen - 1
        }

        // Step 10: the emLen - hLen - sLen - 2 leftmost octets of DB must be
        // zero, followed by 0x01.
        let psLen = emLen - hLen - sLen - 2
        guard psLen >= 0, psLen < db.count else { return false }
        guard db[0..<psLen].allSatisfy({ $0 == 0 }), db[psLen] == 0x01 else { return false }

        // Step 11: salt = last sLen octets of DB.
        let salt = Array(db[(db.count - sLen)...])

        // Steps 12-13: M' = 0x00 * 8 || mHash || salt; H' = Hash(M').
        let hPrime = hash.hash([UInt8](repeating: 0, count: 8), mHash, salt)

        // Step 14: H == H'.
        return h == hPrime
    }

    /// db ^= MGF1(seed, db.count) (RFC 8017 §B.2.1).
    static func mgf1XOR(_ db: inout [UInt8], seed: [UInt8], hash: Hash) {
        var done = 0
        var counter: UInt32 = 0
        while done < db.count {
            let c: [UInt8] = [
                UInt8(truncatingIfNeeded: counter >> 24), UInt8(truncatingIfNeeded: counter >> 16),
                UInt8(truncatingIfNeeded: counter >> 8), UInt8(truncatingIfNeeded: counter),
            ]
            for byte in hash.hash(seed, c) where done < db.count {
                db[done] ^= byte
                done += 1
            }
            counter &+= 1
        }
    }
}
