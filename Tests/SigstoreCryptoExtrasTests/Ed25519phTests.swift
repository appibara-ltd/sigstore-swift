import Crypto
import Foundation
@testable import SigstoreCryptoExtras
import Testing

private struct EdFile: Decodable {
    struct Case: Decodable {
        let name: String
        let publicKey: String
        let message: String?
        let prehash: String
        let context: String
        let signature: String
        let valid: Bool
        let goValid: Bool
        let note: String?
    }

    let tests: [Case]
}

@Suite struct Ed25519phTests {
    // RFC 8032 §7.3, "TEST abc" (Ed25519ph), verbatim.
    static let rfcPublicKey = [UInt8](hex: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
    static let rfcMessage = [UInt8](hex: "616263")
    static let rfcSignature = [UInt8](
        hex: "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
            + "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")

    @Test func rfc8032Section7_3() {
        let prehash = Array(SHA512.hash(data: Self.rfcMessage))
        #expect(Ed25519ph.isValidSignature(Self.rfcSignature, prehash: prehash, publicKey: Self.rfcPublicKey))
        #expect(Ed25519ph.isValidSignature(Self.rfcSignature, message: Self.rfcMessage, publicKey: Self.rfcPublicKey))
        #expect(Ed25519ph.isValidSignature(
            Data(Self.rfcSignature), prehash: Data(prehash), publicKey: Data(Self.rfcPublicKey), context: Data()))
        // Ed25519ph is not Ed25519: the same signature over the message as a
        // pure Ed25519 signature must not verify, and vice versa.
        let key = try? Curve25519.Signing.PublicKey(rawRepresentation: Self.rfcPublicKey)
        #expect(key?.isValidSignature(Self.rfcSignature, for: Self.rfcMessage) == false)
        // A non-empty context changes dom2.
        #expect(!Ed25519ph.isValidSignature(
            Self.rfcSignature, prehash: prehash, publicKey: Self.rfcPublicKey, context: [UInt8]("x".utf8)))
    }

    @Test func goVectors() throws {
        let file = try Vectors.load("ed25519ph", as: EdFile.self)
        #expect(file.tests.count >= 40)
        var valid = 0
        for c in file.tests {
            let sig = [UInt8](hex: c.signature)
            let pub = [UInt8](hex: c.publicKey)
            let ph = [UInt8](hex: c.prehash)
            let ctx = [UInt8](hex: c.context)
            let got = Ed25519ph.isValidSignature(sig, prehash: ph, publicKey: pub, context: ctx)
            #expect(got == c.valid, "\(c.name)")
            if c.note == nil {
                #expect(c.valid == c.goValid, "\(c.name): vector disagrees with Go without a note")
            }
            if let m = c.message {
                let msg = [UInt8](hex: m)
                #expect(Array(SHA512.hash(data: msg)) == ph, "\(c.name)")
                #expect(Ed25519ph.isValidSignature(sig, message: msg, publicKey: pub, context: ctx) == c.valid, "\(c.name)")
            }
            if ctx.isEmpty {
                #expect(Ed25519ph.isValidSignature(sig, prehash: ph, publicKey: pub) == c.valid, "\(c.name)")
            }
            if c.valid { valid += 1 }
        }
        #expect(valid >= 10)
    }

    @Test func malformedInputsReturnFalse() {
        let ph = Array(SHA512.hash(data: Self.rfcMessage))
        let sig = Self.rfcSignature
        let pub = Self.rfcPublicKey
        #expect(Ed25519ph.isValidSignature(sig, prehash: ph, publicKey: pub))
        // Lengths.
        #expect(!Ed25519ph.isValidSignature([UInt8](), prehash: ph, publicKey: pub))
        #expect(!Ed25519ph.isValidSignature(Array(sig.dropLast()), prehash: ph, publicKey: pub))
        #expect(!Ed25519ph.isValidSignature(sig + [0], prehash: ph, publicKey: pub))
        #expect(!Ed25519ph.isValidSignature(sig, prehash: [UInt8](), publicKey: pub))
        #expect(!Ed25519ph.isValidSignature(sig, prehash: Array(ph.dropLast()), publicKey: pub))
        #expect(!Ed25519ph.isValidSignature(sig, prehash: ph + [0], publicKey: pub))
        #expect(!Ed25519ph.isValidSignature(sig, prehash: Array(ph[0..<32]), publicKey: pub))
        #expect(!Ed25519ph.isValidSignature(sig, prehash: ph, publicKey: [UInt8]()))
        #expect(!Ed25519ph.isValidSignature(sig, prehash: ph, publicKey: Array(pub.dropLast())))
        #expect(!Ed25519ph.isValidSignature(sig, prehash: ph, publicKey: pub + [0]))
        // Context longer than 255 bytes (RFC 8032 §5.1).
        #expect(!Ed25519ph.isValidSignature(
            sig, prehash: ph, publicKey: pub, context: [UInt8](repeating: 1, count: 256)))
        // Extremes.
        let ones = [UInt8](repeating: 0xff, count: 64)
        #expect(!Ed25519ph.isValidSignature(ones, prehash: ph, publicKey: [UInt8](repeating: 0xff, count: 32)))
        #expect(!Ed25519ph.isValidSignature(ones, prehash: ph, publicKey: [UInt8](repeating: 0, count: 32)))
    }

    @Test func randomInputsNeverTrap() {
        var rng = XorShift(state: 0x9e37_79b9_7f4a_7c15)
        for _ in 0..<200 {
            let sig = rng.bytes(64)
            let pub = rng.bytes(32)
            let ph = rng.bytes(64)
            #expect(!Ed25519ph.isValidSignature(sig, prehash: ph, publicKey: pub))
            // Valid key, random signature.
            #expect(!Ed25519ph.isValidSignature(sig, prehash: ph, publicKey: Self.rfcPublicKey))
        }
    }

    @Test func nonCanonicalScalarRejected() {
        // S = L and S = 2^256 - 1 (RFC 8032 §5.1.7 step 1: S >= L fails).
        #expect(!Ed25519ph.isBelowOrder(Ed25519ph.orderLE))
        #expect(!Ed25519ph.isBelowOrder([UInt8](repeating: 0xff, count: 32)))
        var lMinus1 = Ed25519ph.orderLE
        lMinus1[0] -= 1
        #expect(Ed25519ph.isBelowOrder(lMinus1))
        #expect(Ed25519ph.isBelowOrder([UInt8](repeating: 0, count: 32)))
    }

    @Test func fieldAndCurveConstants() {
        // d (RFC 8032 §5.1), big endian
        // 52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3.
        #expect(FieldElement.d.bytes.reversed().hex
            == "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3")
        // sqrt(-1)^2 = -1.
        #expect(FieldElement.sqrtMinusOne.squared.equals(-FieldElement.one))
        // B round-trips and [L]B = O (B has order L).
        let base = EdwardsPoint.base
        #expect(base.encoded == [0x58] + [UInt8](repeating: 0x66, count: 31))
        let zero = [UInt8](repeating: 0, count: 32)
        let lb = EdwardsPoint.doubleScalarMultiply(Ed25519ph.orderLE, base, zero, base)
        #expect(lb.encoded == EdwardsPoint.identity.encoded)
        // Non-canonical field elements (y >= p) are rejected.
        var p = [UInt8](repeating: 0xff, count: 32)
        p[0] = 0xed
        p[31] = 0x7f
        #expect(FieldElement(canonicalBytes: p) == nil)
        p[0] = 0xec // p - 1
        #expect(FieldElement(canonicalBytes: p) != nil)
    }

    @Test func scalarReduction() {
        // (2^512 - 1) mod L, little endian (computed with Python integers).
        #expect(Ed25519ph.reduceModOrder([UInt8](repeating: 0xff, count: 64)).hex
            == "000f9c44e31106a447938568a71b0ed065bef517d273ecce3d9a307c1b419903")
        // (L + 5) mod L = 5, L mod L = 0.
        var lPlus5 = Ed25519ph.orderLE + [UInt8](repeating: 0, count: 32)
        lPlus5[0] += 5
        #expect(Ed25519ph.reduceModOrder(lPlus5) == [5] + [UInt8](repeating: 0, count: 31))
        #expect(Ed25519ph.reduceModOrder(Ed25519ph.orderLE + [UInt8](repeating: 0, count: 32))
            == [UInt8](repeating: 0, count: 32))
    }

    @Test func timing() {
        let ph = Array(SHA512.hash(data: Self.rfcMessage))
        let clock = ContinuousClock()
        let n = 20
        let elapsed = clock.measure {
            for _ in 0..<n {
                _ = Ed25519ph.isValidSignature(Self.rfcSignature, prehash: ph, publicKey: Self.rfcPublicKey)
            }
        }
        print("Ed25519ph verify: \(elapsed / n) per signature")
    }
}
