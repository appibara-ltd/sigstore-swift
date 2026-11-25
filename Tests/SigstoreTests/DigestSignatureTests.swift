import Crypto
import Foundation
import Sigstore
import Testing
import X509
import _CryptoExtras

/// Ed25519ph and RSA over a precomputed digest, through `SignatureVerifier`
/// (sigstore `ED25519phVerifier` / `RSAPKCS1v15Verifier` with `WithDigest`).
@Suite("Digest-only signatures")
struct DigestSignatureTests {
    // RFC 8032 §7.3 (Ed25519ph, message "abc").
    private let rfcKey = Hex.decode("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")!
    private let rfcSig = Hex.decode(
        "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")!

    private func ed25519Key() throws -> Certificate.PublicKey {
        Certificate.PublicKey(try Curve25519.Signing.PublicKey(rawRepresentation: rfcKey))
    }

    @Test func ed25519phVerifiesMessageAndDigest() throws {
        let v = try SignatureVerifier(publicKey: ed25519Key(), useED25519ph: true)
        #expect(v.isEd25519ph && !v.isEd25519)
        let msg = Data("abc".utf8)
        #expect(v.verify(signature: rfcSig, message: msg))
        #expect(try v.verify(signature: rfcSig, digest: Array(SHA512.hash(data: msg))))
        #expect(!v.verify(signature: rfcSig, message: Data("abd".utf8)))
        #expect(try !v.verify(signature: rfcSig, digest: Array(SHA512.hash(data: Data("abd".utf8)))))
        // A SHA-256-length digest is not an Ed25519ph prehash.
        #expect(throws: (any Error).self) { try v.verify(signature: rfcSig, digest: Array(SHA256.hash(data: msg))) }
    }

    @Test func pureEd25519DoesNotAcceptEd25519phSignatures() throws {
        let pure = try SignatureVerifier(publicKey: ed25519Key())
        #expect(pure.isEd25519)
        #expect(!pure.verify(signature: rfcSig, message: Data("abc".utf8)))
        // Go: plain ED25519Verifier cannot verify a bare digest.
        #expect(throws: (any Error).self) { try pure.verify(signature: rfcSig, digest: Array(repeating: 0, count: 64)) }
    }

    @Test(arguments: [HashFunc.sha256, .sha384, .sha512])
    func rsaPKCS1v15OverDigest(_ hash: HashFunc) throws {
        let sk = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let msg = Data("rsa digest message".utf8)
        let digest: [UInt8]
        let sig: _RSA.Signing.RSASignature
        switch hash {
        case .sha256:
            digest = Array(SHA256.hash(data: msg))
            sig = try sk.signature(for: SHA256.hash(data: msg), padding: .insecurePKCS1v1_5)
        case .sha384:
            digest = Array(SHA384.hash(data: msg))
            sig = try sk.signature(for: SHA384.hash(data: msg), padding: .insecurePKCS1v1_5)
        case .sha512:
            digest = Array(SHA512.hash(data: msg))
            sig = try sk.signature(for: SHA512.hash(data: msg), padding: .insecurePKCS1v1_5)
        }
        let v = try SignatureVerifier(publicKey: Certificate.PublicKey(sk.publicKey), hashFunction: hash)
        #expect(try v.verify(signature: sig.rawRepresentation, digest: digest))
        var other = digest
        other[0] ^= 1
        #expect(try !v.verify(signature: sig.rawRepresentation, digest: other))
        // A digest of another hash's length is rejected (ComputeDigestForVerifying).
        #expect(throws: (any Error).self) { try v.verify(signature: sig.rawRepresentation, digest: Array(repeating: 0, count: 20)) }
    }
}
