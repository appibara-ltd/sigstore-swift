import Crypto
import Foundation

/// A precomputed digest, so ECDSA can verify a signature over a digest we
/// did not compute (sigstore `options.WithDigest`). One type per size,
/// because swift-crypto's `Digest.byteCount` is static.
protocol PrehashedDigest: Digest {
    var bytes: [UInt8] { get }
}

extension PrehashedDigest {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }
    public func makeIterator() -> IndexingIterator<[UInt8]> { bytes.makeIterator() }
    public var description: String { "Prehashed digest: \(Hex.encode(bytes))" }
}

struct Prehashed256: PrehashedDigest {
    static let byteCount = 32
    let bytes: [UInt8]
}

struct Prehashed384: PrehashedDigest {
    static let byteCount = 48
    let bytes: [UInt8]
}

struct Prehashed512: PrehashedDigest {
    static let byteCount = 64
    let bytes: [UInt8]
}

extension SignatureVerifier {
    /// Verifies `signature` over a precomputed `digest` (sigstore
    /// `VerifySignature(..., options.WithDigest(digest))`). The digest length
    /// must match the verifier's hash function, as sigstore's
    /// `ComputeDigestForVerifying` requires. Only ECDSA is supported:
    /// Ed25519 cannot verify a bare digest, and swift-crypto's RSA only
    /// accepts its own digest types.
    public func verify<S: DataProtocol>(signature: S, digest: [UInt8]) throws -> Bool {
        guard digest.count == hashFunction.size else {
            throw SigstoreError("unexpected length of digest for hash function specified")
        }
        switch key {
        case .ecdsaP256(let k):
            guard let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature) else { return false }
            switch hashFunction {
            case .sha256: return k.isValidSignature(sig, for: Prehashed256(bytes: digest))
            case .sha384: return k.isValidSignature(sig, for: Prehashed384(bytes: digest))
            case .sha512: return k.isValidSignature(sig, for: Prehashed512(bytes: digest))
            }
        case .ecdsaP384(let k):
            guard let sig = try? P384.Signing.ECDSASignature(derRepresentation: signature) else { return false }
            switch hashFunction {
            case .sha256: return k.isValidSignature(sig, for: Prehashed256(bytes: digest))
            case .sha384: return k.isValidSignature(sig, for: Prehashed384(bytes: digest))
            case .sha512: return k.isValidSignature(sig, for: Prehashed512(bytes: digest))
            }
        case .ecdsaP521(let k):
            guard let sig = try? P521.Signing.ECDSASignature(derRepresentation: signature) else { return false }
            switch hashFunction {
            case .sha256: return k.isValidSignature(sig, for: Prehashed256(bytes: digest))
            case .sha384: return k.isValidSignature(sig, for: Prehashed384(bytes: digest))
            case .sha512: return k.isValidSignature(sig, for: Prehashed512(bytes: digest))
            }
        case .ed25519:
            throw SigstoreError(
                "message signatures with ed25519 signatures can only be verified with artifacts, and not just their digest"
            )
        case .rsaPKCS1v15:
            throw SigstoreError("verifying RSA signatures over a precomputed digest is not supported yet")
        }
    }
}
