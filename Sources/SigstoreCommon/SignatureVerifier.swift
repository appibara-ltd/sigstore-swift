import Crypto
import _CryptoExtras
import Foundation
import SwiftASN1
import X509

/// A public key paired with the hash function used to verify signatures.
///
/// Plays the role of `github.com/sigstore/sigstore/pkg/signature.Verifier`
/// (as returned by `signature.LoadVerifier` / `LoadDefaultVerifier`).
public struct SignatureVerifier: Sendable {
    public enum Key: Sendable {
        case ecdsaP256(P256.Signing.PublicKey)
        case ecdsaP384(P384.Signing.PublicKey)
        case ecdsaP521(P521.Signing.PublicKey)
        case ed25519(Curve25519.Signing.PublicKey)
        case rsaPKCS1v15(_RSA.Signing.PublicKey)
    }

    public let key: Key
    /// Hash applied to the message for ECDSA/RSA. Ignored for Ed25519 (pure).
    public let hashFunction: HashFunc
    public let publicKey: Certificate.PublicKey

    /// Loads a verifier, using `hashFunction` or the key's default
    /// (sigstore `LoadDefaultVerifier`: P-256→SHA-256, P-384→SHA-384,
    /// P-521→SHA-512, RSA→SHA-256).
    public init(publicKey: Certificate.PublicKey, hashFunction: HashFunc? = nil) throws {
        self.publicKey = publicKey
        if let k = P256.Signing.PublicKey(publicKey) {
            key = .ecdsaP256(k)
            self.hashFunction = hashFunction ?? .sha256
        } else if let k = P384.Signing.PublicKey(publicKey) {
            key = .ecdsaP384(k)
            self.hashFunction = hashFunction ?? .sha384
        } else if let k = P521.Signing.PublicKey(publicKey) {
            key = .ecdsaP521(k)
            self.hashFunction = hashFunction ?? .sha512
        } else if let k = Curve25519.Signing.PublicKey(publicKey) {
            key = .ed25519(k)
            self.hashFunction = hashFunction ?? .sha512
        } else if let k = _RSA.Signing.PublicKey(publicKey) {
            key = .rsaPKCS1v15(k)
            self.hashFunction = hashFunction ?? .sha256
        } else {
            throw SigstoreError("unsupported public key type")
        }
    }

    /// Parses a DER-encoded SubjectPublicKeyInfo.
    public init<D: DataProtocol>(spki: D, hashFunction: HashFunc? = nil) throws {
        let parsed: Certificate.PublicKey
        do {
            parsed = try Certificate.PublicKey(derEncoded: Array(spki))
        } catch {
            throw SigstoreError("failed to parse public key", underlying: error)
        }
        try self.init(publicKey: parsed, hashFunction: hashFunction)
    }

    /// Default signature hash for a key (sigstore-go `getSignatureHashAlgo`).
    public static func defaultHashFunc(for publicKey: Certificate.PublicKey) -> HashFunc {
        if P384.Signing.PublicKey(publicKey) != nil { return .sha384 }
        if P521.Signing.PublicKey(publicKey) != nil { return .sha512 }
        if Curve25519.Signing.PublicKey(publicKey) != nil { return .sha512 }
        return .sha256
    }

    public var isEd25519: Bool {
        if case .ed25519 = key { return true }
        return false
    }

    /// Verifies `signature` over `message`. ECDSA signatures are ASN.1 DER.
    public func verify<S: DataProtocol, M: DataProtocol>(signature: S, message: M) -> Bool {
        switch key {
        case .ed25519(let k):
            return k.isValidSignature(signature, for: message)
        case .ecdsaP256(let k):
            guard let sig = try? P256.Signing.ECDSASignature(derRepresentation: signature) else { return false }
            switch hashFunction {
            case .sha256: return k.isValidSignature(sig, for: SHA256.hash(data: message))
            case .sha384: return k.isValidSignature(sig, for: SHA384.hash(data: message))
            case .sha512: return k.isValidSignature(sig, for: SHA512.hash(data: message))
            }
        case .ecdsaP384(let k):
            guard let sig = try? P384.Signing.ECDSASignature(derRepresentation: signature) else { return false }
            switch hashFunction {
            case .sha256: return k.isValidSignature(sig, for: SHA256.hash(data: message))
            case .sha384: return k.isValidSignature(sig, for: SHA384.hash(data: message))
            case .sha512: return k.isValidSignature(sig, for: SHA512.hash(data: message))
            }
        case .ecdsaP521(let k):
            guard let sig = try? P521.Signing.ECDSASignature(derRepresentation: signature) else { return false }
            switch hashFunction {
            case .sha256: return k.isValidSignature(sig, for: SHA256.hash(data: message))
            case .sha384: return k.isValidSignature(sig, for: SHA384.hash(data: message))
            case .sha512: return k.isValidSignature(sig, for: SHA512.hash(data: message))
            }
        case .rsaPKCS1v15(let k):
            let sig = _RSA.Signing.RSASignature(rawRepresentation: signature)
            switch hashFunction {
            case .sha256: return k.isValidSignature(sig, for: SHA256.hash(data: message), padding: .insecurePKCS1v1_5)
            case .sha384: return k.isValidSignature(sig, for: SHA384.hash(data: message), padding: .insecurePKCS1v1_5)
            case .sha512: return k.isValidSignature(sig, for: SHA512.hash(data: message), padding: .insecurePKCS1v1_5)
            }
        }
    }
}

extension Certificate.PublicKey {
    /// Full DER SubjectPublicKeyInfo (Go `x509.MarshalPKIXPublicKey`).
    /// Note: swift-certificates' `subjectPublicKeyInfoBytes` is only the
    /// subjectPublicKey BIT STRING contents, not the SPKI structure.
    public var pkixBytes: [UInt8] {
        var serializer = DER.Serializer()
        // Serializing an already-parsed key cannot fail.
        try! serializer.serialize(self)
        return serializer.serializedBytes
    }
}
