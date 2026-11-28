// Port of sigstore-go v1.4.1 pkg/sign/keys.go, with the algorithm table of
// sigstore/sigstore v1.11.4 pkg/signature/algorithm_registry.go.

import Crypto
import Foundation
import SigstoreCommon
import SigstoreProtobufSpecs
import SwiftASN1
import X509
import _CryptoExtras

/// Mirrors `sign.Keypair`: a signing key and the details a bundle and a
/// certificate request need about it.
public protocol Keypair: Sendable {
    /// The hash algorithm used to compute the digest to sign
    /// (`.unspecified` for pure Ed25519).
    var hashAlgorithm: Dev_Sigstore_Common_V1_HashAlgorithm { get }
    /// The signing algorithm of the key.
    var signingAlgorithm: Dev_Sigstore_Common_V1_PublicKeyDetails { get }
    /// The public key hint written to bundles signed with a bare key.
    var hint: Data { get }
    /// The top-level key algorithm ("ECDSA", "RSA", "ED25519"), used in
    /// Fulcio requests.
    var keyAlgorithm: String { get }
    /// The public key.
    var publicKey: SigstorePublicKey { get }
    /// The public key as a PEM "PUBLIC KEY" block.
    func publicKeyPem() throws -> String
    /// Signs `data`. Returns the signature and the data that was signed: the
    /// digest of `data`, except for pure Ed25519, which signs `data` itself.
    func signData(_ data: Data) async throws -> (signature: Data, digest: Data)
}

/// Mirrors `sign.EphemeralKeypairOptions`.
public struct EphemeralKeypairOptions: Sendable {
    /// Optional fingerprint for the public key. Defaults to the base64
    /// SHA-256 of the DER SubjectPublicKeyInfo.
    public var hint: Data?
    /// Optional algorithm of the signing key. `.unspecified` means ECDSA
    /// P-256 with SHA-256.
    public var algorithm: Dev_Sigstore_Common_V1_PublicKeyDetails

    /// Creates options with an optional hint and algorithm.
    public init(hint: Data? = nil, algorithm: Dev_Sigstore_Common_V1_PublicKeyDetails = .unspecified) {
        self.hint = hint
        self.algorithm = algorithm
    }
}

/// Mirrors `sign.EphemeralKeypair`: a key generated for a single signature.
public struct EphemeralKeypair: Keypair {
    enum PrivateKey: Sendable {
        case p256(P256.Signing.PrivateKey)
        case p384(P384.Signing.PrivateKey)
        case p521(P521.Signing.PrivateKey)
        case ed25519(Curve25519.Signing.PrivateKey)
        case rsa(_RSA.Signing.PrivateKey)
    }

    let privateKey: PrivateKey
    let details: AlgorithmDetails
    /// The public key hint.
    public let hint: Data
    /// The public key.
    public let publicKey: SigstorePublicKey

    /// Mirrors `NewEphemeralKeypair`: generates a key for `options.algorithm`
    /// (default ECDSA P-256 with SHA-256) with a SHA-256 key hint unless
    /// `options.hint` is set.
    ///
    /// - Throws: For an unknown algorithm, ML-DSA (use a dedicated keypair,
    ///   as in sigstore-go) and Ed25519ph, which this port cannot sign with
    ///   (swift-crypto has no Ed25519ph).
    public init(options: EphemeralKeypairOptions = EphemeralKeypairOptions()) throws {
        let algorithm = options.algorithm == .unspecified ? .pkixEcdsaP256Sha256 : options.algorithm
        let details = try AlgorithmDetails(algorithm)
        let key: PrivateKey
        let pub: Certificate.PublicKey
        switch details.keyType {
        case .ecdsa(let curve):
            switch curve {
            case .p256:
                let k = P256.Signing.PrivateKey()
                key = .p256(k)
                pub = Certificate.PublicKey(k.publicKey)
            case .p384:
                let k = P384.Signing.PrivateKey()
                key = .p384(k)
                pub = Certificate.PublicKey(k.publicKey)
            case .p521:
                let k = P521.Signing.PrivateKey()
                key = .p521(k)
                pub = Certificate.PublicKey(k.publicKey)
            }
        case .rsa(let bits):
            let k = try _RSA.Signing.PrivateKey(keySize: _RSA.Signing.KeySize(bitCount: bits))
            key = .rsa(k)
            pub = Certificate.PublicKey(k.publicKey)
        case .ed25519:
            guard details.hashFunction == nil else {
                // Go signs Ed25519ph with ed25519.PrivateKey.Sign(…, crypto.SHA512).
                throw SigstoreError("unsupported signing algorithm: Ed25519ph signing is not implemented")
            }
            let k = Curve25519.Signing.PrivateKey()
            key = .ed25519(k)
            pub = Certificate.PublicKey(k.publicKey)
        case .mlDSA:
            throw SigstoreError("unsupported key type: ML-DSA")
        }
        self.privateKey = key
        self.details = details
        self.publicKey = .x509(pub)
        self.hint = options.hint ?? Data(Base64.encode(Array(SHA256.hash(data: pub.pkixBytes))).utf8)
    }

    /// The hash algorithm used to compute the digest to sign.
    public var hashAlgorithm: Dev_Sigstore_Common_V1_HashAlgorithm { details.protoHash }

    /// The signing algorithm of the key.
    public var signingAlgorithm: Dev_Sigstore_Common_V1_PublicKeyDetails { details.algorithm }

    /// The top-level key algorithm, used in Fulcio requests.
    public var keyAlgorithm: String {
        switch details.keyType {
        case .ecdsa: return "ECDSA"
        case .rsa: return "RSA"
        case .ed25519: return "ED25519"
        case .mlDSA: return ""
        }
    }

    /// The public key as a PEM "PUBLIC KEY" block.
    public func publicKeyPem() throws -> String {
        publicKeyPEM(publicKey.pkixBytes)
    }

    /// Mirrors `EphemeralKeypair.SignData`: ECDSA and RSA (PKCS #1 v1.5) sign
    /// the digest of `data`; Ed25519 signs `data`.
    ///
    /// The RSA-PSS algorithms also produce PKCS #1 v1.5 signatures, as in
    /// sigstore-go, which passes a `crypto.Hash` (not `rsa.PSSOptions`) to
    /// `rsa.PrivateKey.Sign`.
    public func signData(_ data: Data) async throws -> (signature: Data, digest: Data) {
        guard let hash = details.hashFunction else {
            guard case .ed25519(let k) = privateKey else {
                throw SigstoreError("no hash function for a non-Ed25519 key")
            }
            return (try k.signature(for: data), data)
        }
        switch hash {
        case .sha256: return try sign(SHA256.hash(data: data))
        case .sha384: return try sign(SHA384.hash(data: data))
        case .sha512: return try sign(SHA512.hash(data: data))
        }
    }

    private func sign<D: Digest>(_ digest: D) throws -> (signature: Data, digest: Data) {
        let signature: Data
        switch privateKey {
        case .p256(let k): signature = try k.signature(for: digest).derRepresentation
        case .p384(let k): signature = try k.signature(for: digest).derRepresentation
        case .p521(let k): signature = try k.signature(for: digest).derRepresentation
        case .rsa(let k): signature = try k.signature(for: digest, padding: .insecurePKCS1v1_5).rawRepresentation
        case .ed25519: throw SigstoreError("Ed25519 cannot sign a digest")
        }
        return (signature, Data(digest))
    }
}

/// Encodes a DER SubjectPublicKeyInfo as PEM, with a trailing newline like
/// Go's `pem.EncodeToMemory`.
func publicKeyPEM(_ der: [UInt8]) -> String {
    pemBlock(type: "PUBLIC KEY", der: der)
}

/// Encodes `der` as a PEM block ending in a newline.
func pemBlock(type: String, der: [UInt8]) -> String {
    let pem = PEMDocument(type: type, derBytes: der).pemString
    return pem.hasSuffix("\n") ? pem : pem + "\n"
}

/// The subset of sigstore `signature.AlgorithmDetails` signing needs.
struct AlgorithmDetails: Sendable {
    enum Curve: Sendable { case p256, p384, p521 }
    enum KeyType: Sendable {
        case ecdsa(Curve)
        case rsa(bits: Int)
        case ed25519
        case mlDSA
    }

    let algorithm: Dev_Sigstore_Common_V1_PublicKeyDetails
    let keyType: KeyType
    /// `nil` when the data is signed without pre-hashing (Go `crypto.Hash(0)`).
    let hashFunction: HashFunc?

    /// Mirrors `signature.GetAlgorithmDetails`.
    init(_ algorithm: Dev_Sigstore_Common_V1_PublicKeyDetails) throws {
        self.algorithm = algorithm
        switch algorithm {
        case .pkixRsaPkcs1V152048Sha256, .pkixRsaPss2048Sha256: (keyType, hashFunction) = (.rsa(bits: 2048), .sha256)
        case .pkixRsaPkcs1V153072Sha256, .pkixRsaPss3072Sha256: (keyType, hashFunction) = (.rsa(bits: 3072), .sha256)
        case .pkixRsaPkcs1V154096Sha256, .pkixRsaPss4096Sha256: (keyType, hashFunction) = (.rsa(bits: 4096), .sha256)
        case .pkixEcdsaP256Sha256: (keyType, hashFunction) = (.ecdsa(.p256), .sha256)
        case .pkixEcdsaP384Sha384: (keyType, hashFunction) = (.ecdsa(.p384), .sha384)
        case .pkixEcdsaP384Sha256: (keyType, hashFunction) = (.ecdsa(.p384), .sha256)
        case .pkixEcdsaP521Sha512: (keyType, hashFunction) = (.ecdsa(.p521), .sha512)
        case .pkixEcdsaP521Sha256: (keyType, hashFunction) = (.ecdsa(.p521), .sha256)
        case .pkixEd25519: (keyType, hashFunction) = (.ed25519, nil)
        case .pkixEd25519Ph: (keyType, hashFunction) = (.ed25519, .sha512)
        case .mlDsa44, .mlDsa65, .mlDsa87: (keyType, hashFunction) = (.mlDSA, nil)
        default: throw SigstoreError("could not find algorithm details for known algorithm: \(algorithm)")
        }
    }

    /// The protobuf hash algorithm (`GetProtoHashType`).
    var protoHash: Dev_Sigstore_Common_V1_HashAlgorithm {
        switch hashFunction {
        case nil: return .unspecified
        case .sha256: return .sha2256
        case .sha384: return .sha2384
        case .sha512: return .sha2512
        }
    }
}
