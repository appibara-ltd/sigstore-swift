// Port of sigstore-go v1.4.1 pkg/verify/identity_verifier.go and the v2
// entity interfaces in pkg/verify/interface.go. In v1.4.1 these are API
// scaffolding for v2 bundles: every `Verify` returns "not implemented".

import Foundation
import SigstoreCommon
import SigstoreProtobufSpecs
import SigstoreRoot
import SigstoreTLog
import X509

/// Mirrors `verify.errNotImplemented`.
public struct NotImplementedError: Error, CustomStringConvertible, Sendable {
    public var description: String { "not implemented" }
    public init() {}
}

/// Mirrors `verify.VerifiableEntity` (a v2 bundle or other verifiable entity).
public protocol VerifiableEntity: Sendable {
    /// RFC 3161 signed timestamps (DER).
    func timestamps() throws -> [Data]
    func version() throws -> String
    var hasTransparencyLogProof: Bool { get }
    var hasCertificate: Bool { get }
    var hasPublicKey: Bool { get }
    var hasEnvelope: Bool { get }
    func signature() throws -> Data
    func envelope() throws -> any EnvelopeContent
    func transparencyLogProof() throws -> Dev_Sigstore_Bundle_V2_TransparencyLogProof
    /// The leaf certificate and untrusted intermediates.
    func certificate() throws -> (Certificate, [Certificate])
}

/// Go's `BaseVerifiableEntity`: defaults a conforming type can rely on.
extension VerifiableEntity {
    public func timestamps() throws -> [Data] { throw NotImplementedError() }
    public func version() throws -> String { throw NotImplementedError() }
    public var hasTransparencyLogProof: Bool { false }
    public var hasCertificate: Bool { false }
    public var hasPublicKey: Bool { false }
    public var hasEnvelope: Bool { false }
    public func signature() throws -> Data { throw NotImplementedError() }
    public func envelope() throws -> any EnvelopeContent { throw NotImplementedError() }
    public func transparencyLogProof() throws -> Dev_Sigstore_Bundle_V2_TransparencyLogProof {
        throw NotImplementedError()
    }
    public func certificate() throws -> (Certificate, [Certificate]) { throw NotImplementedError() }
}

/// Mirrors `verify.IdentityVerificationResult`.
public struct IdentityVerificationResult: Sendable {
    public var verified: Bool
    public var timestamps: [Date]
    public var statement: Statement?
    public var verifiedIdentity: CertificateIdentity?
}

/// Mirrors `verify.IdentityVerifier`.
public struct IdentityVerifier: Sendable {
    public let trustedMaterial: any TrustedMaterial

    /// Mirrors `verify.IdentityVerifierOption` (v1.4.1 defines none).
    public struct Option: Sendable {
        let apply: @Sendable (inout IdentityVerifier) throws -> Void
        public init(_ apply: @escaping @Sendable (inout IdentityVerifier) throws -> Void) { self.apply = apply }
    }

    /// Mirrors `NewIdentityVerifier`.
    public init(trustedMaterial: any TrustedMaterial, options: [Option] = []) throws {
        self.trustedMaterial = trustedMaterial
        for option in options { try option.apply(&self) }
    }

    /// Mirrors `IdentityVerifier.Verify` (not implemented in sigstore-go v1.4.1).
    public func verify(_ entity: any VerifiableEntity, policy: PolicyBuilder) throws -> IdentityVerificationResult {
        throw NotImplementedError()
    }
}

/// Mirrors `verify.PKIVerifier`: CA + RFC 3161, no transparency log.
public struct PKIVerifier: Sendable {
    public let trustedMaterial: any TrustedMaterial
    public internal(set) var signedTimestampThreshold = 1

    /// Mirrors `verify.PKIVerifierOption`.
    public struct Option: Sendable {
        let apply: @Sendable (inout PKIVerifier) throws -> Void

        /// Mirrors `WithPKISignedTimestamps`.
        public static func withPKISignedTimestamps(threshold: Int) -> Option {
            Option { v in
                guard threshold >= 1 else { throw SigstoreError("signed timestamp threshold must be at least 1") }
                v.signedTimestampThreshold = threshold
            }
        }
    }

    /// Mirrors `NewPKIVerifier` (default threshold 1).
    public init(trustedMaterial: any TrustedMaterial, options: [Option] = []) throws {
        self.trustedMaterial = trustedMaterial
        for option in options { try option.apply(&self) }
    }

    /// Mirrors `PKIVerifier.Verify` (not implemented in sigstore-go v1.4.1).
    public func verify(_ entity: any VerifiableEntity, policy: PolicyBuilder) throws -> IdentityVerificationResult {
        throw NotImplementedError()
    }
}

/// Mirrors `verify.KeyVerifier`: managed keys, optional RFC 3161.
public struct KeyVerifier: Sendable {
    public let trustedMaterial: any TrustedMaterial
    public internal(set) var signedTimestampThreshold = 0

    /// Mirrors `verify.KeyVerifierOption`.
    public struct Option: Sendable {
        let apply: @Sendable (inout KeyVerifier) throws -> Void

        /// Mirrors `WithKeySignedTimestamps`.
        public static func withKeySignedTimestamps(threshold: Int) -> Option {
            Option { v in
                guard threshold >= 1 else { throw SigstoreError("signed timestamp threshold must be at least 1") }
                v.signedTimestampThreshold = threshold
            }
        }
    }

    /// Mirrors `NewKeyVerifier` (no signed timestamps by default).
    public init(trustedMaterial: any TrustedMaterial, options: [Option] = []) throws {
        self.trustedMaterial = trustedMaterial
        for option in options { try option.apply(&self) }
    }

    /// Mirrors `KeyVerifier.Verify` (not implemented in sigstore-go v1.4.1).
    public func verify(_ entity: any VerifiableEntity, policy: PolicyBuilder) throws -> IdentityVerificationResult {
        throw NotImplementedError()
    }
}

/// Go's `BaseSignedEntity`: defaults for `SignedEntity`.
extension SignedEntity {
    public var hasInclusionPromise: Bool { false }
    public var hasInclusionProof: Bool { false }
    public func signatureContent() throws -> any SignatureContent { throw NotImplementedError() }
    public func timestamps() throws -> [Data] { throw NotImplementedError() }
    public func tlogEntries() throws -> [Entry] { throw NotImplementedError() }
    public func verificationContent() throws -> any VerificationContent { throw NotImplementedError() }
    public func version() throws -> String { throw NotImplementedError() }
}
