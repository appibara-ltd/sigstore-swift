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
    /// The message `not implemented`.
    public var description: String { "not implemented" }
    /// Creates the error.
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
    /// Default: throws ``NotImplementedError``.
    public func timestamps() throws -> [Data] { throw NotImplementedError() }
    /// Default: throws ``NotImplementedError``.
    public func version() throws -> String { throw NotImplementedError() }
    /// Default: `false`.
    public var hasTransparencyLogProof: Bool { false }
    /// Default: `false`.
    public var hasCertificate: Bool { false }
    /// Default: `false`.
    public var hasPublicKey: Bool { false }
    /// Default: `false`.
    public var hasEnvelope: Bool { false }
    /// Default: throws ``NotImplementedError``.
    public func signature() throws -> Data { throw NotImplementedError() }
    /// Default: throws ``NotImplementedError``.
    public func envelope() throws -> any EnvelopeContent { throw NotImplementedError() }
    /// Default: throws ``NotImplementedError``.
    public func transparencyLogProof() throws -> Dev_Sigstore_Bundle_V2_TransparencyLogProof {
        throw NotImplementedError()
    }
    /// Default: throws ``NotImplementedError``.
    public func certificate() throws -> (Certificate, [Certificate]) { throw NotImplementedError() }
}

/// Mirrors `verify.IdentityVerificationResult`.
public struct IdentityVerificationResult: Sendable {
    /// Whether verification succeeded.
    public var verified: Bool
    /// The verified timestamps.
    public var timestamps: [Date]
    /// The in-toto statement, if the entity carried one.
    public var statement: Statement?
    /// The certificate identity that matched the policy, if any.
    public var verifiedIdentity: CertificateIdentity?
}

/// Mirrors `verify.IdentityVerifier`.
public struct IdentityVerifier: Sendable {
    /// The trust roots used for verification.
    public let trustedMaterial: any TrustedMaterial

    /// Mirrors `verify.IdentityVerifierOption` (v1.4.1 defines none).
    public struct Option: Sendable {
        let apply: @Sendable (inout IdentityVerifier) throws -> Void
        /// Creates an option from a closure that mutates the verifier; it may throw
        /// to reject the configuration.
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
    /// The trust roots used for verification.
    public let trustedMaterial: any TrustedMaterial
    /// The minimum number of verified RFC 3161 timestamps (default 1).
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
    /// The trust roots used for verification.
    public let trustedMaterial: any TrustedMaterial
    /// The minimum number of verified RFC 3161 timestamps (default 0).
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
    /// Default: `false`.
    public var hasInclusionPromise: Bool { false }
    /// Default: `false`.
    public var hasInclusionProof: Bool { false }
    /// Default: throws ``NotImplementedError``.
    public func signatureContent() throws -> any SignatureContent { throw NotImplementedError() }
    /// Default: throws ``NotImplementedError``.
    public func timestamps() throws -> [Data] { throw NotImplementedError() }
    /// Default: throws ``NotImplementedError``.
    public func tlogEntries() throws -> [Entry] { throw NotImplementedError() }
    /// Default: throws ``NotImplementedError``.
    public func verificationContent() throws -> any VerificationContent { throw NotImplementedError() }
    /// Default: throws ``NotImplementedError``.
    public func version() throws -> String { throw NotImplementedError() }
}
