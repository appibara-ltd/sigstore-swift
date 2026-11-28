// Port of sigstore-go pkg/root/trusted_material.go.

import Foundation
import SigstoreCommon

/// Mirrors `root.TrustedMaterial`. Go getter methods are Swift properties.
public protocol TrustedMaterial: Sendable {
    var timestampingAuthorities: [any TimestampingAuthority] { get }
    var fulcioCertificateAuthorities: [any CertificateAuthority] { get }
    /// Keyed by hex-encoded log ID.
    var rekorLogs: [String: TransparencyLog] { get }
    /// Keyed by hex-encoded log ID.
    var ctLogs: [String: TransparencyLog] { get }
    func publicKeyVerifier(_ keyID: String) throws -> any TimeConstrainedVerifier
    var publicKeyVerifiers: [any TimeConstrainedVerifier] { get }
}

/// Default implementations (Go `BaseTrustedMaterial`).
extension TrustedMaterial {
    /// Default: no timestamping authorities.
    public var timestampingAuthorities: [any TimestampingAuthority] { [] }
    /// Default: no certificate authorities.
    public var fulcioCertificateAuthorities: [any CertificateAuthority] { [] }
    /// Default: no Rekor logs.
    public var rekorLogs: [String: TransparencyLog] { [:] }
    /// Default: no CT logs.
    public var ctLogs: [String: TransparencyLog] { [:] }
    /// Default: always throws (no public key verifier is known).
    public func publicKeyVerifier(_ keyID: String) throws -> any TimeConstrainedVerifier {
        throw SigstoreError("public key verifier not found")
    }
    /// Default: no public key verifiers.
    public var publicKeyVerifiers: [any TimeConstrainedVerifier] { [] }
}

/// Mirrors `root.ValidityPeriodChecker`.
public protocol ValidityPeriodChecker: Sendable {
    func validAtTime(_ time: Date) -> Bool
}

/// Mirrors `root.TimeConstrainedVerifier` (a validity-bounded signature verifier).
public protocol TimeConstrainedVerifier: ValidityPeriodChecker {
    var verifier: SignatureVerifier { get }
}

/// Mirrors `root.ExpiringKey`.
public struct ExpiringKey: TimeConstrainedVerifier {
    /// The verifier for the trusted key.
    public let verifier: SignatureVerifier
    /// Start of the key's validity period; `nil` means unbounded.
    public let validityPeriodStart: Date?
    /// End of the key's validity period; `nil` means unbounded.
    public let validityPeriodEnd: Date?

    /// Mirrors sigstore-go `root.NewExpiringKey`: a verifier valid between
    /// the given bounds (`nil` for an unbounded side).
    public init(verifier: SignatureVerifier, validityPeriodStart: Date?, validityPeriodEnd: Date?) {
        self.verifier = verifier
        self.validityPeriodStart = validityPeriodStart
        self.validityPeriodEnd = validityPeriodEnd
    }

    /// Mirrors `ExpiringKey.ValidAtTime`: `true` unless `t` is before the
    /// start or after the end of the validity period (bounds inclusive).
    public func validAtTime(_ t: Date) -> Bool {
        if let start = validityPeriodStart, t < start { return false }
        if let end = validityPeriodEnd, t > end { return false }
        return true
    }
}

/// Mirrors `root.TrustedPublicKeyMaterial`.
public struct TrustedPublicKeyMaterial: TrustedMaterial {
    private let lookup: (@Sendable (String) throws -> any TimeConstrainedVerifier)?
    private let verifiers: [any TimeConstrainedVerifier]

    /// Mirrors `NewTrustedPublicKeyMaterial`.
    public init(publicKeyVerifier: @escaping @Sendable (String) throws -> any TimeConstrainedVerifier) {
        self.lookup = publicKeyVerifier
        self.verifiers = []
    }

    /// Mirrors `NewTrustedPublicKeyVerifiers`.
    public init(verifiers: [any TimeConstrainedVerifier]) {
        self.lookup = nil
        self.verifiers = verifiers
    }

    /// Mirrors `NewTrustedPublicKeyMaterialFromMapping`.
    public init(mapping: [String: ExpiringKey]) {
        self.init(publicKeyVerifier: { keyID in
            guard let key = mapping[keyID] else {
                throw SigstoreError("public key not found for keyID: \(keyID)")
            }
            return key
        })
    }

    /// Looks up the verifier for `keyID` via the lookup closure.
    ///
    /// - Throws: If the material was created with ``init(verifiers:)``, or the
    ///   lookup closure throws (e.g. an unknown key ID).
    public func publicKeyVerifier(_ keyID: String) throws -> any TimeConstrainedVerifier {
        if let lookup, verifiers.isEmpty {
            return try lookup(keyID)
        }
        throw SigstoreError("public key verifier not found for keyID: \(keyID)")
    }

    /// The verifiers passed to ``init(verifiers:)``; empty for
    /// lookup-based material.
    public var publicKeyVerifiers: [any TimeConstrainedVerifier] {
        lookup != nil ? [] : verifiers
    }
}

/// Mirrors `root.TrustedMaterialCollection`.
public struct TrustedMaterialCollection: TrustedMaterial {
    /// The collected trusted materials, in lookup order.
    public var materials: [any TrustedMaterial]

    /// Creates a collection over `materials`.
    public init(_ materials: [any TrustedMaterial]) {
        self.materials = materials
    }

    /// Returns the first verifier found for `keyID` among `materials`.
    ///
    /// - Throws: If no material has a verifier for `keyID`.
    public func publicKeyVerifier(_ keyID: String) throws -> any TimeConstrainedVerifier {
        for tm in materials {
            if let v = try? tm.publicKeyVerifier(keyID) { return v }
        }
        throw SigstoreError("public key verifier not found for keyID: \(keyID)")
    }

    /// The public key verifiers of all `materials`, concatenated.
    public var publicKeyVerifiers: [any TimeConstrainedVerifier] {
        materials.flatMap { $0.publicKeyVerifiers }
    }

    /// The timestamping authorities of all `materials`, concatenated.
    public var timestampingAuthorities: [any TimestampingAuthority] {
        materials.flatMap { $0.timestampingAuthorities }
    }

    /// The certificate authorities of all `materials`, concatenated.
    public var fulcioCertificateAuthorities: [any CertificateAuthority] {
        materials.flatMap { $0.fulcioCertificateAuthorities }
    }

    /// The Rekor logs of all `materials`, merged by log ID; later materials
    /// win on duplicate IDs.
    public var rekorLogs: [String: TransparencyLog] {
        materials.reduce(into: [:]) { acc, tm in acc.merge(tm.rekorLogs) { _, new in new } }
    }

    /// The CT logs of all `materials`, merged by log ID; later materials win
    /// on duplicate IDs.
    public var ctLogs: [String: TransparencyLog] {
        materials.reduce(into: [:]) { acc, tm in acc.merge(tm.ctLogs) { _, new in new } }
    }
}
