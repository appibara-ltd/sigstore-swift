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
    public var timestampingAuthorities: [any TimestampingAuthority] { [] }
    public var fulcioCertificateAuthorities: [any CertificateAuthority] { [] }
    public var rekorLogs: [String: TransparencyLog] { [:] }
    public var ctLogs: [String: TransparencyLog] { [:] }
    public func publicKeyVerifier(_ keyID: String) throws -> any TimeConstrainedVerifier {
        throw SigstoreError("public key verifier not found")
    }
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
    public let verifier: SignatureVerifier
    public let validityPeriodStart: Date?
    public let validityPeriodEnd: Date?

    public init(verifier: SignatureVerifier, validityPeriodStart: Date?, validityPeriodEnd: Date?) {
        self.verifier = verifier
        self.validityPeriodStart = validityPeriodStart
        self.validityPeriodEnd = validityPeriodEnd
    }

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

    public func publicKeyVerifier(_ keyID: String) throws -> any TimeConstrainedVerifier {
        if let lookup, verifiers.isEmpty {
            return try lookup(keyID)
        }
        throw SigstoreError("public key verifier not found for keyID: \(keyID)")
    }

    public var publicKeyVerifiers: [any TimeConstrainedVerifier] {
        lookup != nil ? [] : verifiers
    }
}

/// Mirrors `root.TrustedMaterialCollection`.
public struct TrustedMaterialCollection: TrustedMaterial {
    public var materials: [any TrustedMaterial]

    public init(_ materials: [any TrustedMaterial]) {
        self.materials = materials
    }

    public func publicKeyVerifier(_ keyID: String) throws -> any TimeConstrainedVerifier {
        for tm in materials {
            if let v = try? tm.publicKeyVerifier(keyID) { return v }
        }
        throw SigstoreError("public key verifier not found for keyID: \(keyID)")
    }

    public var publicKeyVerifiers: [any TimeConstrainedVerifier] {
        materials.flatMap { $0.publicKeyVerifiers }
    }

    public var timestampingAuthorities: [any TimestampingAuthority] {
        materials.flatMap { $0.timestampingAuthorities }
    }

    public var fulcioCertificateAuthorities: [any CertificateAuthority] {
        materials.flatMap { $0.fulcioCertificateAuthorities }
    }

    public var rekorLogs: [String: TransparencyLog] {
        materials.reduce(into: [:]) { acc, tm in acc.merge(tm.rekorLogs) { _, new in new } }
    }

    public var ctLogs: [String: TransparencyLog] {
        materials.reduce(into: [:]) { acc, tm in acc.merge(tm.ctLogs) { _, new in new } }
    }
}
