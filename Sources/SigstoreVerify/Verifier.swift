// Verifier half of sigstore-go pkg/verify/signed_entity.go.

import Foundation
import SigstoreCommon
import SigstoreFulcio
import SigstoreRoot
import SigstoreTLog
import X509

/// Mirrors `verify.VerificationResultMediaType01`: the media type of a
/// ``VerificationResult``.
public let verificationResultMediaType01 = "application/vnd.dev.sigstore.verificationresult+json;version=0.1"

/// Mirrors `verify.VerifierConfig`.
public struct VerifierConfig: Sendable {
    /// Whether RFC 3161 timestamps are required to verify short-lived certificates.
    public internal(set) var requireSignedTimestamps = false
    /// The minimum number of verified RFC 3161 timestamps.
    public internal(set) var signedTimestampThreshold = 0
    /// Whether log entry integrated timestamps are required to verify short-lived
    /// certificates.
    public internal(set) var requireIntegratedTimestamps = false
    /// The minimum number of verified log entry integrated timestamps.
    public internal(set) var integratedTimeThreshold = 0
    /// Whether RFC 3161 and/or log integrated timestamps are required to verify
    /// short-lived certificates.
    public internal(set) var requireObserverTimestamps = false
    /// The minimum number of verified RFC 3161 and/or log integrated timestamps.
    public internal(set) var observerTimestampThreshold = 0
    /// Whether transparency log inclusion proofs are required.
    public internal(set) var requireTlogEntries = false
    /// The minimum number of verified transparency log entries.
    public internal(set) var tlogEntriesThreshold = 0
    /// Whether SCTs are required in Fulcio certificates.
    public internal(set) var requireSCTs = false
    /// Whether ``VerificationResult/statement`` is built without parsing the
    /// predicate (which is then `nil`).
    public internal(set) var omitStatementPredicate = false
    /// The minimum number of verified SCTs in a Fulcio certificate.
    public internal(set) var ctlogEntriesThreshold = 0
    /// Whether the current time is used instead of a signed or log timestamp.
    public internal(set) var useCurrentTime = false
    /// Whether timestamp checks are skipped (for key-signed entities).
    public internal(set) var allowNoTimestamp = false

    init() {}

    /// Mirrors `VerifierConfig.Validate`.
    public func validate() throws {
        if allowNoTimestamp
            && (requireObserverTimestamps || requireSignedTimestamps || requireIntegratedTimestamps || useCurrentTime)
        {
            throw SigstoreError("specify WithNoObserverTimestamps() without any other verifier options")
        }
        if !requireObserverTimestamps && !requireSignedTimestamps && !requireIntegratedTimestamps && !useCurrentTime
            && !allowNoTimestamp
        {
            throw SigstoreError(
                "when initializing a new Verifier, you must specify at least one of "
                    + "WithObserverTimestamps(), WithSignedTimestamps(), WithIntegratedTimestamps() or WithCurrentTime(), "
                    + "or exclusively specify WithNoObserverTimestamps()")
        }
    }
}

/// Mirrors `verify.VerifierOption`.
public struct VerifierOption: Sendable {
    let apply: @Sendable (inout VerifierConfig) throws -> Void

    /// Mirrors `WithoutStatementPredicate`.
    public static func withoutStatementPredicate() -> VerifierOption {
        VerifierOption { $0.omitStatementPredicate = true }
    }

    /// Mirrors `WithSignedTimestamps`.
    public static func withSignedTimestamps(threshold: Int) -> VerifierOption {
        VerifierOption { c in
            guard threshold >= 1 else { throw SigstoreError("signed timestamp threshold must be at least 1") }
            c.requireSignedTimestamps = true
            c.signedTimestampThreshold = threshold
        }
    }

    /// Mirrors `WithObserverTimestamps`.
    public static func withObserverTimestamps(threshold: Int) -> VerifierOption {
        VerifierOption { c in
            guard threshold >= 1 else { throw SigstoreError("observer timestamp threshold must be at least 1") }
            c.requireObserverTimestamps = true
            c.observerTimestampThreshold = threshold
        }
    }

    /// Mirrors `WithTransparencyLog`.
    public static func withTransparencyLog(threshold: Int) -> VerifierOption {
        VerifierOption { c in
            guard threshold >= 1 else {
                throw SigstoreError("transparency log entry threshold must be at least 1")
            }
            c.requireTlogEntries = true
            c.tlogEntriesThreshold = threshold
        }
    }

    /// Mirrors `WithIntegratedTimestamps`.
    public static func withIntegratedTimestamps(threshold: Int) -> VerifierOption {
        VerifierOption { c in
            guard threshold >= 1 else { throw SigstoreError("integrated timestamp threshold must be at least 1") }
            c.requireIntegratedTimestamps = true
            c.integratedTimeThreshold = threshold
        }
    }

    /// Mirrors `WithSignedCertificateTimestamps`.
    public static func withSignedCertificateTimestamps(threshold: Int) -> VerifierOption {
        VerifierOption { c in
            guard threshold >= 1 else { throw SigstoreError("ctlog entry threshold must be at least 1") }
            c.requireSCTs = true
            c.ctlogEntriesThreshold = threshold
        }
    }

    /// Mirrors `WithCurrentTime`.
    public static func withCurrentTime() -> VerifierOption {
        VerifierOption { $0.useCurrentTime = true }
    }

    /// Mirrors `WithNoObserverTimestamps`.
    public static func withNoObserverTimestamps() -> VerifierOption {
        VerifierOption { $0.allowNoTimestamp = true }
    }
}

/// Mirrors `verify.SignatureVerificationResult`.
public struct SignatureVerificationResult: Sendable {
    /// The UTF-8 bytes of the verifying key's hint, for key-signed entities.
    public var publicKeyID: Data?
    /// A summary of the verified signing certificate, for certificate-signed
    /// entities.
    public var certificate: Summary?
}

/// Mirrors `verify.TimestampVerificationResult`.
public struct TimestampVerificationResult: Sendable, Hashable {
    /// "Tlog", "TimestampAuthority" or "CurrentTime".
    public var type: String
    /// The URL of the log or timestamp authority, if any.
    public var uri: String
    /// The verified time.
    public var timestamp: Date
}

/// Mirrors `verify.VerificationResult`.
public struct VerificationResult: Sendable {
    /// The result's media type, ``verificationResultMediaType01``.
    public var mediaType: String = verificationResultMediaType01
    /// The in-toto statement, if the entity is a DSSE envelope carrying one.
    public var statement: Statement?
    /// Details of the verified signature.
    public var signature: SignatureVerificationResult?
    /// The timestamps that were verified.
    public var verifiedTimestamps: [TimestampVerificationResult] = []
    /// The certificate identity that matched the policy, if any.
    public var verifiedIdentity: CertificateIdentity?
}

/// Mirrors `verify.Verifier`.
public struct Verifier: Sendable {
    /// The trust roots used for verification.
    public let trustedMaterial: any TrustedMaterial
    /// The validated configuration built from the options.
    public let config: VerifierConfig

    /// Mirrors `NewVerifier`.
    public init(trustedMaterial: any TrustedMaterial, options: [VerifierOption]) throws {
        var c = VerifierConfig()
        for option in options {
            do {
                try option.apply(&c)
            } catch {
                throw error.wrapped("failed to configure verifier")
            }
        }
        try c.validate()
        self.trustedMaterial = trustedMaterial
        self.config = c
    }

    /// Mirrors `Verifier.Verify`. `async` because certificate path validation
    /// (swift-certificates) is async; it performs no network I/O.
    public func verify(_ entity: any SignedEntity, policy pb: PolicyBuilder) async throws -> VerificationResult {
        let policy: PolicyConfig
        do {
            policy = try pb.buildConfig()
        } catch {
            throw error.wrapped("failed to build policy")
        }
        if !policy.context.isEmpty {
            throw SigstoreError("WithContext is only supported by IdentityVerifier")
        }

        // > ## Transparency Log Entry
        let verifiedTlogTimestamps: [TimestampVerificationResult]
        do {
            verifiedTlogTimestamps = try verifyTransparencyLogInclusion(entity)
        } catch {
            throw error.wrapped("failed to verify log inclusion")
        }

        // > ## Establishing a Time for the Signature
        let verifiedTimestamps: [TimestampVerificationResult]
        do {
            verifiedTimestamps = try await verifyObserverTimestamps(entity, logTimestamps: verifiedTlogTimestamps)
        } catch {
            throw error.wrapped("failed to verify timestamps")
        }

        let verificationContent: any VerificationContent
        do {
            verificationContent = try entity.verificationContent()
        } catch {
            throw error.wrapped("failed to fetch verification content")
        }

        var signedWithCertificate = false
        var certSummary: Summary?

        if let leafCert = verificationContent.certificate {
            if policy.requireSigningKey {
                throw SigstoreError("expected key signature, not certificate")
            }
            if config.allowNoTimestamp {
                throw SigstoreError("must provide timestamp to verify certificate")
            }
            signedWithCertificate = true
            do {
                certSummary = try summarizeCertificate(leafCert)
            } catch {
                throw error.wrapped("failed to summarize certificate")
            }

            // > The Verifier MUST perform certification path validation (RFC 5280 §6) of the
            // > certificate chain ... with a fake "current time" ... using each timestamp.
            let intermediates = verificationContent.intermediates
            var chains: [[Certificate]] = []
            for verifiedTs in verifiedTimestamps {
                do {
                    chains = try await verifyLeafCertificate(
                        observerTimestamp: verifiedTs.timestamp, leafCert: leafCert,
                        trustedMaterial: trustedMaterial, intermediates: intermediates)
                } catch {
                    throw error.wrapped("failed to verify leaf certificate")
                }
            }

            // > the Verifier MUST extract the SignedCertificateTimestamp embedded in the leaf
            // > certificate, and verify it as in RFC 9162 §8.1.3
            if config.requireSCTs {
                do {
                    try verifySignedCertificateTimestamp(
                        chains: chains, threshold: config.ctlogEntriesThreshold, trustedMaterial: trustedMaterial)
                } catch {
                    throw error.wrapped("failed to verify signed certificate timestamp")
                }
            }
        } else if verificationContent.publicKey != nil {
            for verifiedTs in verifiedTimestamps
            where !verificationContent.validAtTime(verifiedTs.timestamp, trustedMaterial: trustedMaterial) {
                throw SigstoreError("signature time outside of public key validity window")
            }
        }

        if config.requireSCTs && verificationContent.publicKey != nil {
            throw SigstoreError("SCTs required but bundle is signed with a public key, which cannot contain SCTs")
        }

        // > ## Signature Verification
        let sigContent: any SignatureContent
        do {
            sigContent = try entity.signatureContent()
        } catch {
            throw error.wrapped("failed to fetch signature content")
        }
        let entityVersion: String
        do {
            entityVersion = try entity.version()
        } catch {
            throw error.wrapped("failed to fetch entity version")
        }
        let enableCompat = ["v0.1", "0.1", "v0.2", "0.2", "v0.3", "0.3"].contains(entityVersion)
        let verifier: CompatVerifier
        do {
            verifier = try getSignatureVerifier(
                sigContent, verificationContent, trustedMaterial, enableCompat: enableCompat)
        } catch {
            throw error.wrapped("failed to get signature verifier")
        }

        do {
            if policy.requireArtifact {
                if policy.verifyArtifacts {
                    try verifySignatureWithVerifierAndArtifacts(verifier, sigContent, policy.artifacts)
                } else if policy.verifyArtifactDigests {
                    try verifySignatureWithVerifierAndArtifactDigests(verifier, sigContent, policy.artifactDigests)
                } else {
                    throw SigstoreError("no artifact or artifact digest provided")
                }
            } else {
                try verifySignatureWithVerifier(verifier, sigContent)
            }
        } catch {
            throw error.wrapped("failed to verify signature")
        }

        var result = VerificationResult()
        if signedWithCertificate {
            result.signature = SignatureVerificationResult(publicKeyID: nil, certificate: certSummary)
        } else if let pk = verificationContent.publicKey {
            result.signature = SignatureVerificationResult(publicKeyID: Data(pk.hint.utf8), certificate: nil)
        }

        if let envelope = sigContent.envelopeContent {
            do {
                result.statement = config.omitStatementPredicate
                    ? try summarizeStatement(envelope) : try envelope.statement()
            } catch {
                throw error.wrapped("failed to fetch envelope statement")
            }
        }

        result.verifiedTimestamps = verifiedTimestamps

        // > The Verifier MUST then check the certificate against the verification policy.
        if policy.requireIdentities {
            guard signedWithCertificate, let certSummary else {
                throw SigstoreError("can't verify certificate identities: entity was not signed with a certificate")
            }
            guard !policy.certificateIdentities.isEmpty else {
                throw SigstoreError("can't verify certificate identities: no identities provided")
            }
            do {
                result.verifiedIdentity = try policy.certificateIdentities.verify(certSummary)
            } catch {
                throw error.wrapped("failed to verify certificate identity")
            }
        }

        return result
    }

    /// Mirrors `Verifier.VerifyTransparencyLogInclusion`.
    public func verifyTransparencyLogInclusion(_ entity: any SignedEntity) throws -> [TimestampVerificationResult] {
        guard config.requireTlogEntries else { return [] }
        let timestamps = try verifyTlogEntry(
            entity, trustedMaterial: trustedMaterial, logThreshold: config.tlogEntriesThreshold,
            trustIntegratedTime: config.requireIntegratedTimestamps || config.requireObserverTimestamps)
        return timestamps.map { TimestampVerificationResult(type: "Tlog", uri: $0.uri, timestamp: $0.time) }
    }

    /// Mirrors `Verifier.VerifyObserverTimestamps`.
    public func verifyObserverTimestamps(
        _ entity: any SignedEntity, logTimestamps: [TimestampVerificationResult]
    ) async throws -> [TimestampVerificationResult] {
        var verifiedTimestamps: [TimestampVerificationResult] = []

        if config.requireSignedTimestamps {
            let signed = try await verifySignedTimestampWithThreshold(
                entity, trustedMaterial: trustedMaterial, threshold: config.signedTimestampThreshold)
            verifiedTimestamps += signed.map {
                TimestampVerificationResult(type: "TimestampAuthority", uri: $0.uri, timestamp: $0.time)
            }
        }

        if config.requireIntegratedTimestamps {
            if logTimestamps.count < config.integratedTimeThreshold {
                throw SigstoreError(
                    "threshold not met for verified log entry integrated timestamps: \(logTimestamps.count) < \(config.integratedTimeThreshold)"
                )
            }
            verifiedTimestamps += logTimestamps
        }

        if config.requireObserverTimestamps {
            let signed: [Timestamp]
            let errors: [any Error]
            do {
                (signed, errors) = try await verifySignedTimestamp(entity, trustedMaterial: trustedMaterial)
            } catch {
                throw error.wrapped("failed to verify signed timestamps")
            }
            let tsCount = signed.count + logTimestamps.count
            if tsCount < config.observerTimestampThreshold {
                let joined = errors.map { "\($0)" }.joined(separator: "\n")
                throw SigstoreError(
                    "threshold not met for verified signed & log entry integrated timestamps: \(tsCount) < \(config.observerTimestampThreshold); error: \(joined)"
                )
            }
            verifiedTimestamps += logTimestamps
            verifiedTimestamps += signed.map {
                TimestampVerificationResult(type: "TimestampAuthority", uri: $0.uri, timestamp: $0.time)
            }
        }

        if config.useCurrentTime {
            verifiedTimestamps.append(TimestampVerificationResult(type: "CurrentTime", uri: "", timestamp: Date()))
        }

        if verifiedTimestamps.isEmpty && !config.allowNoTimestamp {
            throw SigstoreError("no valid observer timestamps found")
        }
        return verifiedTimestamps
    }
}
