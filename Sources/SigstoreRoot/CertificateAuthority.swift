// Port of sigstore-go pkg/root/certificate_authority.go.

import Foundation
import SigstoreCommon
import SwiftASN1
@_spi(FixedExpiryValidationTime) import X509

/// Mirrors `root.CertificateAuthority`.
///
/// `verify` is `async` because swift-certificates' path validator is async.
public protocol CertificateAuthority: Sendable {
    /// Returns verified chains, each ordered leaf first and root last.
    func verify(_ cert: Certificate, observerTimestamp: Date) async throws -> [[Certificate]]
}

/// Mirrors `root.FulcioCertificateAuthority`.
public struct FulcioCertificateAuthority: CertificateAuthority {
    /// The trusted root certificate chains must end at.
    public var root: Certificate
    /// Intermediate certificates available for building chains to `root`.
    public var intermediates: [Certificate]
    /// Start of the period this authority is trusted for; `nil` means
    /// unbounded. ``verify(_:observerTimestamp:)`` rejects earlier times.
    public var validityPeriodStart: Date?
    /// End of the period this authority is trusted for; `nil` means
    /// unbounded. ``verify(_:observerTimestamp:)`` rejects later times.
    public var validityPeriodEnd: Date?
    /// The authority's URI (informational).
    public var uri: String

    /// Creates a Fulcio certificate authority from its root, optional
    /// intermediates and optional validity period.
    public init(
        root: Certificate,
        intermediates: [Certificate] = [],
        validityPeriodStart: Date? = nil,
        validityPeriodEnd: Date? = nil,
        uri: String = ""
    ) {
        self.root = root
        self.intermediates = intermediates
        self.validityPeriodStart = validityPeriodStart
        self.validityPeriodEnd = validityPeriodEnd
        self.uri = uri
    }

    /// RFC 5280 path validation at `observerTimestamp` with the code-signing
    /// EKU required, as Go's `x509.Certificate.Verify` with
    /// `KeyUsages: [ExtKeyUsageCodeSigning]`.
    public func verify(_ cert: Certificate, observerTimestamp: Date) async throws -> [[Certificate]] {
        if let start = validityPeriodStart, observerTimestamp < start {
            throw SigstoreError("certificate is not valid yet")
        }
        if let end = validityPeriodEnd, observerTimestamp > end {
            throw SigstoreError("certificate is no longer valid")
        }

        var verifier = Verifier(rootCertificates: CertificateStore([root])) {
            RFC5280Policy(fixedExpiryValidationTime: observerTimestamp)
            CodeSigningPolicy()
        }
        let result = await verifier.validate(leaf: cert, intermediates: CertificateStore(intermediates))
        switch result {
        case .validCertificate(let chain):
            return [Array(chain)]
        case .couldNotValidate(let failures):
            let reasons = failures.map { $0.policyFailureReason.description }
            throw SigstoreError(
                "x509: certificate verification failed"
                    + (reasons.isEmpty ? "" : ": " + reasons.joined(separator: "; "))
            )
        }
    }
}

/// Requires the code-signing extended key usage, following Go's
/// `x509.Certificate.Verify` (`checkChainForKeyUsage`): every certificate
/// in the chain, root included, that lists any EKU must list codeSigning
/// or anyExtendedKeyUsage. A missing or empty EKU extension imposes no
/// restriction.
///
/// It also declares SubjectAlternativeName and ExtendedKeyUsage as handled
/// critical extensions (Go's x509 parses both natively; Fulcio marks SAN
/// critical when the subject is empty).
struct CodeSigningPolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.subjectAlternativeName,
        .X509ExtensionID.extendedKeyUsage,
    ]

    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        // Go walks the whole chain, the root (last) included.
        for (index, cert) in chain.enumerated() {
            let eku: ExtendedKeyUsage?
            do {
                eku = try cert.extensions.extendedKeyUsage
            } catch {
                return .failsToMeetPolicy(reason: "invalid extended key usage extension: \(error)")
            }
            // Go treats a missing or empty EKU extension as unrestricted.
            guard let eku, !eku.isEmpty else { continue }
            if !(eku.contains(.codeSigning) || eku.contains(.any)) {
                return .failsToMeetPolicy(
                    reason: "certificate at chain position \(index) does not permit code signing"
                )
            }
        }
        return .meetsPolicy
    }
}
