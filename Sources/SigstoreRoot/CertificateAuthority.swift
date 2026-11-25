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
    public var root: Certificate
    public var intermediates: [Certificate]
    public var validityPeriodStart: Date?
    public var validityPeriodEnd: Date?
    public var uri: String

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
/// `x509.Certificate.Verify` semantics: the leaf must list codeSigning (or
/// anyExtendedKeyUsage); intermediates that carry an EKU extension must too.
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
        // Root (last) is a trust anchor; Go does not check its EKU.
        for (index, cert) in chain.dropLast().enumerated() {
            let eku: ExtendedKeyUsage?
            do {
                eku = try cert.extensions.extendedKeyUsage
            } catch {
                return .failsToMeetPolicy(reason: "invalid extended key usage extension: \(error)")
            }
            // Go treats a missing EKU extension as "any".
            guard let eku else { continue }
            if !(eku.contains(.codeSigning) || eku.contains(.any)) {
                return .failsToMeetPolicy(
                    reason: "certificate at chain position \(index) does not permit code signing"
                )
            }
        }
        return .meetsPolicy
    }
}
