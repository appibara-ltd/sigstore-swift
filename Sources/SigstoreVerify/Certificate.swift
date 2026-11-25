// Port of sigstore-go pkg/verify/certificate.go.

import Foundation
import SigstoreCommon
import SigstoreRoot
import X509

/// Mirrors `VerifyLeafCertificate`.
public func verifyLeafCertificate(
    observerTimestamp: Date, leafCert: Certificate, trustedMaterial: any TrustedMaterial
) async throws -> [[Certificate]] {
    try await verifyLeafCertificate(
        observerTimestamp: observerTimestamp, leafCert: leafCert, trustedMaterial: trustedMaterial,
        intermediates: [])
}

func verifyLeafCertificate(
    observerTimestamp: Date,
    leafCert: Certificate,
    trustedMaterial: any TrustedMaterial,
    intermediates: [Certificate]
) async throws -> [[Certificate]] {
    var lastError: (any Error)?
    for var ca in trustedMaterial.fulcioCertificateAuthorities {
        if var fca = ca as? FulcioCertificateAuthority, !intermediates.isEmpty {
            fca.intermediates += intermediates
            ca = fca
        }
        do {
            return try await ca.verify(leafCert, observerTimestamp: observerTimestamp)
        } catch {
            lastError = error
        }
    }
    throw SigstoreError("leaf certificate verification failed", underlying: lastError)
}
