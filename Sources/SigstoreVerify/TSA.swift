// Port of sigstore-go pkg/verify/tsa.go — STUB.
//
// RFC 3161 timestamp verification is not implemented yet. Bundles whose
// only observer timestamps are RFC 3161 tokens therefore fail
// verification; tokens alongside a verified tlog entry are reported as
// unverified and ignored (as sigstore-go does for tokens that fail).

import Foundation
import SigstoreCommon
import SigstoreRoot

/// sigstore-go internal/limits.MaxAllowedTimestamps.
public let maxAllowedTimestamps = 32

/// Mirrors `VerifySignedTimestamp`: returns verified timestamps and the
/// per-token verification errors.
public func verifySignedTimestamp(
    _ entity: any SignedEntity, trustedMaterial: any TrustedMaterial
) throws -> (verified: [Timestamp], errors: [any Error]) {
    let signedTimestamps = try entity.timestamps()
    if signedTimestamps.count > maxAllowedTimestamps {
        throw SigstoreError("too many signed timestamps: \(signedTimestamps.count) > \(maxAllowedTimestamps)")
    }
    let errors: [any Error] = signedTimestamps.map { _ in
        SigstoreError("RFC 3161 timestamp verification is not implemented")
    }
    return ([], errors)
}

/// Mirrors `VerifySignedTimestampWithThreshold`.
public func verifySignedTimestampWithThreshold(
    _ entity: any SignedEntity, trustedMaterial: any TrustedMaterial, threshold: Int
) throws -> [Timestamp] {
    let (verified, errors) = try verifySignedTimestamp(entity, trustedMaterial: trustedMaterial)
    if verified.count < threshold {
        let detail = errors.last.map { ": \($0)" } ?? ""
        throw SigstoreError(
            "threshold not met for verified signed timestamps: \(verified.count) < \(threshold)\(detail)")
    }
    return verified
}
