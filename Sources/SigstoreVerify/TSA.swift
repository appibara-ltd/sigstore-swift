// Port of sigstore-go pkg/verify/tsa.go.

import Foundation
import SigstoreCommon
import SigstoreRoot

/// sigstore-go internal/limits.MaxAllowedTimestamps.
public let maxAllowedTimestamps = 32

/// Mirrors `VerifySignedTimestamp`: returns verified timestamps and the
/// per-token verification errors.
public func verifySignedTimestamp(
    _ entity: any SignedEntity, trustedMaterial: any TrustedMaterial
) async throws -> (verified: [Timestamp], errors: [any Error]) {
    let signedTimestamps = try entity.timestamps()
    // limit the number of timestamps to prevent DoS
    if signedTimestamps.count > maxAllowedTimestamps {
        throw SigstoreError("too many signed timestamps: \(signedTimestamps.count) > \(maxAllowedTimestamps)")
    }
    let signatureBytes = try entity.signatureContent().signature

    var verifiedTimestamps: [Timestamp] = []
    var verificationErrors: [any Error] = []
    for timestamp in signedTimestamps {
        let verified: Timestamp
        do {
            verified = try await verifySignedTimestamp(
                timestamp, signatureBytes: signatureBytes, trustedMaterial: trustedMaterial)
        } catch {
            verificationErrors.append(error)
            continue
        }
        // A single compromised TSA must not meet the threshold on its own.
        if verifiedTimestamps.contains(where: { $0.uri == verified.uri }) {
            verificationErrors.append(
                SigstoreError("duplicate timestamps from the same authority, ignoring \(verified.uri)"))
            continue
        }
        verifiedTimestamps.append(verified)
    }
    return (verifiedTimestamps, verificationErrors)
}

/// Mirrors `VerifySignedTimestampWithThreshold`.
public func verifySignedTimestampWithThreshold(
    _ entity: any SignedEntity, trustedMaterial: any TrustedMaterial, threshold: Int
) async throws -> [Timestamp] {
    let (verified, errors) = try await verifySignedTimestamp(entity, trustedMaterial: trustedMaterial)
    if verified.count < threshold {
        let joined = errors.map { "\($0)" }.joined(separator: "\n")
        throw SigstoreError(
            "threshold not met for verified signed timestamps: \(verified.count) < \(threshold); error: \(joined)")
    }
    return verified
}

/// Mirrors the unexported `verifySignedTimestamp`: the first trusted TSA
/// that verifies the token wins.
func verifySignedTimestamp(
    _ signedTimestamp: Data, signatureBytes: Data, trustedMaterial: any TrustedMaterial
) async throws -> Timestamp {
    var errors: [String] = []
    for tsa in trustedMaterial.timestampingAuthorities {
        do {
            return try await tsa.verify(signedTimestamp: signedTimestamp, signature: signatureBytes)
        } catch {
            errors.append("\(error)")
        }
    }
    throw SigstoreError("unable to verify signed timestamps: \(errors.joined(separator: "\n"))")
}
