// Port of sigstore-go pkg/verify/tlog.go (Rekor v1 only for now).

import Crypto
import Foundation
import SigstoreCommon
import SigstoreRoot
import SigstoreTLog

/// sigstore-go internal/limits.MaxAllowedTlogEntries.
public let maxAllowedTlogEntries = 32

/// Mirrors `VerifyTlogEntry`: verifies each entry's inclusion proof and/or
/// promise against trusted Rekor logs, checks the entry body matches the
/// entity, and requires `logThreshold` distinct verified logs. Returns the
/// integrated times backed by an inclusion promise when
/// `trustIntegratedTime` is set.
public func verifyTlogEntry(
    _ entity: any SignedEntity,
    trustedMaterial: any TrustedMaterial,
    logThreshold: Int,
    trustIntegratedTime: Bool
) throws -> [Timestamp] {
    let entries: [Entry]
    do {
        entries = try entity.tlogEntries()
    } catch {
        throw error.wrapped("failed to retrieve transparency log entries")
    }
    if entries.count > maxAllowedTlogEntries {
        throw SigstoreError("too many tlog entries: \(entries.count) > \(maxAllowedTlogEntries)")
    }
    for i in entries.indices {
        for j in (i + 1)..<entries.count
        where entries[i].logKeyID == entries[j].logKeyID && entries[i].logIndex == entries[j].logIndex {
            throw SigstoreError("duplicate tlog entries found")
        }
    }

    let sigContent = try entity.signatureContent()
    let entitySignature = sigContent.signature
    let verificationContent = try entity.verificationContent()

    var verifiedTimestamps: [Timestamp] = []
    var verifiedLogIDs = Set<Data>()
    var hasTimestamp = Set<Data>()

    let rekorLogs = trustedMaterial.rekorLogs
    for entry in entries {
        try validateEntry(entry)

        let keyID = entry.logKeyID
        guard let tlogVerifier = rekorLogs[Hex.encode(keyID)] else {
            continue
        }

        if !entry.hasInclusionPromise && !entry.hasInclusionProof {
            throw SigstoreError("entry must contain an inclusion proof and/or promise")
        }
        if entry.isRekorV2 && !entry.hasInclusionProof {
            throw SigstoreError("rekor v2 entries must have an inclusion proof")
        }
        if entry.hasInclusionPromise {
            do {
                try verifySET(entry, verifiers: rekorLogs)
            } catch {
                // Go skips the entry (it then does not count towards the threshold).
                continue
            }
        }
        if entry.hasInclusionProof {
            let verifier = try SignatureVerifier(
                publicKey: tlogVerifier.publicKey, hashFunction: tlogVerifier.signatureHashFunc)
            if hasRekorV1STH(entry) {
                try verifyInclusion(entry, verifier: verifier)
            } else {
                // TODO: Rekor v2 (signed note checkpoints, hashedrekord v0.0.2).
                throw SigstoreError("Rekor v2 log entries are not supported yet")
            }
        }

        if !entry.isRekorV2 {
            guard entry.signature == entitySignature else {
                throw SigstoreError("transparency log signature does not match")
            }
            guard verificationContent.compareKey(entry.publicKey, trustedMaterial: trustedMaterial) else {
                throw SigstoreError("transparency log certificate does not match")
            }

            if let msgSig = sigContent.messageSignatureContent {
                guard let (entryDigest, entryAlgo) = entry.hashedRekordDigest() else {
                    throw SigstoreError("transparency log entry is not a hashedrekord or missing digest")
                }
                let entityHashFunc = try HashFunc(algorithmString: msgSig.digestAlgorithm)
                let entryHashFunc = try HashFunc(algorithmString: entryAlgo)
                guard entityHashFunc == entryHashFunc else {
                    throw SigstoreError(
                        "transparency log hashedrekord entry digest algorithm mismatch: \(msgSig.digestAlgorithm) != \(entryAlgo)"
                    )
                }
                guard Array(msgSig.digest) == entryDigest else {
                    throw SigstoreError(
                        "transparency log hashedrekord entry digest \(Hex.encode(entryDigest)) does not match artifact \(Hex.encode(msgSig.digest))"
                    )
                }
            } else if let envelope = sigContent.envelopeContent {
                let payloadHash = Array(SHA256.hash(data: envelope.rawEnvelope.payload))
                guard let entryDigest = entry.dssePayloadHash() else {
                    throw SigstoreError("transparency log rekor v1 entry is not a dsse_v001 or intoto_v002 entry")
                }
                guard payloadHash == entryDigest else {
                    throw SigstoreError(
                        "transparency log dsse/intoto entry payload hash \(Hex.encode(entryDigest)) does not match envelope payload hash \(Hex.encode(payloadHash))"
                    )
                }
            } else {
                throw SigstoreError("bundle must contain either a message signature or an envelope")
            }
        }

        if let integrated = entry.integratedTime,
            !verificationContent.validAtTime(integrated, trustedMaterial: trustedMaterial)
        {
            throw SigstoreError("integrated time outside certificate validity")
        }

        verifiedLogIDs.insert(keyID)
        if trustIntegratedTime && entry.hasInclusionPromise && !hasTimestamp.contains(keyID) {
            hasTimestamp.insert(keyID)
            verifiedTimestamps.append(
                Timestamp(
                    time: entry.integratedTime ?? Date(timeIntervalSince1970: 0),
                    uri: tlogVerifier.baseURL))
        }
    }

    if verifiedLogIDs.count < logThreshold {
        throw SigstoreError(
            "not enough verified log entries from transparency log: \(verifiedLogIDs.count) < \(logThreshold)")
    }
    return verifiedTimestamps
}

/// Mirrors `hasRekorV1STH`: Rekor v1 checkpoint origins end in " - <treeID>".
func hasRekorV1STH(_ entry: Entry) -> Bool {
    let body = entry.transparencyLogEntry.inclusionProof.checkpoint.envelope
    let lines = body.split(separator: "\n", omittingEmptySubsequences: false)
    guard lines.count >= 4 else { return false }
    // Go regexp ".* - [0-9]+$" (unanchored start, `$` = end of text).
    let first = lines[0]
    guard let range = first.range(of: " - ", options: .backwards) else { return false }
    let suffix = first[range.upperBound...]
    return !suffix.isEmpty && suffix.allSatisfy(\.isASCIIDigitCharacter)
}

extension Character {
    fileprivate var isASCIIDigitCharacter: Bool { isASCII && isNumber }
}
