// Port of sigstore-go pkg/verify/tlog.go.

import Crypto
import Foundation
import SigstoreCommon
import SigstoreProtobufSpecs
import SigstoreRoot
import SigstoreTLog
import SwiftASN1
import X509

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
                guard !tlogVerifier.baseURL.isEmpty else {
                    throw SigstoreError(
                        "cannot verify Rekor v2 entry without baseUrl in transparency log's trusted root")
                }
                guard let components = URLComponents(string: tlogVerifier.baseURL) else {
                    throw SigstoreError("invalid transparency log baseUrl \(tlogVerifier.baseURL)")
                }
                let noteVerifier: NoteVerifier
                do {
                    noteVerifier = try NoteVerifier(origin: urlHostname(components), verifier: verifier)
                } catch {
                    throw SigstoreError("loading note verifier", underlying: error)
                }
                let entryHash = try reconstructV2EntryHash(
                    sigContent, verificationContent, trustedMaterial: trustedMaterial,
                    entitySignature: entitySignature)
                do {
                    try verifyLogEntryWithHash(
                        entry.transparencyLogEntry, verifier: noteVerifier, entryHash: entryHash)
                } catch {
                    throw SigstoreError("verifying log entry", underlying: error)
                }
            }
            // DO NOT use timestamp with only an inclusion proof, because it is not signed metadata
        }

        // Rekor v1 only: enforce bundle <-> entry equality field-by-field.
        // Rekor v2 skips this because the reconstructed hash already commits
        // to the signature, public key, and digest from the bundle.
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

/// Mirrors `reconstructV2EntryHash`: rebuilds the hashedrekord 0.0.2 entry
/// Rekor v2 logged for this bundle (signature, signing certificate or
/// public key with its default algorithm, and the signed digest; for DSSE,
/// the digest of the PAE) and returns its leaf hash.
func reconstructV2EntryHash(
    _ sigContent: any SignatureContent, _ verificationContent: any VerificationContent,
    trustedMaterial: any TrustedMaterial, entitySignature: Data
) throws -> [UInt8] {
    let key: Certificate.PublicKey
    var verifierProto = Dev_Sigstore_Rekor_V2_Verifier()
    if let leaf = verificationContent.certificate {
        key = leaf.publicKey
        var cert = Dev_Sigstore_Common_V1_X509Certificate()
        var der = DER.Serializer()
        try der.serialize(leaf)  // re-emits the parsed raw TBS/signature bytes
        cert.rawBytes = Data(der.serializedBytes)
        verifierProto.verifier = .x509Certificate(cert)
    } else if let provider = verificationContent.publicKey {
        let trusted: any TimeConstrainedVerifier
        do {
            trusted = try trustedMaterial.publicKeyVerifier(provider.hint)
        } catch {
            throw SigstoreError("public key not found in trusted material", underlying: error)
        }
        key = trusted.verifier.publicKey
        var pk = Dev_Sigstore_Rekor_V2_PublicKey()
        pk.rawBytes = Data(key.pkixBytes)
        verifierProto.verifier = .publicKey(pk)
    } else {
        throw SigstoreError("verification content has neither certificate nor public key")
    }

    let details: Dev_Sigstore_Common_V1_PublicKeyDetails
    do {
        details = try defaultPublicKeyDetails(key, ed25519ph: true)
    } catch {
        throw SigstoreError("getting algorithm details from bundle key", underlying: error)
    }
    verifierProto.keyDetails = details
    let hashType = try protoHashType(details)

    let digest: [UInt8]
    if let msg = sigContent.messageSignatureContent {
        digest = Array(msg.digest)
    } else if let envelope = sigContent.envelopeContent {
        let env = envelope.rawEnvelope
        let pae = DSSEEnvelope.pae(payloadType: env.payloadType, payload: env.payload)
        switch hashType {
        case .sha2256: digest = Array(SHA256.hash(data: pae))
        case .sha2384: digest = Array(SHA384.hash(data: pae))
        case .sha2512: digest = Array(SHA512.hash(data: pae))
        default: throw SigstoreError("rekor v2 hashedrekord entries require a prehashing signature algorithm")
        }
    } else {
        throw SigstoreError("bundle must contain either a message signature or an envelope")
    }
    if hashType == .unspecified {
        throw SigstoreError("rekor v2 hashedrekord entries require a prehashing signature algorithm")
    }

    var signature = Dev_Sigstore_Rekor_V2_Signature()
    signature.content = entitySignature
    signature.verifier = verifierProto
    return try hashedRekordEntryHash(digest: digest, signature: signature)
}

/// Mirrors sigstore `signature.GetDefaultPublicKeyDetails` (no RSA-PSS).
func defaultPublicKeyDetails(
    _ key: Certificate.PublicKey, ed25519ph: Bool
) throws -> Dev_Sigstore_Common_V1_PublicKeyDetails {
    switch try SignatureVerifier(publicKey: key).key {
    case .ecdsaP256: return .pkixEcdsaP256Sha256
    case .ecdsaP384: return .pkixEcdsaP384Sha384
    case .ecdsaP521: return .pkixEcdsaP521Sha512
    case .ed25519: return ed25519ph ? .pkixEd25519Ph : .pkixEd25519
    case .rsaPKCS1v15(let k):
        switch k.keySizeInBits {
        case 2048: return .pkixRsaPkcs1V152048Sha256
        case 3072: return .pkixRsaPkcs1V153072Sha256
        case 4096: return .pkixRsaPkcs1V154096Sha256
        default: throw SigstoreError("unsupported public key type")
        }
    }
}

/// Go's `url.URL.Hostname()`: the host without port or IPv6 brackets.
func urlHostname(_ components: URLComponents) -> String {
    var host = components.percentEncodedHost ?? ""
    if host.hasPrefix("[") && host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
    return host
}
