// Port of sigstore-go pkg/tlog/entry.go (Rekor v1 entries).
//
// Rekor v2 (rekor-tiles) entries are not supported yet; see PROGRESS.md.

import Foundation
import SigstoreCommon
import SigstoreProtobufSpecs
import SigstoreRoot
import X509

/// Mirrors `tlog.ErrNilValue`.
public struct NilValueError: Error, CustomStringConvertible, Sendable {
    public var description: String { "validation error: nil value in transaction log entry" }
}

/// Key material recorded in a log entry (Go returns `any`: either an
/// `*x509.Certificate` or a `crypto.PublicKey`).
public enum EntryPublicKey: Sendable {
    case certificate(Certificate)
    case publicKey(Certificate.PublicKey)
}

/// Decoded Rekor v1 entry bodies sigstore-go accepts (`ValidateEntry`).
public enum RekorV1Entry: Sendable {
    case dsseV001(DSSEV001)
    case hashedRekordV001(HashedRekordV001)
    case intotoV002(IntotoV002)
}

/// Mirrors `tlog.Entry`.
public struct Entry: Sendable {
    public let kind: String
    public let version: String
    public let rekorV1Entry: RekorV1Entry?
    let signedEntryTimestamp: Data?
    public let transparencyLogEntry: Dev_Sigstore_Rekor_V1_TransparencyLogEntry

    init(tle: Dev_Sigstore_Rekor_V1_TransparencyLogEntry) throws {
        let body = tle.canonicalizedBody
        let parsed = try RekorV1Body.parse(body)
        self.kind = parsed.kind
        self.version = parsed.apiVersion
        self.rekorV1Entry = parsed.entry
        if tle.hasInclusionPromise, !tle.inclusionPromise.signedEntryTimestamp.isEmpty {
            self.signedEntryTimestamp = tle.inclusionPromise.signedEntryTimestamp
        } else {
            self.signedEntryTimestamp = nil
        }
        self.transparencyLogEntry = tle
    }

    /// Unix integrated time, or nil when unset (Go returns the zero `time.Time`).
    public var integratedTime: Date? {
        let t = transparencyLogEntry.integratedTime
        return t == 0 ? nil : Date(timeIntervalSince1970: TimeInterval(t))
    }

    /// Mirrors `Entry.Signature`. Empty on decode failure, as in Go.
    public var signature: Data {
        switch rekorV1Entry {
        case .dsseV001(let e): return Base64.decode(e.signatures[0].signature) ?? Data()
        case .hashedRekordV001(let e): return e.signatureContent
        case .intotoV002(let e):
            // Go: base64.StdEncoding.DecodeString(string(sig)); empty on failure.
            return String(data: e.signatures[0].sig, encoding: .utf8).flatMap(Base64.decode) ?? Data()
        case nil: return Data()
        }
    }

    /// Mirrors `Entry.PublicKey`: the PEM certificate or public key in the body.
    public var publicKey: EntryPublicKey? {
        let pem: Data
        switch rekorV1Entry {
        case .dsseV001(let e): pem = e.signatures[0].verifierPEM
        case .hashedRekordV001(let e): pem = e.publicKeyPEM
        case .intotoV002(let e): pem = e.signatures[0].publicKeyPEM
        case nil: return nil
        }
        guard let der = PEM.firstBlockDER(pem) else { return nil }
        if let cert = try? Certificate(derEncoded: der) {
            return .certificate(cert)
        }
        if let key = try? Certificate.PublicKey(derEncoded: der) {
            return .publicKey(key)
        }
        return nil
    }

    /// Raw log key ID bytes (Go returns them as a `string`).
    public var logKeyID: Data { transparencyLogEntry.logID.keyID }

    public var logIndex: Int64 { transparencyLogEntry.logIndex }

    /// Base64 of the canonicalized body (Go `Entry.Body`).
    public var body: String { Base64.encode(transparencyLogEntry.canonicalizedBody) }

    public var hasInclusionPromise: Bool { signedEntryTimestamp != nil }

    public var hasInclusionProof: Bool { transparencyLogEntry.hasInclusionProof }

    /// Always false until Rekor v2 support lands.
    public var isRekorV2: Bool { false }

    /// Mirrors `Entry.GetHashedRekordDigest`.
    public func hashedRekordDigest() -> (digest: [UInt8], algorithm: String)? {
        guard case .hashedRekordV001(let e) = rekorV1Entry,
            let bytes = Hex.decode(e.dataHashValue)
        else { return nil }
        return (bytes, e.dataHashAlgorithm)
    }

    /// Mirrors `Entry.GetDssePayloadHash`.
    public func dssePayloadHash() -> [UInt8]? {
        switch rekorV1Entry {
        case .dsseV001(let e):
            guard let v = e.payloadHashValue else { return nil }
            return Hex.decode(v)
        case .intotoV002(let e):
            guard let v = e.payloadHashValue else { return nil }
            return Hex.decode(v)
        default:
            return nil
        }
    }
}

/// Mirrors `ParseTransparencyLogEntry`.
public func parseTransparencyLogEntry(_ tle: Dev_Sigstore_Rekor_V1_TransparencyLogEntry) throws -> Entry {
    if tle.canonicalizedBody.isEmpty || tle.logIndex < 0 || !tle.hasLogID || tle.logID.keyID.isEmpty
        || !tle.hasKindVersion
    {
        throw NilValueError()
    }
    if tle.hasInclusionProof {
        guard tle.inclusionProof.hasCheckpoint else {
            throw SigstoreError("inclusion proof missing required checkpoint")
        }
        guard !tle.inclusionProof.checkpoint.envelope.isEmpty else {
            throw SigstoreError("inclusion proof checkpoint empty")
        }
    }
    let entry: Entry
    do {
        entry = try Entry(tle: tle)
    } catch {
        throw SigstoreError("entry body is not a recognizable Rekor v1 or Rekor v2 type", underlying: error)
    }
    if entry.kind != tle.kindVersion.kind || entry.version != tle.kindVersion.version {
        throw SigstoreError(
            "kind and version mismatch: \(entry.kind)/\(entry.version) != \(tle.kindVersion.kind)/\(tle.kindVersion.version)"
        )
    }
    return entry
}

/// Mirrors `ValidateEntry`. Structural validation happens while decoding the
/// body (see `RekorV1Body`), so this only rejects unsupported types.
public func validateEntry(_ entry: Entry) throws {
    guard entry.rekorV1Entry != nil else {
        throw SigstoreError("unsupported entry type: \(entry.kind)/\(entry.version)")
    }
}

/// Mirrors `tlog.RekorPayload` (the SET signed payload).
struct RekorPayload {
    var body: String
    var integratedTime: Int64
    var logIndex: Int64
    var logID: String

    /// RFC 8785 (JCS) canonical JSON. Keys are sorted; all values are either
    /// integers or base64/hex strings, which need no escaping.
    func canonicalJSON() -> Data {
        var s = "{"
        s += "\"body\":\"\(body)\","
        s += "\"integratedTime\":\(integratedTime),"
        s += "\"logID\":\"\(logID)\","
        s += "\"logIndex\":\(logIndex)"
        s += "}"
        return Data(s.utf8)
    }
}

/// Mirrors `VerifySET`: verifies the inclusion promise (SignedEntryTimestamp).
public func verifySET(_ entry: Entry, verifiers: [String: TransparencyLog]) throws {
    guard entry.rekorV1Entry != nil else {
        throw SigstoreError("can only verify SET for Rekor v1 entry")
    }
    let logIDHex = Hex.encode(entry.logKeyID)
    let payload = RekorPayload(
        body: entry.body,
        integratedTime: entry.transparencyLogEntry.integratedTime,
        logIndex: entry.logIndex,
        logID: logIDHex
    )
    guard let tlog = verifiers[logIDHex] else {
        throw SigstoreError("rekor log public key not found for payload")
    }
    guard let start = tlog.validityPeriodStart else {
        throw SigstoreError("rekor validity period start time not set")
    }
    let integrated = entry.integratedTime ?? Date(timeIntervalSince1970: 0)
    if start > integrated || (tlog.validityPeriodEnd.map { $0 < integrated } ?? false) {
        throw SigstoreError("rekor log public key not valid at payload integrated time")
    }
    // Go: ecdsa.VerifyASN1(key, sha256(canonical), set) — ECDSA keys only.
    let verifier = try SignatureVerifier(publicKey: tlog.publicKey, hashFunction: .sha256)
    switch verifier.key {
    case .ecdsaP256, .ecdsaP384, .ecdsaP521: break
    default: throw SigstoreError("unsupported public key type for SET verification")
    }
    guard let set = entry.signedEntryTimestamp,
        verifier.verify(signature: set, message: payload.canonicalJSON())
    else {
        throw SigstoreError("unable to verify SET")
    }
}

/// Mirrors `VerifyInclusion` (Rekor v1): verifies the Merkle inclusion proof
/// and the checkpoint signature, and that the checkpoint root hash matches.
public func verifyInclusion(_ entry: Entry, verifier: SignatureVerifier) throws {
    let tle = entry.transparencyLogEntry
    guard tle.hasInclusionProof else { throw SigstoreError("inclusion proof not provided") }
    let proof = tle.inclusionProof

    // rekor pkg/verify.VerifyInclusion
    guard proof.logIndex >= 0, proof.treeSize >= 0 else {
        throw SigstoreError("invalid inclusion proof index or tree size")
    }
    let leafHash = Merkle.hashLeaf(tle.canonicalizedBody)
    try Merkle.verifyInclusion(
        index: UInt64(proof.logIndex),
        size: UInt64(proof.treeSize),
        leafHash: leafHash,
        proof: proof.hashes.map { Array($0) },
        root: Array(proof.rootHash)
    )

    // rekor pkg/verify.VerifyCheckpointSignature
    let sth: SignedCheckpoint
    do {
        sth = try SignedCheckpoint(text: proof.checkpoint.envelope)
    } catch {
        throw SigstoreError("unmarshalling log entry checkpoint to SignedCheckpoint", underlying: error)
    }
    guard sth.signedNote.verify(verifier) else {
        throw SigstoreError("signature on checkpoint did not verify")
    }
    guard Array(proof.rootHash) == sth.checkpoint.hash else {
        throw SigstoreError(
            "proof root hash does not match signed tree head, expected \(Hex.encode(proof.rootHash)) got \(Hex.encode(sth.checkpoint.hash))"
        )
    }
}

enum PEM {
    /// Decodes the first PEM block (Go `pem.Decode`), returning its DER bytes.
    static func firstBlockDER(_ data: Data) -> [UInt8]? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        let lines = text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline)
        var inBlock = false
        var b64 = ""
        for raw in lines {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if !inBlock {
                if line.hasPrefix("-----BEGIN "), line.hasSuffix("-----") { inBlock = true }
                continue
            }
            if line.hasPrefix("-----END ") { return Base64.decode(b64).map(Array.init) }
            b64 += line
        }
        return nil
    }
}
