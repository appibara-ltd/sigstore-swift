// Rekor v2 signed-note checkpoints and inclusion verification.
//
// Port of the code sigstore-go v1.4.1 relies on, at the versions it pins:
// - rekor-tiles v2.4.2 pkg/note (`NewNoteVerifier`, `KeyHash`) and
//   pkg/verify (`VerifyCheckpoint`, `VerifyLogEntryWithHash`);
// - golang.org/x/mod v0.43.0 sumdb/note (`Open`, `VerifierList`);
// - transparency-dev/formats v0.1.1 log (`ParseCheckpoint`,
//   `Checkpoint.Unmarshal`).
// ML-DSA-44 note keys use rekor-tiles' cosignature/v1 framing.

import Crypto
import Foundation
import SigstoreCommon
import SigstoreProtobufSpecs
import SwiftProtobuf

/// Mirrors a sumdb `note.Verifier` built by rekor-tiles `NewNoteVerifier`.
public struct NoteVerifier: Sendable {
    /// The verifier's key name: the log origin passed to the initializer.
    public let name: String
    /// The 4-byte key hash that signature lines must carry to match this key.
    public let keyHash: UInt32
    let verifier: SignatureVerifier

    /// Mirrors `note.NewNoteVerifier`: `origin` is the log's origin (the
    /// hostname of its base URL); `verifier` verifies note signatures over
    /// the note text with the log's configured hash.
    public init(origin: String, verifier: SignatureVerifier) throws {
        guard isValidNoteName(origin) else { throw SigstoreError("invalid name \(origin)") }
        self.name = origin
        self.keyHash = try noteKeyHash(origin: origin, verifier: verifier)
        self.verifier = verifier
    }

    /// rekor-tiles `noteVerifier.verify`. For ML-DSA the signature is an
    /// 8-byte big-endian timestamp followed by the ML-DSA signature over
    /// `formatCosignatureV1(origin, timestamp, message)`.
    func verify(_ message: [UInt8], _ signature: [UInt8]) -> Bool {
        guard case .mlDSA(let k) = verifier.key else {
            return verifier.verify(signature: signature, message: message)
        }
        guard signature.count == 8 + k.parameterSet.signatureSize else { return false }
        let timestamp = signature.prefix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        guard let formatted = formatCosignatureV1(origin: name, timestamp: timestamp, message: message) else {
            return false
        }
        return verifier.verify(signature: signature.dropFirst(8), message: formatted)
    }
}

/// Mirrors rekor-tiles `note.KeyHash` (the 4-byte key ID).
/// - ECDSA: SHA-256(PKIX) (no name, matching Rekor v1 key hints).
/// - Ed25519: SHA-256(name || "\n" || 0x01 || raw key).
/// - RSA: SHA-256(name || "\n" || 0xFF || "PKIX-RSA-PKCS#1v1.5" || PKIX).
public func noteKeyHash(origin: String, verifier: SignatureVerifier) throws -> UInt32 {
    let digest: SHA256.Digest
    switch verifier.key {
    case .ecdsaP256, .ecdsaP384, .ecdsaP521:
        digest = SHA256.hash(data: verifier.publicKey.pkixBytes)
    case .ed25519(let k), .ed25519ph(let k):  // KeyHash depends on the key type only
        digest = SHA256.hash(data: Array(origin.utf8) + [0x0A, 0x01] + Array(k.rawRepresentation))
    case .rsaPKCS1v15:
        digest = SHA256.hash(
            data: Array(origin.utf8) + [0x0A, 0xFF] + Array("PKIX-RSA-PKCS#1v1.5".utf8)
                + Array(verifier.publicKey.pkixBytes))
    case .mlDSA(let k):
        // mldsaKeyHash: only ML-DSA-44; algorithm byte 6.
        guard k.parameterSet == .mlDSA44 else {
            throw SigstoreError("unsupported ML-DSA parameter set \(k.parameterSet), only ML-DSA-44 is supported")
        }
        digest = SHA256.hash(data: Array(origin.utf8) + [0x0A, 0x06] + Array(k.rawRepresentation))
    }
    return digest.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
}

/// rekor-tiles `formatCosignatureV1`: the C2SP tlog-cosignature
/// "subtree/v1" message for a checkpoint (`msg` must be exactly a checkpoint
/// body with a 32-byte root hash and no extension lines). Nil on error.
func formatCosignatureV1(origin: String, timestamp: UInt64, message: [UInt8]) -> [UInt8]? {
    // message is note text that openNote took from a String: valid UTF-8.
    // swiftlint:disable:next optional_data_string_conversion
    let text = String(decoding: message, as: UTF8.self)
    guard let cp = try? LogCheckpoint(text: text) else { return nil }
    let lines = text.split(separator: "\n", maxSplits: 3, omittingEmptySubsequences: false)
    guard lines.count == 4, lines[3].isEmpty else { return nil }  // no trailing data
    guard cp.hash.count == 32 else { return nil }
    let o = Array(origin.utf8)
    let co = Array(cp.origin.utf8)
    guard o.count <= 255, co.count <= 255 else { return nil }  // uint8 length prefixes
    func u64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8(truncatingIfNeeded: v >> (56 - 8 * UInt64($0))) } }
    return Array("subtree/v1\n\u{0}".utf8) + [UInt8(o.count)] + o + u64(timestamp) + [UInt8(co.count)] + co
        + u64(0) + u64(cp.size) + cp.hash
}

/// sumdb `isValidName`.
func isValidNoteName(_ name: String) -> Bool {
    !name.isEmpty && !name.unicodeScalars.contains { $0.properties.isWhitespace } && !name.contains("+")
}

/// A signed note opened by `openNote`. Mirrors sumdb `note.Note`.
public struct OpenedNote: Sendable {
    /// The signed text, including its trailing newline.
    public var text: String
    /// Names and key hashes of the verified signatures.
    public var verifiedSignatures: [(name: String, hash: UInt32)]
    /// The number of distinct signature lines by unknown keys (ignored).
    public var unverifiedSignatureCount: Int
}

/// Mirrors sumdb `note.Open` with a single known verifier: parses the note,
/// verifies every signature by `verifier` (a bad one is an error), and
/// requires at least one. Signatures by unknown keys are ignored.
public func openNote(_ message: String, verifier: NoteVerifier) throws -> OpenedNote {
    let malformed = SigstoreError("malformed note")
    // Valid UTF-8 (guaranteed by String) with no non-newline control characters.
    if message.unicodeScalars.contains(where: { $0.value < 0x20 && $0 != "\n" }) { throw malformed }

    let msg = Array(message.utf8)
    guard let split = lastIndex(of: [0x0A, 0x0A], in: msg) else { throw malformed }
    let text = Array(msg[...split])
    var sigs = msg[(split + 2)...]
    guard let last = sigs.last, last == 0x0A else { throw malformed }

    let prefix = Array("\u{2014} ".utf8)
    var seen = Set<String>()
    var seenUnverified = Set<[UInt8]>()
    var verified: [(String, UInt32)] = []
    var unverified = 0
    var numSig = 0
    while !sigs.isEmpty {
        // sigs is non-empty and ends with a newline (checked above).
        // swiftlint:disable:next force_unwrapping
        let i = sigs.firstIndex(of: 0x0A)!
        var line = Array(sigs[..<i])
        sigs = sigs[(i + 1)...]

        guard line.starts(with: prefix) else { throw malformed }
        line.removeFirst(prefix.count)
        // A slice of a String's UTF-8 cut at ASCII bytes: valid UTF-8.
        // swiftlint:disable:next optional_data_string_conversion
        let lineString = String(decoding: line, as: UTF8.self)
        let name: String
        let b64: String
        if let space = lineString.firstIndex(of: " ") {
            name = String(lineString[..<space])
            b64 = String(lineString[lineString.index(after: space)...])
        } else {
            name = lineString
            b64 = ""
        }
        guard !b64.isEmpty, isValidNoteName(name), let decoded = Base64.decode(b64), decoded.count >= 5 else {
            throw malformed
        }
        let sig = Array(decoded)
        let hash = sig.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }

        numSig += 1
        if numSig > 100 { throw malformed }

        guard name == verifier.name && hash == verifier.keyHash else {
            // Unknown verifier: keep (deduplicated) as unverified.
            if seenUnverified.insert(line).inserted { unverified += 1 }
            continue
        }
        if !seen.insert("\(name)\u{0}\(hash)").inserted { continue }
        guard verifier.verify(text, Array(sig.dropFirst(4))) else {
            throw SigstoreError("invalid signature for key \(name)+\(String(format: "%08x", hash))")
        }
        verified.append((name, hash))
    }
    guard !verified.isEmpty else { throw SigstoreError("note has no verifiable signatures") }
    return OpenedNote(
        // A slice of a String's UTF-8 cut at a newline: valid UTF-8.
        // swiftlint:disable:next optional_data_string_conversion
        text: String(decoding: text, as: UTF8.self), verifiedSignatures: verified, unverifiedSignatureCount: unverified)
}

/// Mirrors transparency-dev/formats `log.Checkpoint`.
public struct LogCheckpoint: Sendable, Equatable {
    /// The log origin (first line); never empty after parsing.
    public var origin: String
    /// The tree size the checkpoint commits to.
    public var size: UInt64
    /// The Merkle root hash, base64-decoded.
    public var hash: [UInt8]

    /// Mirrors `Checkpoint.Unmarshal`: origin, decimal size and base64 root
    /// hash on the first three lines; any further lines are extension data.
    public init(text: String) throws {
        let lines = text.split(separator: "\n", maxSplits: 3, omittingEmptySubsequences: false)
        guard lines.count >= 4 else { throw SigstoreError("invalid checkpoint - too few newlines") }
        origin = String(lines[0])
        guard !origin.isEmpty else { throw SigstoreError("invalid checkpoint - empty origin") }
        // strconv.ParseUint(s, 10, 64): ASCII digits only, no sign.
        guard !lines[1].isEmpty, lines[1].allSatisfy({ $0.isASCII && $0.isNumber }), let size = UInt64(lines[1])
        else {
            throw SigstoreError("invalid checkpoint - size invalid")
        }
        self.size = size
        guard let h = Base64.decode(String(lines[2])) else {
            throw SigstoreError("invalid checkpoint - invalid hash")
        }
        hash = Array(h)
    }
}

/// Mirrors `log.ParseCheckpoint` with only the log's verifier: opens the
/// note, then requires the checkpoint origin to equal `verifier.name`.
public func parseCheckpoint(_ checkpoint: String, verifier: NoteVerifier) throws -> LogCheckpoint {
    let note: OpenedNote
    do {
        note = try openNote(checkpoint, verifier: verifier)
    } catch {
        throw SigstoreError("failed to verify signatures on checkpoint", underlying: error)
    }
    guard note.verifiedSignatures.contains(where: { $0.name == verifier.name && $0.hash == verifier.keyHash }) else {
        throw SigstoreError("no log signature found on note")
    }
    let cp: LogCheckpoint
    do {
        cp = try LogCheckpoint(text: note.text)
    } catch {
        throw SigstoreError("failed to unmarshal checkpoint", underlying: error)
    }
    guard cp.origin == verifier.name else {
        throw SigstoreError("got Origin \"\(cp.origin)\" but expected \"\(verifier.name)\"")
    }
    return cp
}

/// Mirrors rekor-tiles `verify.VerifyLogEntryWithHash`: verifies the
/// entry's signed checkpoint, then the inclusion of `entryHash` (an RFC
/// 6962 leaf hash) at the entry's log index under the checkpoint's root.
/// The proof's own root hash and tree size are not used.
public func verifyLogEntryWithHash(
    _ tle: Dev_Sigstore_Rekor_V1_TransparencyLogEntry, verifier: NoteVerifier, entryHash: [UInt8]
) throws {
    let cp: LogCheckpoint
    do {
        cp = try parseCheckpoint(tle.inclusionProof.checkpoint.envelope, verifier: verifier)
    } catch {
        throw SigstoreError("unverified checkpoint signature", underlying: error)
    }
    guard tle.logIndex >= 0 else { throw SigstoreError("invalid index: \(tle.logIndex)") }
    do {
        try Merkle.verifyInclusion(
            index: UInt64(tle.logIndex), size: cp.size, leafHash: entryHash,
            proof: tle.inclusionProof.hashes.map { Array($0) }, root: cp.hash)
    } catch {
        throw SigstoreError("verifying inclusion", underlying: error)
    }
}

private func lastIndex(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
    guard haystack.count >= needle.count else { return nil }
    var i = haystack.count - needle.count
    while i >= 0 {
        if haystack[i] == needle[0] && Array(haystack[i..<(i + needle.count)]) == needle { return i }
        i -= 1
    }
    return nil
}

// MARK: - hashedrekord 0.0.2 entry hash (rekor-tiles pkg/types/hashedrekord)

/// Hash type of a `PublicKeyDetails` (sigstore `GetAlgorithmDetails(...)
/// .GetProtoHashType()`), for the algorithms that prehash. Throws for
/// details without a registered algorithm.
public func protoHashType(
    _ details: Dev_Sigstore_Common_V1_PublicKeyDetails
) throws -> Dev_Sigstore_Common_V1_HashAlgorithm {
    switch details {
    case .pkixEcdsaP256Sha256, .pkixRsaPkcs1V152048Sha256, .pkixRsaPkcs1V153072Sha256,
        .pkixRsaPkcs1V154096Sha256, .pkixRsaPss2048Sha256, .pkixRsaPss3072Sha256, .pkixRsaPss4096Sha256,
        .pkixEcdsaP384Sha256, .pkixEcdsaP521Sha256:
        return .sha2256
    case .pkixEcdsaP384Sha384:
        return .sha2384
    case .pkixEcdsaP521Sha512, .pkixEd25519Ph:
        return .sha2512
    case .pkixEd25519, .mlDsa44, .mlDsa65, .mlDsa87:
        return .unspecified  // signs the message, not a digest
    default:
        throw SigstoreError("getting key algorithm details: unsupported algorithm \(details)")
    }
}

/// Mirrors rekor-tiles `hashedrekord.ToEntryHash`: the RFC 6962 leaf hash
/// of the JCS-canonicalized protojson of the hashedrekord 0.0.2 entry that
/// Rekor v2 would log for (`digest`, `signature`).
public func hashedRekordEntryHash(
    digest: [UInt8], signature: Dev_Sigstore_Rekor_V2_Signature
) throws -> [UInt8] {
    var entry = Dev_Sigstore_Rekor_V2_Entry()
    entry.kind = "hashedrekord"
    entry.apiVersion = "0.0.2"
    var hr = Dev_Sigstore_Rekor_V2_HashedRekordLogEntryV002()
    hr.data.digest = Data(digest)
    hr.data.algorithm = try protoHashType(signature.verifier.keyDetails)
    hr.signature = signature
    entry.spec.spec = .hashedRekordV002(hr)

    let serialized: Data
    do {
        serialized = try entry.jsonUTF8Data()
    } catch {
        throw SigstoreError("marshaling reconstructed entry", underlying: error)
    }
    let canonicalized: Data
    do {
        canonicalized = try JSONCanonicalizer.transform(serialized)
    } catch {
        throw SigstoreError("canonicalizing reconstructed entry", underlying: error)
    }
    return Merkle.hashLeaf(canonicalized)
}
