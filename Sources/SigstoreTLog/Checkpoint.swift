// Signed note / checkpoint parsing and verification. Port of rekor
// pkg/util/signed_note.go and pkg/util/checkpoint.go (Rekor v1 STH format).

import Crypto
import Foundation
import SigstoreCommon

/// A single signature line of a Rekor v1 signed note. Mirrors sumdb
/// `note.Signature` as used by rekor `util.SignedNote`.
public struct NoteSignature: Sendable {
    /// The signer's key name, as written on the signature line.
    public var name: String
    /// Big-endian key hint: first 4 bytes of SHA-256(PKIX public key).
    public var hash: UInt32
    /// The raw signature bytes, with the 4-byte key hint removed.
    public var signature: Data
}

/// A signed note: note text followed by one or more signature lines. Mirrors
/// rekor `util.SignedNote`.
public struct SignedNote: Sendable {
    /// The signed text, including its trailing newline.
    public var note: String
    /// The parsed signatures; never empty after parsing.
    public var signatures: [NoteSignature]

    /// Mirrors `SignedNote.UnmarshalText`.
    public init(text: String) throws {
        let data = Array(text.utf8)
        let sep: [UInt8] = [0x0A, 0x0A]
        guard let split = lastIndex(of: sep, in: data) else {
            throw SigstoreError("malformed note")
        }
        let noteBytes = data[..<(split + 1)]
        let sigBlock = data[(split + 2)...]
        guard let last = sigBlock.last, last == 0x0A else {
            throw SigstoreError("malformed note")
        }
        note = String(decoding: noteBytes, as: UTF8.self)

        var sigs: [NoteSignature] = []
        let lines = String(decoding: sigBlock, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false)
        for line in lines.dropLast() {  // last element is empty (block ends with "\n")
            // Fscanf("\u{2014} %s %s\n")
            guard line.hasPrefix("\u{2014} ") else {
                throw SigstoreError("parsing signature: unexpected line")
            }
            let fields = line.dropFirst(2).split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count == 2 else {
                throw SigstoreError("parsing signature: unexpected field count")
            }
            guard let sigBytes = Base64.decode(String(fields[1])) else {
                throw SigstoreError("decoding signature")
            }
            guard sigBytes.count >= 5 else {
                throw SigstoreError("signature is too small")
            }
            let hint = sigBytes.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            sigs.append(NoteSignature(name: String(fields[0]), hash: hint, signature: Data(sigBytes.dropFirst(4))))
        }
        guard !sigs.isEmpty else {
            throw SigstoreError("no signatures found in input")
        }
        signatures = sigs
    }

    /// Mirrors `SignedNote.Verify`: every signature must carry the verifier's
    /// key hint and verify over the note text. ECDSA/RSA verify against
    /// SHA-256(note) regardless of the verifier's configured hash.
    public func verify(_ verifier: SignatureVerifier) -> Bool {
        guard !signatures.isEmpty else { return false }
        let msg = Data(note.utf8)
        let pkHash = SHA256.hash(data: verifier.publicKey.pkixBytes).prefix(4)
            .reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        let sha256Verifier: SignatureVerifier
        if verifier.isEd25519 {
            sha256Verifier = verifier
        } else {
            guard let v = try? SignatureVerifier(publicKey: verifier.publicKey, hashFunction: .sha256) else {
                return false
            }
            sha256Verifier = v
        }
        for sig in signatures {
            guard sig.hash == pkHash else { return false }
            guard sha256Verifier.verify(signature: sig.signature, message: msg) else { return false }
        }
        return true
    }
}

/// The body of a Rekor v1 checkpoint (signed tree head). Mirrors rekor
/// `util.Checkpoint`.
public struct Checkpoint: Sendable {
    /// The log origin string (first line); never empty after parsing.
    public var origin: String
    /// The tree size the checkpoint commits to.
    public var size: UInt64
    /// The Merkle root hash, base64-decoded.
    public var hash: [UInt8]
    /// Any extension lines after the root hash, up to the first empty line.
    public var otherContent: [String]

    /// Mirrors `Checkpoint.UnmarshalCheckpoint`.
    public init(text: String) throws {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count >= 4 else {
            throw SigstoreError("invalid checkpoint - too few newlines")
        }
        origin = String(lines[0])
        guard !origin.isEmpty else {
            throw SigstoreError("invalid checkpoint - empty ecosystem")
        }
        guard let size = UInt64(lines[1]) else {
            throw SigstoreError("invalid checkpoint - size invalid")
        }
        self.size = size
        guard let h = Base64.decode(String(lines[2])) else {
            throw SigstoreError("invalid checkpoint - invalid hash")
        }
        hash = Array(h)
        var other: [String] = []
        for line in lines[3...] {
            if line.isEmpty { break }
            other.append(String(line))
        }
        otherContent = other
    }
}

/// Mirrors rekor `util.SignedCheckpoint`.
public struct SignedCheckpoint: Sendable {
    /// The checkpoint parsed from the signed note's text.
    public var checkpoint: Checkpoint
    /// The signed note that carries the checkpoint and its signatures.
    public var signedNote: SignedNote

    /// Parses a signed checkpoint: the signed note, then the checkpoint in its
    /// text. Signatures are not verified here; call `signedNote.verify(_:)`.
    ///
    /// - Throws: When the note or the checkpoint body is malformed.
    public init(text: String) throws {
        let note: SignedNote
        do {
            note = try SignedNote(text: text)
        } catch {
            throw SigstoreError("unmarshalling signed note", underlying: error)
        }
        do {
            checkpoint = try Checkpoint(text: note.note)
        } catch {
            throw SigstoreError("unmarshalling checkpoint", underlying: error)
        }
        signedNote = note
    }
}

private func lastIndex(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
    guard haystack.count >= needle.count else { return nil }
    var i = haystack.count - needle.count
    while i >= 0 {
        if Array(haystack[i..<(i + needle.count)]) == needle { return i }
        i -= 1
    }
    return nil
}
