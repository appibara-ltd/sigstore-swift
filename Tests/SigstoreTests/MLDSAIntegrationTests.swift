import Foundation
import Sigstore
import Testing

/// ML-DSA wired into keys, trusted roots and Rekor v2 note checkpoints,
/// against Go 1.27 crypto/mldsa + crypto/x509 output
/// (`scripts/mldsa-integration`, `Fixtures/mldsa.json`).
@Suite("ML-DSA integration")
struct MLDSAIntegrationTests {
    private struct KeyCase: Decodable { let params, spki, message, signature: String }
    private struct CheckpointCase: Decodable { let origin, spki, note: String }
    private struct Vectors: Decodable { let keys: [KeyCase]; let checkpoint: CheckpointCase }

    private func vectors() throws -> Vectors {
        try JSONDecoder().decode(Vectors.self, from: Fixtures.file("mldsa.json"))
    }

    private func b64(_ s: String) throws -> Data { try #require(Data(base64Encoded: s)) }

    @Test func goSPKIsAndSignaturesVerify() throws {
        let v = try vectors()
        #expect(v.keys.map(\.params) == ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
        for c in v.keys {
            let spki = try b64(c.spki)
            let key = try SigstorePublicKey(spki: spki)
            guard case .mlDSA(let k) = key else {
                Issue.record("\(c.params) parsed as a classical key")
                continue
            }
            #expect(k.parameterSet.description == c.params)
            #expect(key.pkixBytes == Array(spki))  // re-encodes byte-identically
            let verifier = try SignatureVerifier(spki: spki)
            #expect(verifier.isMLDSA)
            let msg = try b64(c.message)
            let sig = try b64(c.signature)
            #expect(verifier.verify(signature: sig, message: msg))
            #expect(!verifier.verify(signature: sig, message: msg + Data([0])))
            // sigstore MLDSAVerifier refuses WithDigest.
            #expect(throws: (any Error).self) { try verifier.verify(signature: sig, digest: Array(repeating: 0, count: 32)) }
        }
    }

    @Test func malformedMLDSASPKIIsRejected() throws {
        var spki = Array(try b64(try vectors().keys[0].spki))
        spki.removeLast()  // truncated key
        #expect(throws: (any Error).self) { try SigstorePublicKey(spki: spki) }
    }

    @Test func mldsa44CheckpointVerifies() throws {
        let c = try vectors().checkpoint
        let verifier = try NoteVerifier(origin: c.origin, verifier: SignatureVerifier(spki: try b64(c.spki)))
        let cp = try parseCheckpoint(c.note, verifier: verifier)
        #expect(cp.origin == c.origin && cp.size == 42)
        // The signature line's key hash is rekor-tiles' ML-DSA-44 key ID.
        let blob = try b64(String(c.note.split(separator: "\n").last!.split(separator: " ")[2]))
        #expect(blob.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) } == verifier.keyHash)
    }

    @Test func tamperedMLDSACheckpointFails() throws {
        let c = try vectors().checkpoint
        let verifier = try NoteVerifier(origin: c.origin, verifier: SignatureVerifier(spki: try b64(c.spki)))
        // Changed tree size: the signed subtree/v1 message differs.
        let tampered = c.note.replacingOccurrences(of: "\n42\n", with: "\n43\n")
        #expect(throws: (any Error).self) { try parseCheckpoint(tampered, verifier: verifier) }
        // Changed timestamp prefix inside the signature blob.
        let line = String(c.note.split(separator: "\n").last!)
        var blob = Array(try b64(String(line.split(separator: " ")[2])))
        blob[11] ^= 1
        let reSigned = c.note.replacingOccurrences(
            of: line, with: "\u{2014} \(c.origin) \(Data(blob).base64EncodedString())")
        #expect(throws: (any Error).self) { try parseCheckpoint(reSigned, verifier: verifier) }
    }

    @Test func onlyMLDSA44KeysCanSignNotes() throws {
        let v = try vectors()
        let k65 = try SignatureVerifier(spki: try b64(v.keys[1].spki))
        #expect { try NoteVerifier(origin: "log.example.dev", verifier: k65) } throws: {
            "\($0)".contains("only ML-DSA-44 is supported")
        }
    }

    @Test func trustedRootAcceptsMLDSA44LogKeys() throws {
        let v = try vectors()
        func root(_ spki: String) -> Data {
            Data("""
            {"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1","tlogs":[{"baseUrl":"https://\(v.checkpoint.origin)","hashAlgorithm":"SHA2_256","publicKey":{"rawBytes":"\(spki)","keyDetails":"ML_DSA_44","validFor":{"start":"2025-01-01T00:00:00Z"}},"logId":{"keyId":"AAAA"}}]}
            """.utf8)
        }
        let tr = try TrustedRoot(json: root(v.checkpoint.spki))
        guard case .mlDSA(let k)? = tr.rekorLogs.values.first?.publicKey else {
            Issue.record("expected an ML-DSA log key")
            return
        }
        #expect(k.parameterSet == .mlDSA44)
        // An ML-DSA-65 key declared as ML_DSA_44 is rejected.
        #expect { try TrustedRoot(json: root(v.keys[1].spki)) } throws: { "\($0)".contains("not ML-DSA-44") }
    }
}
