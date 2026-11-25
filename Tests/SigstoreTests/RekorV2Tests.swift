import Crypto
import Foundation
import Sigstore
import Testing

/// sigstore-conformance (Apache-2.0) Rekor v2 bundles from the staging
/// `log2025-alpha1` log, with their custom trusted roots and `a.txt`.
private enum RekorV2Fixture: String {
    case hashedRekord = "rekor2-happy-path"
    case dsse = "rekor2-dsse-happy-path"

    static let san =
        "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
    static let issuer = "https://token.actions.githubusercontent.com"
    static let logHost = "log2025-alpha1.rekor.sigstage.dev"

    func data(_ name: String) throws -> Data {
        guard
            let url = Foundation.Bundle.module.url(
                forResource: name, withExtension: nil, subdirectory: "Fixtures/conformance/\(rawValue)")
        else { throw SigstoreError("fixture \(rawValue)/\(name) not found") }
        return try Data(contentsOf: url)
    }

    func json(_ name: String) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: data(name)) as! [String: Any]
    }

    func bundle(_ mutate: (inout [String: Any]) throws -> Void = { _ in }) throws -> SigstoreBundle.Bundle {
        var json = try json("bundle.sigstore.json")
        try mutate(&json)
        return try SigstoreBundle.Bundle(json: JSONSerialization.data(withJSONObject: json))
    }

    func trustedRoot(_ mutate: (inout [String: Any]) throws -> Void = { _ in }) throws -> TrustedRoot {
        var json = try json("trusted_root.json")
        try mutate(&json)
        return try TrustedRoot(json: JSONSerialization.data(withJSONObject: json))
    }

    func verify(_ bundle: SigstoreBundle.Bundle, root: TrustedRoot? = nil) async throws -> VerificationResult {
        let verifier = try Verifier(
            trustedMaterial: root ?? trustedRoot(),
            options: [.withSignedCertificateTimestamps(threshold: 1), .withTransparencyLog(threshold: 1),
                .withSignedTimestamps(threshold: 1)])
        let policy = PolicyBuilder(
            .withArtifact(try data("artifact")),
            .withCertificateIdentity(try CertificateIdentity(issuer: Self.issuer, sanValue: Self.san)))
        return try await verifier.verify(bundle, policy: policy)
    }
}

/// Mutates the first tlog entry of a bundle JSON object.
private func mutateEntry(_ json: inout [String: Any], _ body: (inout [String: Any]) -> Void) {
    var vm = json["verificationMaterial"] as! [String: Any]
    var entries = vm["tlogEntries"] as! [[String: Any]]
    body(&entries[0])
    vm["tlogEntries"] = entries
    json["verificationMaterial"] = vm
}

/// Mutates the decoded canonicalized body of the first tlog entry.
private func mutateBody(_ json: inout [String: Any], _ body: (inout [String: Any]) -> Void) {
    mutateEntry(&json) { entry in
        let raw = Data(base64Encoded: entry["canonicalizedBody"] as! String)!
        var obj = try! JSONSerialization.jsonObject(with: raw) as! [String: Any]
        body(&obj)
        entry["canonicalizedBody"] = try! JSONSerialization.data(withJSONObject: obj).base64EncodedString()
    }
}

/// Sets the Rekor v2 log's baseUrl in a trusted root JSON object.
private func setV2BaseURL(_ json: inout [String: Any], _ url: String?) {
    var tlogs = json["tlogs"] as! [[String: Any]]
    for i in tlogs.indices where (tlogs[i]["baseUrl"] as? String)?.contains(RekorV2Fixture.logHost) == true {
        if let url { tlogs[i]["baseUrl"] = url } else { tlogs[i].removeValue(forKey: "baseUrl") }
    }
    json["tlogs"] = tlogs
}

@Suite("Rekor v2 log entries")
struct RekorV2Tests {
    @Test(arguments: [RekorV2Fixture.hashedRekord, .dsse])
    fileprivate func happyPathVerifies(_ fixture: RekorV2Fixture) async throws {
        let bundle = try fixture.bundle()
        let entry = try #require(bundle.tlogEntries().first)
        #expect(entry.isRekorV2)
        #expect(entry.kind == "hashedrekord" && entry.version == "0.0.2")
        #expect(!entry.hasInclusionPromise)
        let result = try await fixture.verify(bundle)
        // Rekor v2 entries carry no signed time; the TSA provides it.
        #expect(result.verifiedTimestamps.map(\.type) == ["TimestampAuthority"])
    }

    /// The reconstructed entry (protojson + JCS) must hash to the leaf Rekor
    /// logged: SHA-256(0x00 || canonicalizedBody).
    @Test(arguments: [RekorV2Fixture.hashedRekord, .dsse])
    fileprivate func entryHashMatchesLoggedBody(_ fixture: RekorV2Fixture) throws {
        let entry = try #require(fixture.bundle().tlogEntries().first)
        guard case .hashedRekordV002(let hr) = entry.rekorV2Entry?.spec.spec else {
            Issue.record("not a hashedrekord 0.0.2 entry")
            return
        }
        let hash = try hashedRekordEntryHash(digest: Array(hr.data.digest), signature: hr.signature)
        #expect(hash == Merkle.hashLeaf(entry.transparencyLogEntry.canonicalizedBody))
    }

    @Test func noteKeyHashMatchesCheckpointSignature() throws {
        let root = try RekorV2Fixture.hashedRekord.trustedRoot()
        let log = try #require(root.rekorLogs.values.first { $0.baseURL.contains(RekorV2Fixture.logHost) })
        let verifier = try SignatureVerifier(publicKey: log.publicKey, hashFunction: log.signatureHashFunc)
        // The checkpoint's signature line is "— <origin> <base64(keyhash || sig)>".
        let envelope = try #require(RekorV2Fixture.hashedRekord.bundle().tlogEntries().first)
            .transparencyLogEntry.inclusionProof.checkpoint.envelope
        let line = try #require(envelope.split(separator: "\n").last { $0.hasPrefix("\u{2014} ") })
        let sig = try #require(Data(base64Encoded: String(line.split(separator: " ")[2])))
        let hint = sig.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        #expect(try noteKeyHash(origin: RekorV2Fixture.logHost, verifier: verifier) == hint)
        // Ed25519 key hashes bind the origin.
        #expect(try noteKeyHash(origin: "other.example", verifier: verifier) != hint)
    }

    // MARK: Negative

    @Test func tamperedCheckpointSignatureFails() async throws {
        let bundle = try RekorV2Fixture.hashedRekord.bundle { json in
            mutateEntry(&json) { entry in
                var proof = entry["inclusionProof"] as! [String: Any]
                var cp = proof["checkpoint"] as! [String: Any]
                var env = cp["envelope"] as! String
                // Flip a character of the signature (last line, before "\n").
                let i = env.index(env.endIndex, offsetBy: -6)
                env.replaceSubrange(i...i, with: env[i] == "A" ? "B" : "A")
                cp["envelope"] = env
                proof["checkpoint"] = cp
                entry["inclusionProof"] = proof
            }
        }
        await expectFailure("verifying log entry: unverified checkpoint signature") {
            _ = try await RekorV2Fixture.hashedRekord.verify(bundle)
        }
    }

    @Test func tamperedCheckpointTextFails() async throws {
        let bundle = try RekorV2Fixture.hashedRekord.bundle { json in
            mutateEntry(&json) { entry in
                var proof = entry["inclusionProof"] as! [String: Any]
                var cp = proof["checkpoint"] as! [String: Any]
                let env = cp["envelope"] as! String
                var lines = env.components(separatedBy: "\n")
                lines[1] = String(UInt64(lines[1])! + 1)  // tree size
                cp["envelope"] = lines.joined(separator: "\n")
                proof["checkpoint"] = cp
                entry["inclusionProof"] = proof
            }
        }
        await expectFailure("invalid signature for key \(RekorV2Fixture.logHost)") {
            _ = try await RekorV2Fixture.hashedRekord.verify(bundle)
        }
    }

    @Test func checkpointFromAnotherOriginFails() async throws {
        let root = try RekorV2Fixture.hashedRekord.trustedRoot { setV2BaseURL(&$0, "https://log.example.com") }
        await expectFailure("note has no verifiable signatures") {
            _ = try await RekorV2Fixture.hashedRekord.verify(RekorV2Fixture.hashedRekord.bundle(), root: root)
        }
    }

    @Test func missingBaseURLFails() async throws {
        let root = try RekorV2Fixture.hashedRekord.trustedRoot { setV2BaseURL(&$0, nil) }
        await expectFailure("cannot verify Rekor v2 entry without baseUrl") {
            _ = try await RekorV2Fixture.hashedRekord.verify(RekorV2Fixture.hashedRekord.bundle(), root: root)
        }
    }

    @Test func signatureNotInLogFails() async throws {
        // A different (still well-formed) signature reconstructs another entry.
        let bundle = try RekorV2Fixture.hashedRekord.bundle { json in
            var ms = json["messageSignature"] as! [String: Any]
            var sig = Data(base64Encoded: ms["signature"] as! String)!
            sig[sig.count - 1] ^= 0x01
            ms["signature"] = sig.base64EncodedString()
            json["messageSignature"] = ms
        }
        await expectFailure("verifying log entry: verifying inclusion") {
            _ = try await RekorV2Fixture.hashedRekord.verify(bundle)
        }
    }

    @Test func envelopeNotInLogFails() async throws {
        let bundle = try RekorV2Fixture.dsse.bundle { json in
            var env = json["dsseEnvelope"] as! [String: Any]
            env["payloadType"] = "application/vnd.in-toto+json; tampered"
            json["dsseEnvelope"] = env
        }
        await expectFailure("verifying log entry: verifying inclusion") {
            _ = try await RekorV2Fixture.dsse.verify(bundle)
        }
    }

    @Test func entryWithoutVerifierFails() async throws {
        let bundle = try RekorV2Fixture.hashedRekord.bundle { json in
            mutateBody(&json) { body in
                var spec = body["spec"] as! [String: Any]
                var hr = spec["hashedRekordV002"] as! [String: Any]
                var sig = hr["signature"] as! [String: Any]
                sig.removeValue(forKey: "verifier")
                hr["signature"] = sig
                spec["hashedRekordV002"] = hr
                body["spec"] = spec
            }
        }
        await expectFailure("missing verifier") {
            _ = try await RekorV2Fixture.hashedRekord.verify(bundle)
        }
    }

    @Test func v2BodyWithWrongAPIVersionIsRejected() throws {
        #expect(throws: (any Error).self) {
            _ = try RekorV2Fixture.hashedRekord.bundle { json in
                mutateBody(&json) { $0["apiVersion"] = "0.0.1" }
                mutateEntry(&json) { entry in
                    entry["kindVersion"] = ["kind": "hashedrekord", "version": "0.0.1"]
                }
            }.tlogEntries()
        }
    }

    @Test func v2BodyWithUnknownFieldIsRejected() throws {
        #expect(throws: (any Error).self) {
            _ = try RekorV2Fixture.hashedRekord.bundle { json in
                mutateBody(&json) { $0["unknown"] = "x" }
            }.tlogEntries()
        }
    }
}

// MARK: - Signed notes

@Suite("Signed note checkpoints")
struct SignedNoteTests {
    let key = P256.Signing.PrivateKey()
    let origin = "log.test"

    var noteVerifier: NoteVerifier {
        get throws {
            try NoteVerifier(
                origin: origin,
                verifier: SignatureVerifier(publicKey: .init(key.publicKey), hashFunction: .sha256))
        }
    }

    func signatureLine(_ text: String, name: String? = nil, hash: UInt32? = nil, signer: P256.Signing.PrivateKey? = nil)
        throws -> String
    {
        let h = try hash ?? noteVerifier.keyHash
        let sig = try (signer ?? key).signature(for: Data(text.utf8)).derRepresentation
        let blob = withUnsafeBytes(of: h.bigEndian) { Data($0) } + sig
        return "\u{2014} \(name ?? origin) \(blob.base64EncodedString())\n"
    }

    var checkpointText: String { "\(origin)\n42\n\(Data(repeating: 7, count: 32).base64EncodedString())\n" }

    @Test func validCheckpointParses() throws {
        let note = checkpointText + "\n" + (try signatureLine(checkpointText))
        let cp = try parseCheckpoint(note, verifier: noteVerifier)
        #expect(cp == (try LogCheckpoint(text: checkpointText)))
        #expect(cp.size == 42 && cp.origin == origin)
    }

    @Test func extraUnknownSignaturesAreIgnored() throws {
        let other = P256.Signing.PrivateKey()
        let note = checkpointText + "\n"
            + (try signatureLine(checkpointText, name: "witness.test", hash: 1, signer: other))
            + (try signatureLine(checkpointText))
        let opened = try openNote(note, verifier: noteVerifier)
        #expect(opened.verifiedSignatures.count == 1)
        #expect(opened.unverifiedSignatureCount == 1)
    }

    @Test func badSignatureByKnownKeyFails() throws {
        let note = checkpointText + "\n" + (try signatureLine(checkpointText, signer: P256.Signing.PrivateKey()))
        #expect(throws: (any Error).self) { try openNote(note, verifier: noteVerifier) }
    }

    @Test func onlyUnknownSignaturesFail() throws {
        let note = checkpointText + "\n" + (try signatureLine(checkpointText, name: "other.test"))
        #expect { try openNote(note, verifier: noteVerifier) } throws: {
            "\($0)".contains("no verifiable signatures")
        }
    }

    @Test(arguments: [
        "log.test\n1\nAAAA\n\u{2014} log.test AAAAAAA=\n",  // no blank line before signatures
        "log.test\n1\nAAAA\n\n\u{2014} log.test AAAAAAA=",  // signature block not newline-terminated
        "log.test\n1\nAAAA\n\n- log.test AAAAAAA=\n",  // wrong prefix
        "log.test\n1\nAA\tAA\n\n\u{2014} log.test AAAAAAA=\n",  // control character
        "log.test\n1\nAAAA\n\n\u{2014} log.test AAAA\n",  // signature shorter than 5 bytes
        "log.test\n1\nAAAA\n\n\u{2014} log+test AAAAAAA=\n",  // invalid name
        "log.test\n1\nAAAA\n\n\u{2014} log.test\n",  // missing signature
    ])
    func malformedNotesFail(_ note: String) throws {
        #expect { try openNote(note, verifier: noteVerifier) } throws: { "\($0)".contains("malformed note") }
    }

    @Test func tooManySignaturesFail() throws {
        let line = try signatureLine(checkpointText, name: "w.test", hash: 9)
        let note = checkpointText + "\n" + String(repeating: line, count: 101)
        #expect { try openNote(note, verifier: noteVerifier) } throws: { "\($0)".contains("malformed note") }
    }

    @Test func originMismatchFails() throws {
        let text = "other.test\n42\n\(Data(repeating: 7, count: 32).base64EncodedString())\n"
        let note = text + "\n" + (try signatureLine(text))
        #expect { try parseCheckpoint(note, verifier: noteVerifier) } throws: {
            "\($0)".contains("but expected \"log.test\"")
        }
    }

    @Test(arguments: ["log.test\n+42\nAAAA\n", "log.test\n-1\nAAAA\n", "\n42\nAAAA\n", "log.test\n42\nnot base64\n",
        "log.test\n42\nAAAA"])
    func invalidCheckpointBodiesFail(_ text: String) {
        #expect(throws: (any Error).self) { try LogCheckpoint(text: text) }
    }

    @Test func invalidOriginIsRejected() throws {
        #expect(throws: (any Error).self) {
            try NoteVerifier(
                origin: "has space", verifier: SignatureVerifier(publicKey: .init(key.publicKey)))
        }
    }
}

// MARK: - JCS

@Suite("RFC 8785 canonicalization")
struct JSONCanonicalizerTests {
    @Test func sortsKeysAndMinimallyEscapes() throws {
        let input = #"{"b":1,"a":"x\u0001\"\/é","Z":[true,false,null],"c":{"y":"\n","x":-3}}"#
        let out = try JSONCanonicalizer.transform(Data(input.utf8))
        #expect(
            String(decoding: out, as: UTF8.self)
                == #"{"Z":[true,false,null],"a":"x\u0001\"/é","b":1,"c":{"x":-3,"y":"\n"}}"#)
    }

    @Test func sortsByUTF16CodeUnits() throws {
        // U+1F600 is the surrogate pair D83D DE00, which sorts before U+E000.
        let input = "{\"\u{E000}\":1,\"\u{1F600}\":2}"
        let out = String(decoding: try JSONCanonicalizer.transform(Data(input.utf8)), as: UTF8.self)
        #expect(out == "{\"\u{1F600}\":2,\"\u{E000}\":1}")
    }

    @Test func rejectsNonIntegerNumbers() {
        #expect(throws: (any Error).self) { try JSONCanonicalizer.transform(Data(#"{"a":1.5}"#.utf8)) }
    }
}

private func expectFailure(
    _ fragment: String, sourceLocation: SourceLocation = #_sourceLocation, _ body: () async throws -> Void
) async {
    do {
        try await body()
        Issue.record("expected an error containing \"\(fragment)\"", sourceLocation: sourceLocation)
    } catch {
        #expect("\(error)".contains(fragment), "unexpected error: \(error)", sourceLocation: sourceLocation)
    }
}
