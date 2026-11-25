import Foundation
import Sigstore
import Testing

@Suite("Tampered / mismatched provenance must fail")
struct NegativeVerificationTests {
    private func expectFailure(
        _ bundle: SigstoreBundle.Bundle,
        policy: PolicyBuilder? = nil,
        verifier: Verifier? = nil,
        containing fragment: String,
        sourceLocation: SourceLocation = #_sourceLocation
    ) async throws {
        let v = try verifier ?? Fixtures.publicGoodVerifier()
        let p = try policy ?? Fixtures.policy()
        do {
            _ = try await v.verify(bundle, policy: p)
            Issue.record("verification unexpectedly succeeded", sourceLocation: sourceLocation)
        } catch {
            #expect("\(error)".contains(fragment), "unexpected error: \(error)", sourceLocation: sourceLocation)
        }
    }

    private func mutate(_ body: (inout [String: Any]) throws -> Void) throws -> SigstoreBundle.Bundle {
        var json = try Fixtures.provenanceJSON()
        try body(&json)
        return try Fixtures.bundle(from: json)
    }

    @Test func tamperedPayloadFails() async throws {
        let bundle = try mutate { json in
            var env = json["dsseEnvelope"] as! [String: Any]
            var payload = Data(base64Encoded: env["payload"] as! String)!
            // Flip a byte inside the statement JSON (keeps it parseable).
            let text = String(decoding: payload, as: UTF8.self)
                .replacingOccurrences(of: "appitool-linux-arm64", with: "appitool-linux-arm65")
            payload = Data(text.utf8)
            env["payload"] = payload.base64EncodedString()
            json["dsseEnvelope"] = env
        }
        // The tlog entry pins the payload hash, so this fails before the signature check.
        try await expectFailure(bundle, containing: "payload hash")
    }

    @Test func tamperedPayloadFailsDSSESignatureCheck() throws {
        // Exercise the DSSE signature check directly (in `verify` the tlog
        // payload-hash check fires first).
        let bundle = try mutate { json in
            var env = json["dsseEnvelope"] as! [String: Any]
            let text = String(decoding: Data(base64Encoded: env["payload"] as! String)!, as: UTF8.self)
                .replacingOccurrences(of: "appitool-linux-arm64", with: "appitool-linux-arm65")
            env["payload"] = Data(text.utf8).base64EncodedString()
            json["dsseEnvelope"] = env
        }
        #expect(throws: (any Error).self) {
            try verifySignatureWithArtifactDigests(
                bundle.signatureContent(), bundle.verificationContent(),
                trustedMaterial: Fixtures.trustedRoot(),
                digests: [ArtifactDigest(algorithm: "sha256", digest: Fixtures.artifactDigest)])
        }
        // Sanity: the untampered bundle passes the same check.
        let good = try Fixtures.provenanceBundle()
        try verifySignatureWithArtifactDigests(
            good.signatureContent(), good.verificationContent(),
            trustedMaterial: Fixtures.trustedRoot(),
            digests: [ArtifactDigest(algorithm: "sha256", digest: Fixtures.artifactDigest)])
    }

    @Test func tamperedSignatureFails() async throws {
        let bundle = try mutate { json in
            var env = json["dsseEnvelope"] as! [String: Any]
            var sigs = env["signatures"] as! [[String: Any]]
            var sig = Data(base64Encoded: sigs[0]["sig"] as! String)!
            sig[sig.count - 1] ^= 0x01
            sigs[0]["sig"] = sig.base64EncodedString()
            env["signatures"] = sigs
            json["dsseEnvelope"] = env
        }
        try await expectFailure(bundle, containing: "signature does not match")
    }

    @Test func wrongWorkflowFails() async throws {
        let identity = try CertificateIdentity(
            issuer: Fixtures.githubIssuer, sanValue: "",
            sanRegex: #"^https://github\.com/appibara-ltd/appitool/\.github/workflows/other\.yml@"#)
        try await expectFailure(
            Fixtures.provenanceBundle(), policy: Fixtures.policy(identity: identity),
            containing: "expected SAN value to match regex")
    }

    @Test func wrongRepositoryFails() async throws {
        let identity = try CertificateIdentity(
            issuer: Fixtures.githubIssuer, sanValue: "",
            sanRegex: #"^https://github\.com/someone-else/appitool/"#)
        try await expectFailure(
            Fixtures.provenanceBundle(), policy: Fixtures.policy(identity: identity),
            containing: "no matching CertificateIdentity")
    }

    @Test func wrongIssuerFails() async throws {
        let identity = try CertificateIdentity(
            issuer: "https://accounts.google.com", sanValue: "", sanRegex: Fixtures.workflowSANRegex)
        try await expectFailure(
            Fixtures.provenanceBundle(), policy: Fixtures.policy(identity: identity),
            containing: "expected issuer value")
    }

    @Test func wrongDigestFails() async throws {
        var digest = Fixtures.artifactDigest
        digest[0] ^= 0xFF
        try await expectFailure(
            Fixtures.provenanceBundle(), policy: Fixtures.policy(digest: digest),
            containing: "does not match any digest in statement")
    }

    @Test func wrongArtifactBytesFail() async throws {
        let policy = PolicyBuilder(
            .withArtifact(Data("not the tarball".utf8)),
            .withCertificateIdentity(try Fixtures.releaseWorkflowIdentity()))
        try await expectFailure(
            Fixtures.provenanceBundle(), policy: policy,
            containing: "provided artifact digests do not match digests in statement")
    }

    @Test func expiredCertificateAtCurrentTimeFails() async throws {
        // Without the tlog's integrated time the only observer time is "now",
        // long after the 10-minute Fulcio certificate expired.
        let verifier = try Verifier(
            trustedMaterial: Fixtures.trustedRoot(),
            options: [.withSignedCertificateTimestamps(threshold: 1), .withCurrentTime()])
        try await expectFailure(
            Fixtures.provenanceBundle(), verifier: verifier, containing: "failed to verify leaf certificate")
    }

    @Test func certificateAuthorityOutOfWindowFails() async throws {
        // Trusted root whose Fulcio CAs stopped being valid before signing.
        var root = try Fixtures.trustedRootProtobuf()
        for i in root.certificateAuthorities.indices {
            root.certificateAuthorities[i].validFor.end = .init(date: Date(timeIntervalSince1970: 1_700_000_000))
        }
        let verifier = try Fixtures.publicGoodVerifier(TrustedRoot(protobuf: root))
        try await expectFailure(
            Fixtures.provenanceBundle(), verifier: verifier, containing: "certificate is no longer valid")
    }

    @Test func integratedTimeTamperingBreaksSET() async throws {
        let bundle = try mutate { json in
            var vm = json["verificationMaterial"] as! [String: Any]
            var entries = vm["tlogEntries"] as! [[String: Any]]
            entries[0]["integratedTime"] = String(Int(entries[0]["integratedTime"] as! String)! + 60)
            vm["tlogEntries"] = entries
            json["verificationMaterial"] = vm
        }
        // Go skips entries whose SET fails, so the threshold is not met.
        try await expectFailure(bundle, containing: "not enough verified log entries")
    }

    @Test func tamperedInclusionProofFails() async throws {
        let bundle = try mutate { json in
            var vm = json["verificationMaterial"] as! [String: Any]
            var entries = vm["tlogEntries"] as! [[String: Any]]
            var proof = entries[0]["inclusionProof"] as! [String: Any]
            var hashes = proof["hashes"] as! [String]
            var h = Data(base64Encoded: hashes[0])!
            h[0] ^= 0x01
            hashes[0] = h.base64EncodedString()
            proof["hashes"] = hashes
            entries[0]["inclusionProof"] = proof
            vm["tlogEntries"] = entries
            json["verificationMaterial"] = vm
        }
        try await expectFailure(bundle, containing: "does not match expected root")
    }

    @Test func tamperedCheckpointSignatureFails() async throws {
        let bundle = try mutate { json in
            var vm = json["verificationMaterial"] as! [String: Any]
            var entries = vm["tlogEntries"] as! [[String: Any]]
            var proof = entries[0]["inclusionProof"] as! [String: Any]
            var checkpoint = proof["checkpoint"] as! [String: Any]
            let envelope = checkpoint["envelope"] as! String
            checkpoint["envelope"] = envelope.replacingOccurrences(of: "3961978411\n", with: "3961978412\n")
            proof["checkpoint"] = checkpoint
            entries[0]["inclusionProof"] = proof
            vm["tlogEntries"] = entries
            json["verificationMaterial"] = vm
        }
        try await expectFailure(bundle, containing: "signature on checkpoint did not verify")
    }

    @Test func untrustedRekorLogFails() async throws {
        var root = try Fixtures.trustedRootProtobuf()
        root.tlogs.removeAll { $0.baseURL == "https://rekor.sigstore.dev" }
        let verifier = try Fixtures.publicGoodVerifier(TrustedRoot(protobuf: root))
        try await expectFailure(
            Fixtures.provenanceBundle(), verifier: verifier, containing: "not enough verified log entries")
    }

    @Test func untrustedCTLogFails() async throws {
        var root = try Fixtures.trustedRootProtobuf()
        root.ctlogs.removeAll()
        let verifier = try Fixtures.publicGoodVerifier(TrustedRoot(protobuf: root))
        try await expectFailure(
            Fixtures.provenanceBundle(), verifier: verifier, containing: "unable to meet threshold")
    }

    @Test func swappedCertificateFails() async throws {
        // Replace the leaf with the Fulcio intermediate: the tlog entry no
        // longer matches the bundle's certificate.
        let root = try Fixtures.trustedRootProtobuf()
        let intermediate = root.certificateAuthorities.last!.certChain.certificates.first!.rawBytes
        let bundle = try mutate { json in
            var vm = json["verificationMaterial"] as! [String: Any]
            vm["certificate"] = ["rawBytes": intermediate.base64EncodedString()]
            json["verificationMaterial"] = vm
        }
        try await expectFailure(bundle, containing: "transparency log certificate does not match")
    }
}
