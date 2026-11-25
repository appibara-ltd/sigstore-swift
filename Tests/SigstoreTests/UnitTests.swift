import Foundation
import Sigstore
import Testing

@Suite struct UnitTests {
    @Test func dssePAE() {
        // Example from the DSSE protocol spec.
        let pae = DSSEEnvelope.pae(payloadType: "http://example.com/HelloWorld", payload: Data("hello world".utf8))
        #expect(String(decoding: pae, as: UTF8.self) == "DSSEv1 29 http://example.com/HelloWorld 11 hello world")
    }

    @Test func merkleInclusionSmallTree() throws {
        // Tree of 3 leaves: root = H(H(l0,l1), l2).
        let leaves = (0..<3).map { Merkle.hashLeaf(Data([UInt8($0)])) }
        let n01 = Merkle.hashChildren(leaves[0], leaves[1])
        let root = Merkle.hashChildren(n01, leaves[2])
        try Merkle.verifyInclusion(index: 0, size: 3, leafHash: leaves[0], proof: [leaves[1], leaves[2]], root: root)
        try Merkle.verifyInclusion(index: 2, size: 3, leafHash: leaves[2], proof: [n01], root: root)
        #expect(throws: (any Error).self) {
            try Merkle.verifyInclusion(index: 1, size: 3, leafHash: leaves[1], proof: [leaves[2], leaves[0]], root: root)
        }
        #expect(throws: (any Error).self) {
            try Merkle.verifyInclusion(index: 3, size: 3, leafHash: leaves[2], proof: [n01], root: root)
        }
    }

    @Test func checkpointParsing() throws {
        let text = "rekor.sigstore.dev - 1193050959916656506\n3961978411\nnshVs/hw8jxpu4wy46drSDsIkKPLBRIWS29ls0tkE8A=\n\n\u{2014} rekor.sigstore.dev wNI9ajBGAiEA0DVLYew3Pp/1TQ/e4nUJ2eJ6047TL4iyofxnRn35NA0CIQCphxqseEBukhsptsjKZRgtmXlqlVGzQpFEzUc15bilLw==\n"
        let sc = try SignedCheckpoint(text: text)
        #expect(sc.checkpoint.origin == "rekor.sigstore.dev - 1193050959916656506")
        #expect(sc.checkpoint.size == 3961978411)
        #expect(sc.signedNote.signatures.count == 1)
        #expect(sc.signedNote.signatures[0].hash == 0xc0d2_3d6a)
        #expect(throws: (any Error).self) { try SignedCheckpoint(text: "no signature block") }
    }

    @Test func bundleMediaTypes() throws {
        #expect(try mediaTypeString("0.1") == "application/vnd.dev.sigstore.bundle+json;version=0.1")
        #expect(try mediaTypeString("v0.3") == "application/vnd.dev.sigstore.bundle.v0.3+json")
        var json = try Fixtures.provenanceJSON()
        json["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.4+json"
        #expect(throws: (any Error).self) { try Fixtures.bundle(from: json) }
        json["mediaType"] = "application/json"
        #expect(throws: (any Error).self) { try Fixtures.bundle(from: json) }
    }

    @Test func unknownBundleFieldsRejected() throws {
        var json = try Fixtures.provenanceJSON()
        json["unexpected"] = true
        #expect(throws: (any Error).self) { try Fixtures.bundle(from: json) }
    }

    @Test func trustedRootParses() throws {
        let root = try Fixtures.trustedRoot()
        #expect(root.rekorLogs.count == 2)
        #expect(root.ctLogs.count == 2)
        #expect(root.fulcioCertificateAuthorities.count == 2)
        #expect(root.timestampingAuthorities.count == 1)
    }

    @Test func verifierConfigValidation() throws {
        #expect(throws: (any Error).self) { try Verifier(trustedMaterial: Fixtures.trustedRoot(), options: []) }
        #expect(throws: (any Error).self) {
            try Verifier(trustedMaterial: Fixtures.trustedRoot(), options: [.withTransparencyLog(threshold: 0)])
        }
        #expect(throws: (any Error).self) {
            try Verifier(
                trustedMaterial: Fixtures.trustedRoot(), options: [.withNoObserverTimestamps(), .withCurrentTime()])
        }
    }

    @Test func policyValidation() throws {
        // Identities required by default.
        #expect(throws: (any Error).self) {
            try PolicyBuilder(.withArtifactDigest(algorithm: "sha256", digest: Fixtures.artifactDigest)).buildConfig()
        }
        #expect(throws: (any Error).self) {
            try PolicyBuilder(
                .withArtifactDigest(algorithm: "sha256", digest: Fixtures.artifactDigest),
                .withoutIdentitiesUnsafe(), .withCertificateIdentity(Fixtures.releaseWorkflowIdentity())
            ).buildConfig()
        }
        #expect(throws: (any Error).self) { try CertificateIdentity(issuer: "", sanValue: "x") }
        #expect(throws: (any Error).self) { try CertificateIdentity(issuer: "x", sanValue: "", sanRegex: "(") }
    }
}
