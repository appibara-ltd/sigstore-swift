import Foundation
import Sigstore
import Testing

/// sigstore-go v1.4.1 `bundle.BundleV2` and the v2 verifier scaffolding.
@Suite("Bundle v2")
struct BundleV2Tests {
    private let mediaType = "application/vnd.dev.sigstore.bundle.v2.0+json"
    private let sig = Data("signature".utf8).base64EncodedString()

    private func bundle(_ material: String, payload: String? = nil, mediaType: String? = nil) throws -> BundleV2 {
        var json = #"{"mediaType":"\#(mediaType ?? self.mediaType)","verificationMaterial":\#(material)"#
        if let payload { json += #","payload":\#(payload)"# }
        return try BundleV2(json: Data((json + "}").utf8))
    }

    @Test func publicKeyBundleWithEnvelope() throws {
        let payload = Data("{}".utf8).base64EncodedString()
        let b = try bundle(
            #"{"publicKey":{"signature":{"signature":"\#(sig)"},"timestamps":{"rfc3161Timestamps":[{"signedTimestamp":"AQID"}]}}}"#,
            payload: #"{"payloadType":"application/vnd.in-toto+json","payload":"\#(payload)"}"#)
        #expect(b.hasPublicKey && b.hasEnvelope && !b.hasCertificate && !b.hasTransparencyLogProof)
        #expect(try b.version() == "v2.0")
        #expect(try b.signature() == Data("signature".utf8))
        #expect(try b.timestamps() == [Data([1, 2, 3])])
        let env = try b.envelope().rawEnvelope
        #expect(env.payloadType == "application/vnd.in-toto+json" && env.signatures.first?.sig == Data("signature".utf8))
        #expect(throws: (any Error).self) { try b.certificate() }
        #expect(throws: (any Error).self) { try b.transparencyLogProof() }
    }

    @Test func transparencyLogProofBundle() throws {
        let b = try bundle(#"{"transparencyLogProof":{"proof":"AAEC","signature":{"signature":"\#(sig)"}}}"#)
        #expect(try b.transparencyLogProof().proof == Data([0, 1, 2]))
        #expect(try b.timestamps().isEmpty)
    }

    @Test(arguments: [
        #"{"transparencyLogProof":{"proof":""}}"#,  // empty proof
        #"{"transparencyLogProof":{"proof":"AAEC","signature":{}}}"#,  // empty signature present
        #"{"publicKey":{"signature":{}}}"#,  // empty signature
        #"{"certificate":{"certificate":{"rawBytes":"AQ=="},"signature":{"signature":"c2ln"}}}"#,  // no timestamps
        #"{}"#,  // no content
    ])
    func missingVerificationMaterialIsRejected(_ material: String) {
        #expect { try bundle(material) } throws: { "\($0)".contains("missing verification material") }
    }

    @Test func emptyPayloadTypeIsRejected() {
        #expect { try bundle(#"{"publicKey":{"signature":{"signature":"\#(sig)"}}}"#, payload: #"{"payload":"AQ=="}"#) } throws: {
            "\($0)".contains("missing valid envelope")
        }
    }

    @Test func onlyVersion2IsAccepted() {
        #expect { try bundle(#"{"publicKey":{"signature":{"signature":"\#(sig)"}}}"#, mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json") } throws: {
            "\($0)".contains("is not a supported v2 bundle")
        }
    }

    @Test func v2VerifiersAreNotImplementedAsInSigstoreGo() throws {
        let root = try Fixtures.trustedRoot()
        let b = try bundle(#"{"publicKey":{"signature":{"signature":"\#(sig)"}}}"#)
        let policy = PolicyBuilder(.withoutArtifactUnsafe(), .withoutIdentitiesUnsafe())
        #expect(throws: NotImplementedError.self) { try IdentityVerifier(trustedMaterial: root).verify(b, policy: policy) }
        let pki = try PKIVerifier(trustedMaterial: root)
        #expect(pki.signedTimestampThreshold == 1)
        #expect(throws: NotImplementedError.self) { try pki.verify(b, policy: policy) }
        #expect(try KeyVerifier(trustedMaterial: root).signedTimestampThreshold == 0)
        #expect(try KeyVerifier(trustedMaterial: root, options: [.withKeySignedTimestamps(threshold: 2)]).signedTimestampThreshold == 2)
        #expect(throws: (any Error).self) { try PKIVerifier(trustedMaterial: root, options: [.withPKISignedTimestamps(threshold: 0)]) }
        #expect(throws: (any Error).self) { try KeyVerifier(trustedMaterial: root, options: [.withKeySignedTimestamps(threshold: 0)]) }
    }
}
