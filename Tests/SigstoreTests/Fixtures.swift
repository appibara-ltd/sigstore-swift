import Foundation
import Sigstore

enum Fixtures {
    /// sha256 of appitool v0.11.0 `appitool-darwin-arm64.tar.gz`.
    static let artifactDigestHex = "b5eeec2e36db5cfbdda72707ac80b3c807cab76631a35cf618739e29d331f0ce"
    static let githubIssuer = "https://token.actions.githubusercontent.com"
    static let workflowSANRegex = #"^https://github\.com/appibara-ltd/appitool/\.github/workflows/release\.yml@"#
    static let slsaProvenanceV1 = "https://slsa.dev/provenance/v1"

    static var artifactDigest: Data { Data(Hex.decode(artifactDigestHex)!) }

    static func data(_ name: String) throws -> Data {
        guard
            let url = Foundation.Bundle.module.url(
                forResource: name, withExtension: nil, subdirectory: "Fixtures/appitool-v0.11.0")
        else {
            throw SigstoreError("fixture \(name) not found")
        }
        return try Data(contentsOf: url)
    }

    static func provenanceJSON() throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: data("provenance.sigstore.json")) as! [String: Any]
    }

    static func provenanceBundle() throws -> SigstoreBundle.Bundle {
        try SigstoreBundle.Bundle(json: data("provenance.sigstore.json"))
    }

    /// Re-serializes a modified bundle JSON object.
    static func bundle(from json: [String: Any]) throws -> SigstoreBundle.Bundle {
        try SigstoreBundle.Bundle(json: JSONSerialization.data(withJSONObject: json))
    }

    /// Copy of the embedded public-good trusted root, for building variants.
    static func trustedRootProtobuf() throws -> Dev_Sigstore_Trustroot_V1_TrustedRoot {
        guard
            let url = Foundation.Bundle.module.url(
                forResource: "trusted_root", withExtension: "json", subdirectory: "Fixtures")
        else { throw SigstoreError("trusted_root.json fixture not found") }
        return try newTrustedRootProtobuf(Data(contentsOf: url))
    }

    static func trustedRoot() throws -> TrustedRoot {
        try TrustedRoot.embeddedPublicGood()
    }

    /// The verifier configuration `gh attestation verify` uses for the
    /// public-good instance.
    static func publicGoodVerifier(_ trustedMaterial: (any TrustedMaterial)? = nil) throws -> Verifier {
        try Verifier(
            trustedMaterial: trustedMaterial ?? trustedRoot(),
            options: [
                .withSignedCertificateTimestamps(threshold: 1),
                .withTransparencyLog(threshold: 1),
                .withObserverTimestamps(threshold: 1),
            ])
    }

    static func releaseWorkflowIdentity() throws -> CertificateIdentity {
        try CertificateIdentity(issuer: githubIssuer, sanValue: "", sanRegex: workflowSANRegex)
    }

    static func policy(digest: Data = artifactDigest, identity: CertificateIdentity? = nil) throws -> PolicyBuilder {
        PolicyBuilder(
            .withArtifactDigest(algorithm: "sha256", digest: digest),
            .withCertificateIdentity(try identity ?? releaseWorkflowIdentity()))
    }
}
