import Foundation
import Sigstore
import Testing

/// Compares `VerificationResult.jsonData()` with sigstore-go v1.4.1's
/// `json.Marshal(result)` for the same bundles and policies
/// (`scripts/verificationresult-reference`, run with TZ=UTC).
@Suite("VerificationResult JSON (sigstore-go parity)")
struct VerificationResultJSONTests {
    private func goReference(_ name: String) throws -> JSONValue {
        let url = try #require(Foundation.Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
        return try JSONValue(parsing: Data(contentsOf: url))
    }

    @Test func provenanceResultMatchesGo() async throws {
        let result = try await Fixtures.publicGoodVerifier().verify(Fixtures.provenanceBundle(), policy: Fixtures.policy())
        let ours = try JSONValue(parsing: result.jsonData())
        #expect(ours == (try goReference("verification-result-provenance.go")))
    }

    @Test func releaseResultMatchesGo() async throws {
        let bundle = try SigstoreBundle.Bundle(json: Fixtures.data("release.sigstore.json"))
        let verifier = try Verifier(trustedMaterial: Fixtures.githubTrustedRoot(), options: [.withSignedTimestamps(threshold: 1)])
        let policy = PolicyBuilder(
            .withArtifactDigest(algorithm: "sha256", digest: Fixtures.artifactDigest),
            .withCertificateIdentity(
                try CertificateIdentity(issuer: "", issuerRegex: ".*", sanValue: Fixtures.githubReleasesSAN)))
        let result = try await verifier.verify(bundle, policy: policy)
        #expect(try JSONValue(parsing: result.jsonData()) == (try goReference("verification-result-release.go")))
    }

    @Test func roundTrips() async throws {
        let result = try await Fixtures.publicGoodVerifier().verify(Fixtures.provenanceBundle(), policy: Fixtures.policy())
        let decoded = try VerificationResult(json: result.jsonData())
        #expect(try JSONValue(parsing: decoded.jsonData()) == (try JSONValue(parsing: result.jsonData())))
        #expect(decoded.statement?.predicateType == "https://slsa.dev/provenance/v1")
    }
}
