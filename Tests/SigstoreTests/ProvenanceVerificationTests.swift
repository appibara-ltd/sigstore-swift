import Foundation
import Sigstore
import Testing

@Suite("GitHub SLSA provenance (appitool v0.11.0)")
struct ProvenanceVerificationTests {
    @Test func verifiesProvenanceBundle() async throws {
        let bundle = try Fixtures.provenanceBundle()
        #expect(try bundle.version() == "v0.3")
        #expect(bundle.hasInclusionProof)
        #expect(bundle.hasInclusionPromise)

        let result = try await Fixtures.publicGoodVerifier().verify(bundle, policy: Fixtures.policy())

        let statement = try #require(result.statement)
        #expect(statement.predicateType == Fixtures.slsaProvenanceV1)
        #expect(statement.type == "https://in-toto.io/Statement/v1")
        #expect(statement.predicate != nil)
        #expect(statement.subject.contains { $0.digest["sha256"] == Fixtures.artifactDigestHex })

        let cert = try #require(result.signature?.certificate)
        #expect(cert.extensions.issuer == Fixtures.githubIssuer)
        #expect(
            cert.subjectAlternativeName
                == "https://github.com/appibara-ltd/appitool/.github/workflows/release.yml@refs/tags/v0.11.0")
        #expect(cert.extensions.sourceRepositoryURI == "https://github.com/appibara-ltd/appitool")
        #expect(cert.extensions.buildSignerURI.hasPrefix(
            "https://github.com/appibara-ltd/appitool/.github/workflows/release.yml@"))

        #expect(result.verifiedIdentity != nil)
        #expect(result.verifiedTimestamps.count == 1)
        #expect(result.verifiedTimestamps.first?.type == "Tlog")
        #expect(result.verifiedTimestamps.first?.uri == "https://rekor.sigstore.dev")
    }

    @Test func verifiesWithExactSANAndExtensions() async throws {
        // Exact SAN plus extension constraints (as gh's --signer-workflow does).
        var ext = Extensions()
        ext.sourceRepositoryURI = "https://github.com/appibara-ltd/appitool"
        ext.runnerEnvironment = "github-hosted"
        let identity = try CertificateIdentity(
            subjectAlternativeName: SubjectAlternativeNameMatcher(
                "https://github.com/appibara-ltd/appitool/.github/workflows/release.yml@refs/tags/v0.11.0"),
            issuer: IssuerMatcher(Fixtures.githubIssuer),
            extensions: ext)
        let result = try await Fixtures.publicGoodVerifier().verify(
            Fixtures.provenanceBundle(), policy: Fixtures.policy(identity: identity))
        #expect(result.verifiedIdentity == identity)
    }

    @Test func omitsPredicateWhenConfigured() async throws {
        let verifier = try Verifier(
            trustedMaterial: Fixtures.trustedRoot(),
            options: [
                .withSignedCertificateTimestamps(threshold: 1),
                .withTransparencyLog(threshold: 1),
                .withObserverTimestamps(threshold: 1),
                .withoutStatementPredicate(),
            ])
        let result = try await verifier.verify(Fixtures.provenanceBundle(), policy: Fixtures.policy())
        #expect(result.statement?.predicate == nil)
        #expect(result.statement?.predicateType == Fixtures.slsaProvenanceV1)
    }

    @Test func releaseBundleParsesButNeedsTSA() async throws {
        // TSA-only bundle from GitHub's own Sigstore instance: not verifiable
        // until RFC 3161 support and GitHub's trusted root are added.
        let bundle = try SigstoreBundle.Bundle(json: Fixtures.data("release.sigstore.json"))
        #expect(try bundle.tlogEntries().isEmpty)
        #expect(try bundle.timestamps().count == 1)
        await #expect(throws: (any Error).self) {
            _ = try await Fixtures.publicGoodVerifier().verify(bundle, policy: Fixtures.policy())
        }
    }
}
