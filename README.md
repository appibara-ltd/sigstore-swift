# sigstore-swift

A Swift port of the verification side of
[sigstore-go](https://github.com/sigstore/sigstore-go). **Early development:
not yet security-reviewed; do not rely on it for production decisions.**

Status and roadmap: [PROGRESS.md](PROGRESS.md).

## Requirements

Swift 6.4, macOS 13+, Linux or Windows.

```swift
.package(url: "https://github.com/appibara-ltd/sigstore-swift.git", branch: "main")
```

## Verifying a GitHub artifact attestation

```swift
import Foundation
import Sigstore

// Fetches trusted_root.json from the public-good TUF repository
// (cached in ~/.sigstore/root, like sigstore-go).
let trustedRoot = try await fetchTrustedRoot()
let verifier = try Verifier(
    trustedMaterial: trustedRoot,
    options: [
        .withSignedCertificateTimestamps(threshold: 1),
        .withTransparencyLog(threshold: 1),
        .withObserverTimestamps(threshold: 1),
    ])

let bundle = try SigstoreBundle.Bundle(json: bundleJSON)
let identity = try CertificateIdentity(
    issuer: "https://token.actions.githubusercontent.com",
    sanValue: "",
    sanRegex: #"^https://github\.com/OWNER/REPO/\.github/workflows/release\.yml@"#)

let result = try await verifier.verify(
    bundle,
    policy: PolicyBuilder(
        .withArtifactDigest(algorithm: "sha256", digest: artifactSHA256),
        .withCertificateIdentity(identity)))

guard result.statement?.predicateType == "https://slsa.dev/provenance/v1" else {
    throw MyError.unexpectedPredicate
}
```

## Other Sigstore instances

`SigstoreTUF.Options` points the TUF client at another repository. For
example, GitHub's instance (private-repo and release attestations), as `gh`
configures it with its embedded `root.json`:

```swift
let opts = SigstoreTUF.Options()
    .withRoot(githubTUFRoot)  // gh: pkg/cmd/attestation/verification/embed/tuf-repo.github.com/root.json
    .withRepositoryBaseURL("https://tuf-repo.github.com")
let githubTrustedRoot = try await fetchTrustedRootWithOptions(opts)
```

## Conformance

The `sigstore-swift-conformance` executable implements the verify half of the
[sigstore-conformance](https://github.com/sigstore/sigstore-conformance) CLI
protocol. Run the suite locally (needs `uv`):

```bash
scripts/run-conformance.sh
```

## Regenerating protobuf types

```bash
brew install protobuf swift-protobuf
./scripts/generate-protos.sh
```

## License

Apache-2.0. Portions are ports of sigstore-go, rekor, rekor-tiles,
timestamp-authority, go-tuf, certificate-transparency-go and related Go
libraries (Apache-2.0, BSD and MIT licensed).
