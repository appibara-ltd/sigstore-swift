// sigstore-conformance client for sigstore-swift.
//
// Implements the verify half of the CLI protocol
// (https://github.com/sigstore/sigstore-conformance/blob/main/docs/cli_protocol.md).
// Port of sigstore-go test/conformance/main.go (verify-bundle). Signing is
// not implemented yet; `sign-bundle` exits with an error.

import Foundation
import Sigstore
import X509

struct Arguments {
    var command = ""
    var bundlePath: String?
    var certOIDC: String?
    var certSAN: String?
    var keyPath: String?
    var staging = false
    var trustedRootPath: String?
    var fileOrDigest = ""

    /// Mirrors sigstore-go's `parseArgs`: flags in any order, the artifact is
    /// the last argument.
    init(_ argv: [String]) throws {
        guard argv.count >= 2 else { throw SigstoreError(usage) }
        command = argv[1]
        var i = 2
        func value() throws -> String {
            guard i + 1 < argv.count else { throw SigstoreError("missing value for \(argv[i])") }
            return argv[i + 1]
        }
        while i < argv.count {
            switch argv[i] {
            case "--bundle": bundlePath = try value(); i += 2
            case "--certificate-oidc-issuer": certOIDC = try value(); i += 2
            case "--certificate-identity": certSAN = try value(); i += 2
            case "--key": keyPath = try value(); i += 2
            case "--trusted-root": trustedRootPath = try value(); i += 2
            case "--identity-token", "--signing-config": i += 2
            case "--staging": staging = true; i += 1
            default: i += 1
            }
        }
        fileOrDigest = argv.last ?? ""
    }
}

let usage = """
    Usage:
      sigstore-swift-conformance verify-bundle [--staging] --bundle FILE --certificate-identity IDENTITY --certificate-oidc-issuer URL [--trusted-root FILE] FILE_OR_DIGEST
      sigstore-swift-conformance verify-bundle [--staging] --bundle FILE --key PATH_TO_KEY [--trusted-root FILE] FILE_OR_DIGEST
    """

func loadTrustedRoot(_ args: Arguments) throws -> TrustedRoot {
    if let path = args.trustedRootPath {
        return try TrustedRoot(path: path)
    }
    // sigstore-go fetches these via TUF; until SigstoreTUF exists we use
    // embedded copies.
    if args.staging {
        guard let url = Bundle.module.url(forResource: "staging_trusted_root", withExtension: "json") else {
            throw SigstoreError("embedded staging trusted root not found")
        }
        return try TrustedRoot(json: Data(contentsOf: url))
    }
    return try TrustedRoot.embeddedPublicGood()
}

func verifyBundle(_ args: Arguments) async throws {
    guard let bundlePath = args.bundlePath else { throw SigstoreError("--bundle is required") }
    let b = try SigstoreBundle.Bundle.loadJSONFromPath(bundlePath)

    let artifactPolicy: ArtifactPolicyOption
    if let colon = args.fileOrDigest.firstIndex(of: ":") {
        let alg = String(args.fileOrDigest[..<colon])
        let hexDigest = String(args.fileOrDigest[args.fileOrDigest.index(after: colon)...])
        guard let digest = Hex.decode(hexDigest) else { throw SigstoreError("invalid hex digest") }
        artifactPolicy = .withArtifactDigest(algorithm: alg, digest: Data(digest))
    } else {
        artifactPolicy = .withArtifact(try Data(contentsOf: URL(fileURLWithPath: args.fileOrDigest)))
    }

    var identityPolicies: [PolicyOption] = []
    var verifierConfig: [VerifierOption] = []
    let root = try loadTrustedRoot(args)
    var tr: any TrustedMaterial = root

    if let keyPath = args.keyPath {
        identityPolicies.append(.withKey())
        let pem = try String(contentsOfFile: keyPath, encoding: .utf8)
        let key = try Certificate.PublicKey(pemEncoded: pem)
        let verifier = try SignatureVerifier(publicKey: key)
        let keyMaterial = TrustedPublicKeyMaterial { _ in
            ExpiringKey(verifier: verifier, validityPeriodStart: nil, validityPeriodEnd: nil)
        }
        tr = TrustedMaterialCollection([keyMaterial, root])
    } else {
        verifierConfig.append(.withSignedCertificateTimestamps(threshold: 1))
        let oidc = args.certOIDC ?? ""
        let san = args.certSAN ?? ""
        if !oidc.isEmpty || !san.isEmpty {
            identityPolicies.append(
                .withCertificateIdentity(try CertificateIdentity(issuer: oidc, sanValue: san)))
        }
    }

    let bundleTimestamps = try b.timestamps()
    if !tr.timestampingAuthorities.isEmpty && !bundleTimestamps.isEmpty {
        verifierConfig.append(.withSignedTimestamps(threshold: 1))
    }
    if !tr.rekorLogs.isEmpty {
        verifierConfig.append(.withTransparencyLog(threshold: 1))
        if b.hasInclusionPromise {
            verifierConfig.append(.withIntegratedTimestamps(threshold: 1))
        }
    }

    let verifier = try Verifier(trustedMaterial: tr, options: verifierConfig)
    _ = try await verifier.verify(b, policy: PolicyBuilder(artifactPolicy, options: identityPolicies))
}

do {
    let args = try Arguments(CommandLine.arguments)
    switch args.command {
    case "verify-bundle":
        try await verifyBundle(args)
    case "sign-bundle":
        throw SigstoreError("sign-bundle is not implemented (sigstore-swift is verify-only)")
    default:
        throw SigstoreError("Unsupported command \(args.command)\n\(usage)")
    }
} catch {
    FileHandle.standardError.write(Data("\(error)\n".utf8))
    exit(1)
}
