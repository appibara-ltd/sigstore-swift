// Port of sigstore-go v1.4.1 pkg/sign/signer.go.

import Foundation
import SigstoreBundle
import SigstoreCommon
import SigstoreProtobufSpecs
import SigstoreRoot
import SigstoreVerify
import X509

/// The media type of the bundles `bundle(_:keypair:options:)` builds.
let bundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

/// Mirrors `sign.BundleOptions`.
public struct BundleOptions: Sendable {
    /// Optional certificate provider, typically Fulcio. The bundle then holds
    /// a certificate instead of a public key hint.
    public var certificateProvider: (any CertificateProvider)?
    /// Optional certificate chain provider for private Fulcio deployments
    /// with intermediate CAs. Takes precedence over `certificateProvider`
    /// and stores the full chain in the bundle.
    public var certificateChainProvider: (any CertificateChainProvider)?
    /// Optional options for the certificate provider.
    public var certificateProviderOptions: CertificateProviderOptions?
    /// Optional timestamp authorities to get signed timestamps from.
    public var timestampAuthorities: [TimestampAuthority]
    /// Optional transparency logs to get entries from.
    public var transparencyLogs: [any Transparency]
    /// Optional trusted material: when set, the new bundle is verified
    /// against it before it is returned.
    public var trustedRoot: (any TrustedMaterial)?

    /// Creates bundle options; every field is optional.
    public init(
        certificateProvider: (any CertificateProvider)? = nil,
        certificateChainProvider: (any CertificateChainProvider)? = nil,
        certificateProviderOptions: CertificateProviderOptions? = nil,
        timestampAuthorities: [TimestampAuthority] = [],
        transparencyLogs: [any Transparency] = [],
        trustedRoot: (any TrustedMaterial)? = nil
    ) {
        self.certificateProvider = certificateProvider
        self.certificateChainProvider = certificateChainProvider
        self.certificateProviderOptions = certificateProviderOptions
        self.timestampAuthorities = timestampAuthorities
        self.transparencyLogs = transparencyLogs
        self.trustedRoot = trustedRoot
    }
}

/// Mirrors `sign.Bundle`: signs `content` with `keypair` and returns a v0.3
/// bundle, with the verification material from the certificate (chain)
/// provider or the key's hint, signed timestamps over the signature from
/// the timestamp authorities, and entries from the transparency logs.
/// When `options.trustedRoot` is set, the bundle is verified before it is
/// returned.
///
/// - Throws: For ML-DSA keys (not supported in v0.3 bundles), a failing
///   provider, an empty certificate chain, a chain holding a self-signed
///   certificate, or a bundle that fails verification.
public func bundle(
    _ content: any Content, keypair: any Keypair, options: BundleOptions = BundleOptions()
) async throws -> Dev_Sigstore_Bundle_V1_Bundle {
    switch keypair.signingAlgorithm {
    case .mlDsa44, .mlDsa65, .mlDsa87:
        throw SigstoreError("ML-DSA keys are not supported for v0.3 bundles")
    default:
        break
    }

    var bundle = Dev_Sigstore_Bundle_V1_Bundle()
    bundle.mediaType = bundleV03MediaType
    var verifierOptions: [VerifierOption] = []

    // Sign content and add it to the bundle.
    let (signature, digest) = try await keypair.signData(content.preAuthEncoding)
    content.bundle(&bundle, signature: signature, digest: digest, hashAlgorithm: keypair.hashAlgorithm)

    // Add verification material.
    let verifierPEM: String
    var material = Dev_Sigstore_Bundle_V1_VerificationMaterial()
    if let chainProvider = options.certificateChainProvider {
        let chain = try await chainProvider.certificateChain(
            keypair: keypair, options: options.certificateProviderOptions)
        guard let leaf = chain.first else {
            throw SigstoreError("certificates provider returned no certificates")
        }
        var chainProto = Dev_Sigstore_Common_V1_X509CertificateChain()
        chainProto.certificates.append(x509Certificate(leaf))
        for der in chain.dropFirst() {
            let parsed = try Certificate(derEncoded: Array(der))
            if isSelfSigned(parsed) {
                throw SigstoreError("certificate chain must not contain a self-signed (root) certificate")
            }
            chainProto.certificates.append(x509Certificate(der))
        }
        material.x509CertificateChain = chainProto
        verifierPEM = pemBlock(type: "CERTIFICATE", der: Array(leaf))
    } else if let provider = options.certificateProvider {
        let der = try await provider.certificate(keypair: keypair, options: options.certificateProviderOptions)
        material.certificate = x509Certificate(der)
        verifierPEM = pemBlock(type: "CERTIFICATE", der: Array(der))
    } else {
        var identifier = Dev_Sigstore_Common_V1_PublicKeyIdentifier()
        // The hint is a proto3 string, which must be UTF-8 (Go's
        // protojson.Marshal fails on the bundle otherwise).
        guard let hint = String(bytes: keypair.hint, encoding: .utf8) else {
            throw SigstoreError("public key hint is not valid UTF-8")
        }
        identifier.hint = hint
        material.publicKey = identifier
        verifierPEM = try keypair.publicKeyPem()
    }

    if !options.timestampAuthorities.isEmpty {
        for authority in options.timestampAuthorities {
            var signedTimestamp = Dev_Sigstore_Common_V1_RFC3161SignedTimestamp()
            signedTimestamp.signedTimestamp = try await authority.timestamp(signature: signature)
            material.timestampVerificationData.rfc3161Timestamps.append(signedTimestamp)
        }
        verifierOptions.append(.withSignedTimestamps(threshold: options.timestampAuthorities.count))
    }
    bundle.verificationMaterial = material

    let hasCertificate = options.certificateProvider != nil || options.certificateChainProvider != nil
    if !options.transparencyLogs.isEmpty {
        for log in options.transparencyLogs {
            try await log.transparencyLogEntry(keyOrCertPEM: Data(verifierPEM.utf8), bundle: &bundle)
        }
        verifierOptions.append(.withTransparencyLog(threshold: options.transparencyLogs.count))
        // Rekor v2 gives no integrated timestamps: verification then needs
        // a timestamp authority.
        if options.timestampAuthorities.isEmpty {
            // Use Rekor's integrated time only with a certificate; a bare
            // key needs no time.
            verifierOptions.append(
                hasCertificate
                    ? .withIntegratedTimestamps(threshold: options.transparencyLogs.count)
                    : .withNoObserverTimestamps())
        }
    }

    // Without any timestamp, verify a certificate at the current time, and
    // a bare key without time.
    if options.timestampAuthorities.isEmpty && options.transparencyLogs.isEmpty {
        verifierOptions.append(hasCertificate ? .withCurrentTime() : .withNoObserverTimestamps())
    }

    if let trustedRoot = options.trustedRoot {
        let verifier = try Verifier(trustedMaterial: trustedRoot, options: verifierOptions)
        let bundleOptions: [BundleOption] =
            options.certificateChainProvider != nil ? [.withAllowCertificateChain()] : []
        let entity = try SigstoreBundle.Bundle(bundle, options: bundleOptions)
        // We just signed the content, so a DSSE envelope is trusted to
        // reference the intended artifacts (as in sigstore-go).
        var artifactPolicy = ArtifactPolicyOption.withoutArtifactUnsafe()
        if case .messageSignature = bundle.content {
            artifactPolicy = .withArtifact(content.preAuthEncoding)
        }
        _ = try await verifier.verify(entity, policy: PolicyBuilder(artifactPolicy, .withoutIdentitiesUnsafe()))
    }

    return bundle
}

private func x509Certificate(_ der: Data) -> Dev_Sigstore_Common_V1_X509Certificate {
    var cert = Dev_Sigstore_Common_V1_X509Certificate()
    cert.rawBytes = der
    return cert
}

/// Mirrors sigstore-go internal/certificate `IsSelfSigned`: the subject
/// equals the issuer and the certificate's key verifies its own signature.
func isSelfSigned(_ certificate: Certificate) -> Bool {
    guard certificate.subject == certificate.issuer else { return false }
    return certificate.publicKey.isValidSignature(certificate.signature, for: certificate)
}
