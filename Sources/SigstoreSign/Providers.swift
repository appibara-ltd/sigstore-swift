// The provider interfaces of sigstore-go v1.4.1 pkg/sign/certificate.go and
// transparency.go. Their Fulcio and Rekor implementations come later.

import Foundation
import SigstoreProtobufSpecs

/// Mirrors `sign.CertificateProviderOptions`.
public struct CertificateProviderOptions: Sendable {
    /// Optional OIDC JWT to send to the certificate provider; required for
    /// Fulcio.
    public var idToken: String

    /// Creates options with an OIDC token.
    public init(idToken: String = "") {
        self.idToken = idToken
    }
}

/// Mirrors `sign.CertificateProvider`: issues a code signing certificate
/// for a keypair, typically a Fulcio instance.
public protocol CertificateProvider: Sendable {
    /// Returns the DER certificate for `keypair`.
    func certificate(keypair: any Keypair, options: CertificateProviderOptions?) async throws -> Data
}

/// Mirrors `sign.CertificateChainProvider`: issues a certificate chain,
/// for private Fulcio deployments with intermediate CAs.
public protocol CertificateChainProvider: Sendable {
    /// Returns DER certificates, leaf first, without the root.
    func certificateChain(keypair: any Keypair, options: CertificateProviderOptions?) async throws -> [Data]
}

/// Mirrors `sign.Transparency`: a transparency log that records the
/// signature and adds its entry to the bundle.
public protocol Transparency: Sendable {
    /// Uploads an entry for `bundle`'s content, signed by `keyOrCertPEM`,
    /// and appends the resulting log entry to `bundle`.
    func transparencyLogEntry(keyOrCertPEM: Data, bundle: inout Dev_Sigstore_Bundle_V1_Bundle) async throws
}
