import Crypto
import Foundation
import Sigstore
import SwiftASN1
import Testing
import X509

/// A throwaway Fulcio-like PKI (root → intermediate → leaf, P-256) with an
/// optional EKU extension on each certificate.
private struct TestFulcio {
    static let start = Date(timeIntervalSince1970: 1_600_000_000)
    static let end = Date(timeIntervalSince1970: 1_900_000_000)
    static let now = Date(timeIntervalSince1970: 1_750_000_000)

    let root: Certificate
    let intermediate: Certificate
    let leaf: Certificate

    /// `nil` omits the EKU extension.
    init(
        rootEKUs: [ExtendedKeyUsage.Usage]? = nil,
        intermediateEKUs: [ExtendedKeyUsage.Usage]? = [.codeSigning],
        leafEKUs: [ExtendedKeyUsage.Usage]? = [.codeSigning]
    ) throws {
        let rootKey = P256.Signing.PrivateKey()
        let intermediateKey = P256.Signing.PrivateKey()
        let leafKey = P256.Signing.PrivateKey()
        let rootName = try DistinguishedName { CommonName("sigstore-swift test Fulcio root") }
        let intermediateName = try DistinguishedName { CommonName("sigstore-swift test Fulcio intermediate") }

        func extensions(_ base: [Certificate.Extension], _ ekus: [ExtendedKeyUsage.Usage]?) throws -> Certificate.Extensions {
            var all = base
            if let ekus { all.append(try ExtendedKeyUsage(ekus).makeCertificateExtension()) }
            return try Certificate.Extensions(all)
        }
        func critical(_ e: some CertificateExtensionConvertible) throws -> Certificate.Extension {
            var ext = try e.makeCertificateExtension()
            ext.critical = true
            return ext
        }

        root = try Certificate(
            version: .v3, serialNumber: .init(bytes: [0x01]), publicKey: .init(rootKey.publicKey),
            notValidBefore: Self.start, notValidAfter: Self.end, issuer: rootName, subject: rootName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try extensions(
                [try critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil)),
                 try KeyUsage(keyCertSign: true).makeCertificateExtension()], rootEKUs),
            issuerPrivateKey: .init(rootKey))
        intermediate = try Certificate(
            version: .v3, serialNumber: .init(bytes: [0x02]), publicKey: .init(intermediateKey.publicKey),
            notValidBefore: Self.start, notValidAfter: Self.end, issuer: rootName, subject: intermediateName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try extensions(
                [try critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0)),
                 try KeyUsage(keyCertSign: true).makeCertificateExtension()], intermediateEKUs),
            issuerPrivateKey: .init(rootKey))
        leaf = try Certificate(
            version: .v3, serialNumber: .init(bytes: [0x03]), publicKey: .init(leafKey.publicKey),
            notValidBefore: Self.start, notValidAfter: Self.end, issuer: intermediateName,
            subject: try DistinguishedName { CommonName("sigstore-swift test signer") },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try extensions(
                [try critical(BasicConstraints.notCertificateAuthority),
                 try KeyUsage(digitalSignature: true).makeCertificateExtension()], leafEKUs),
            issuerPrivateKey: .init(intermediateKey))
    }

    func verify() async throws -> [[Certificate]] {
        try await FulcioCertificateAuthority(root: root, intermediates: [intermediate])
            .verify(leaf, observerTimestamp: Self.now)
    }
}

/// `FulcioCertificateAuthority.verify` requires the code-signing EKU like Go's
/// `x509.Certificate.Verify` with `KeyUsages: [ExtKeyUsageCodeSigning]`:
/// `checkChainForKeyUsage` checks every certificate, the root included.
@Suite("Fulcio certificate authority EKU")
struct FulcioCertificateAuthorityTests {
    private static let serverAuth = ExtendedKeyUsage.Usage.serverAuth

    @Test(arguments: [
        ("no EKUs on the CAs", nil, nil),
        ("root codeSigning", [ExtendedKeyUsage.Usage.codeSigning], [.codeSigning]),
        ("root anyExtendedKeyUsage", [.any], [.codeSigning]),
        ("root codeSigning among others", [serverAuth, .codeSigning], [.codeSigning]),
        ("intermediate anyExtendedKeyUsage", nil, [.any]),
    ] as [(String, [ExtendedKeyUsage.Usage]?, [ExtendedKeyUsage.Usage]?)])
    func chainVerifies(_ name: String, _ rootEKUs: [ExtendedKeyUsage.Usage]?, _ intermediateEKUs: [ExtendedKeyUsage.Usage]?) async throws {
        let pki = try TestFulcio(rootEKUs: rootEKUs, intermediateEKUs: intermediateEKUs)
        let chains = try await pki.verify()
        #expect(chains.first?.count == 3, "\(name)")
    }

    /// The root is checked too (it used to be skipped).
    @Test(arguments: [
        ("root serverAuth only", [serverAuth], [ExtendedKeyUsage.Usage.codeSigning], [ExtendedKeyUsage.Usage.codeSigning], 2),
        ("root timeStamping only", [.timeStamping], [.codeSigning], [.codeSigning], 2),
        ("intermediate serverAuth only", nil, [serverAuth], [.codeSigning], 1),
        ("leaf serverAuth only", nil, [.codeSigning], [serverAuth], 0),
    ] as [(String, [ExtendedKeyUsage.Usage]?, [ExtendedKeyUsage.Usage]?, [ExtendedKeyUsage.Usage]?, Int)])
    func chainWithoutCodeSigningFails(
        _ name: String, _ rootEKUs: [ExtendedKeyUsage.Usage]?, _ intermediateEKUs: [ExtendedKeyUsage.Usage]?,
        _ leafEKUs: [ExtendedKeyUsage.Usage]?, _ position: Int
    ) async throws {
        let pki = try TestFulcio(rootEKUs: rootEKUs, intermediateEKUs: intermediateEKUs, leafEKUs: leafEKUs)
        do {
            _ = try await pki.verify()
            Issue.record("\(name): expected a code-signing EKU failure")
        } catch {
            #expect("\(error)".contains("certificate at chain position \(position) does not permit code signing"),
                    "\(name): \(error)")
        }
    }
}
