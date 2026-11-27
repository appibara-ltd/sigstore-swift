import Crypto
import Foundation
import Sigstore
import SwiftASN1
import Testing
import X509

// MARK: - Conformance fixture (real TSA token)

/// sigstore-conformance `intoto-with-custom-trust-root` (Apache-2.0): a DSSE
/// bundle with one RFC 3161 timestamp from the conformance mock TSA.
private enum TSAFixture {
    static let directory = "conformance/intoto-with-custom-trust-root"
    static let san =
        "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
    static let issuer = "https://token.actions.githubusercontent.com"
    /// `openssl ts -reply -text`: "Time stamp: Feb  1 00:00:00 2023 GMT".
    static let time = Date(timeIntervalSince1970: 1_675_209_600)

    static func data(_ name: String) throws -> Data {
        try Fixtures.file("\(directory)/\(name)")
    }

    static func json() throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: data("bundle.sigstore.json")) as! [String: Any]
    }

    static func bundle() throws -> SigstoreBundle.Bundle { try SigstoreBundle.Bundle(json: data("bundle.sigstore.json")) }
    static func trustedRoot() throws -> TrustedRoot { try TrustedRoot(json: data("trusted_root.json")) }

    /// The bundle with its timestamp list replaced by `count` copies of the first.
    static func bundle(repeatingTimestamp count: Int) throws -> SigstoreBundle.Bundle {
        var json = try json()
        var vm = json["verificationMaterial"] as! [String: Any]
        var tvd = vm["timestampVerificationData"] as! [String: Any]
        let first = (tvd["rfc3161Timestamps"] as! [Any])[0]
        tvd["rfc3161Timestamps"] = Array(repeating: first, count: count)
        vm["timestampVerificationData"] = tvd
        json["verificationMaterial"] = vm
        return try SigstoreBundle.Bundle(json: JSONSerialization.data(withJSONObject: json))
    }
}

@Suite("RFC 3161 signed timestamps")
struct TimestampAuthorityTests {
    @Test func conformanceTimestampVerifies() async throws {
        let verified = try await verifySignedTimestampWithThreshold(
            TSAFixture.bundle(), trustedMaterial: TSAFixture.trustedRoot(), threshold: 1)
        #expect(verified.count == 1)
        #expect(verified.first?.time == TSAFixture.time)
    }

    @Test func conformanceBundleVerifiesWithSignedTimestamps() async throws {
        let verifier = try Verifier(
            trustedMaterial: TSAFixture.trustedRoot(),
            options: [.withSignedCertificateTimestamps(threshold: 1), .withTransparencyLog(threshold: 1),
                .withSignedTimestamps(threshold: 1)])
        let policy = PolicyBuilder(
            .withArtifact(try TSAFixture.data("artifact")),
            .withCertificateIdentity(try CertificateIdentity(issuer: TSAFixture.issuer, sanValue: TSAFixture.san)))
        let result = try await verifier.verify(TSAFixture.bundle(), policy: policy)
        #expect(result.verifiedTimestamps.contains { $0.type == "TimestampAuthority" && $0.timestamp == TSAFixture.time })
    }

    @Test func timestampOverOtherSignatureFails() async throws {
        let tsa = try #require(TSAFixture.trustedRoot().timestampingAuthorities.first)
        let signed = try #require(TSAFixture.bundle().timestamps().first)
        await expectError("hashed messages don't match") {
            _ = try await tsa.verify(signedTimestamp: signed, signature: Data("not the signature".utf8))
        }
    }

    @Test func duplicateTimestampsFromOneAuthorityCountOnce() async throws {
        let bundle = try TSAFixture.bundle(repeatingTimestamp: 2)
        let root = try TSAFixture.trustedRoot()
        let (verified, errors) = try await verifySignedTimestamp(bundle, trustedMaterial: root)
        #expect(verified.count == 1)
        #expect(errors.contains { "\($0)".contains("duplicate timestamps from the same authority") })
        await expectError("threshold not met for verified signed timestamps: 1 < 2") {
            _ = try await verifySignedTimestampWithThreshold(bundle, trustedMaterial: root, threshold: 2)
        }
    }

    @Test func tooManyTimestampsFail() async throws {
        let bundle = try TSAFixture.bundle(repeatingTimestamp: maxAllowedTimestamps + 1)
        await expectError("too many signed timestamps") {
            _ = try await verifySignedTimestamp(bundle, trustedMaterial: TSAFixture.trustedRoot())
        }
    }

    @Test func untrustedAuthorityFails() async throws {
        let other = try TestTSA()
        await expectError("threshold not met for verified signed timestamps: 0 < 1") {
            _ = try await verifySignedTimestampWithThreshold(
                TSAFixture.bundle(), trustedMaterial: other.trustedMaterial(), threshold: 1)
        }
    }

    // MARK: Synthetic tokens

    private let artifact = Array("signature bytes".utf8)

    @Test func syntheticTimestampVerifies() async throws {
        let tsa = try TestTSA()
        let ts = try await tsa.authority().verify(
            signedTimestamp: tsa.response(for: artifact), signature: Data(artifact))
        #expect(ts.time == TestTSA.defaultTime)
        #expect(ts.uri == TestTSA.uri)
    }

    @Test func timestampWithoutEmbeddedCertsUsesTrustedLeaf() async throws {
        let tsa = try TestTSA()
        var o = TestTSA.TokenOptions()
        o.embedCertificates = false
        let ts = try await tsa.authority().verify(
            signedTimestamp: tsa.response(for: artifact, o), signature: Data(artifact))
        #expect(ts.time == TestTSA.defaultTime)
    }

    @Test func timestampWithoutAnyLeafFails() async throws {
        let tsa = try TestTSA()
        var o = TestTSA.TokenOptions()
        o.embedCertificates = false
        await expectError("leaf certificate must be present in the TSR or as a verify option") {
            _ = try await tsa.authority(includeLeaf: false).verify(
                signedTimestamp: tsa.response(for: self.artifact, o), signature: Data(self.artifact))
        }
    }

    @Test func untrustedRootFails() async throws {
        let tsa = try TestTSA()
        let other = try TestTSA()
        await expectError("error while verifying signer certificate chain") {
            _ = try await other.authority(includeLeaf: false).verify(
                signedTimestamp: tsa.response(for: self.artifact), signature: Data(self.artifact))
        }
    }

    @Test func embeddedCertMustMatchTrustedLeaf() async throws {
        let tsa = try TestTSA()
        let other = try TestTSA()
        var authority = tsa.authority()
        authority.leaf = other.leaf
        await expectError("certificate embedded in the TSR does not match the provided TSA certificate") {
            _ = try await authority.verify(
                signedTimestamp: tsa.response(for: self.artifact), signature: Data(self.artifact))
        }
        // Same issuer, different leaf.
        let sibling = try tsa.issueLeaf(TestTSA.LeafOptions(serial: [0x0C, 0x01]))
        authority.leaf = sibling
        await expectError("certificate embedded in the TSR does not match the provided TSA certificate") {
            _ = try await authority.verify(
                signedTimestamp: tsa.response(for: self.artifact), signature: Data(self.artifact))
        }
    }

    @Test func tamperedSignatureFails() async throws {
        let tsa = try TestTSA()
        var o = TestTSA.TokenOptions()
        o.tamperSignature = true
        await expectError("signature verification failed") {
            _ = try await tsa.authority().verify(
                signedTimestamp: tsa.response(for: self.artifact, o), signature: Data(self.artifact))
        }
    }

    @Test func messageDigestAttributeMismatchFails() async throws {
        let tsa = try TestTSA()
        var o = TestTSA.TokenOptions()
        o.wrongMessageDigest = true
        await expectError("Message digest mismatch") {
            _ = try await tsa.authority().verify(
                signedTimestamp: tsa.response(for: self.artifact, o), signature: Data(self.artifact))
        }
    }

    @Test func nonCriticalEKUFails() async throws {
        let tsa = try TestTSA(leaf: .init(ekuCritical: false))
        await expectError("certificate must set EKU to critical") {
            _ = try await tsa.authority().verify(
                signedTimestamp: tsa.response(for: self.artifact), signature: Data(self.artifact))
        }
    }

    @Test func multipleLeafEKUsFail() async throws {
        let tsa = try TestTSA(leaf: .init(ekus: [.timeStamping, .codeSigning]))
        await expectError("certificate has 2 extended key usages, expected only one") {
            _ = try await tsa.authority().verify(
                signedTimestamp: tsa.response(for: self.artifact), signature: Data(self.artifact))
        }
    }

    @Test func leafWithoutTimestampingEKUFails() async throws {
        let tsa = try TestTSA(leaf: .init(ekus: [.codeSigning]))
        await expectError("does not permit time stamping") {
            _ = try await tsa.authority().verify(
                signedTimestamp: tsa.response(for: self.artifact), signature: Data(self.artifact))
        }
    }

    @Test func caLeafFails() async throws {
        let tsa = try TestTSA(leaf: .init(isCA: true))
        await expectError("TSA certificate must be an end-entity certificate, not a CA") {
            _ = try await tsa.authority(includeLeaf: false).verify(
                signedTimestamp: tsa.response(for: self.artifact), signature: Data(self.artifact))
        }
    }

    @Test func intermediateWithoutTimestampingEKUFails() async throws {
        let tsa = try TestTSA(intermediateEKUs: [.codeSigning])
        await expectError("does not permit time stamping") {
            _ = try await tsa.authority().verify(
                signedTimestamp: tsa.response(for: self.artifact), signature: Data(self.artifact))
        }
        // anyExtendedKeyUsage on the intermediate is accepted.
        let any = try TestTSA(intermediateEKUs: [.any])
        _ = try await any.authority().verify(signedTimestamp: any.response(for: artifact), signature: Data(artifact))
    }

    @Test func timestampOutsideLeafValidityFails() async throws {
        let tsa = try TestTSA()
        var o = TestTSA.TokenOptions()
        o.time = tsa.leaf.notValidAfter.addingTimeInterval(1)
        await expectError("error while verifying signer certificate chain") {
            _ = try await tsa.authority().verify(
                signedTimestamp: tsa.response(for: self.artifact, o), signature: Data(self.artifact))
        }
    }

    @Test func trustRootValidityPeriodIsEnforcedAndInclusive() async throws {
        let tsa = try TestTSA()
        let response = try tsa.response(for: artifact)
        var authority = tsa.authority()

        authority.validityPeriodStart = TestTSA.defaultTime.addingTimeInterval(1)
        await expectError("timestamp is before the validity period start") {
            _ = try await authority.verify(signedTimestamp: response, signature: Data(self.artifact))
        }
        authority.validityPeriodStart = nil
        authority.validityPeriodEnd = TestTSA.defaultTime.addingTimeInterval(-1)
        await expectError("timestamp is after the validity period end") {
            _ = try await authority.verify(signedTimestamp: response, signature: Data(self.artifact))
        }
        // TimeRange is a closed interval.
        authority.validityPeriodStart = TestTSA.defaultTime
        authority.validityPeriodEnd = TestTSA.defaultTime
        _ = try await authority.verify(signedTimestamp: response, signature: Data(artifact))
    }

    @Test func rejectedStatusFails() async throws {
        let tsa = try TestTSA()
        var o = TestTSA.TokenOptions()
        o.status = 2
        await expectError("timestamp response status 2") {
            _ = try await tsa.authority().verify(
                signedTimestamp: tsa.response(for: self.artifact, o), signature: Data(self.artifact))
        }
    }

    @Test func sha1ImprintFails() async throws {
        let tsa = try TestTSA()
        var o = TestTSA.TokenOptions()
        o.hashOID = TestTSA.sha1
        await expectError("weak hash algorithm") {
            _ = try await tsa.authority().verify(
                signedTimestamp: tsa.response(for: self.artifact, o), signature: Data(self.artifact))
        }
    }

    @Test func sha384ImprintVerifies() async throws {
        let tsa = try TestTSA()
        var o = TestTSA.TokenOptions()
        o.hashOID = TestTSA.sha384
        _ = try await tsa.authority().verify(
            signedTimestamp: tsa.response(for: artifact, o), signature: Data(artifact))
    }

    @Test func pqcPolicyWithClassicalKeyFails() async throws {
        let tsa = try TestTSA()
        var o = TestTSA.TokenOptions()
        o.policy = [1, 3, 6, 1, 4, 1, 57264, 2, 1]
        await expectError("requires an ML-DSA certificate chain") {
            _ = try await tsa.authority().verify(
                signedTimestamp: tsa.response(for: self.artifact, o), signature: Data(self.artifact))
        }
    }

    @Test func trailingDataFails() async throws {
        let tsa = try TestTSA()
        let response = try tsa.response(for: artifact) + [0x00]
        await expectError("error parsing response into Timestamp") {
            _ = try await tsa.authority().verify(signedTimestamp: response, signature: Data(self.artifact))
        }
    }

    @Test func missingRootFails() async throws {
        let tsa = try TestTSA()
        var authority = tsa.authority()
        authority.root = nil
        await expectError("timestamping authority \(TestTSA.uri) root certificate is nil") {
            _ = try await authority.verify(
                signedTimestamp: tsa.response(for: self.artifact), signature: Data(self.artifact))
        }
    }
}

private func expectError(
    _ fragment: String, sourceLocation: SourceLocation = #_sourceLocation, _ body: () async throws -> Void
) async {
    do {
        try await body()
        Issue.record("expected an error containing \"\(fragment)\"", sourceLocation: sourceLocation)
    } catch {
        #expect("\(error)".contains(fragment), "unexpected error: \(error)", sourceLocation: sourceLocation)
    }
}

// MARK: - Test TSA

/// A throwaway TSA PKI (root → intermediate → leaf, P-256) that issues
/// RFC 3161 TimeStampResp messages, with knobs for negative tests.
struct TestTSA {
    static let uri = "https://tsa.test/api/v1/timestamp"
    static let defaultTime = Date(timeIntervalSince1970: 1_750_000_000)
    static let sha1: ASN1ObjectIdentifier = [1, 3, 14, 3, 2, 26]
    static let sha256: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    static let sha384: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 2]

    struct LeafOptions {
        var ekuCritical = true
        var ekus: [ExtendedKeyUsage.Usage] = [.timeStamping]
        var isCA = false
        var serial: [UInt8] = [0x0B, 0x01]
        var notValidBefore = Date(timeIntervalSince1970: 1_700_000_000)
        var notValidAfter = Date(timeIntervalSince1970: 1_800_000_000)
    }

    struct TokenOptions {
        var time = TestTSA.defaultTime
        var hashOID = TestTSA.sha256
        var policy: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 2]
        var embedCertificates = true
        var status = 0
        var tamperSignature = false
        var wrongMessageDigest = false
    }

    let rootKey = P256.Signing.PrivateKey()
    let intermediateKey = P256.Signing.PrivateKey()
    let leafKey = P256.Signing.PrivateKey()
    let root: Certificate
    let intermediate: Certificate
    let leaf: Certificate

    init(leaf leafOptions: LeafOptions = .init(), intermediateEKUs: [ExtendedKeyUsage.Usage]? = nil) throws {
        let start = Date(timeIntervalSince1970: 1_600_000_000)
        let end = Date(timeIntervalSince1970: 1_900_000_000)
        let rootName = try DistinguishedName { CommonName("sigstore-swift test TSA root") }
        root = try Certificate(
            version: .v3, serialNumber: .init(bytes: [0x01]), publicKey: .init(rootKey.publicKey),
            notValidBefore: start, notValidAfter: end, issuer: rootName, subject: rootName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                KeyUsage(keyCertSign: true)
            },
            issuerPrivateKey: .init(rootKey))

        var intermediateExtensions: [Certificate.Extension] = [
            try Self.critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0)),
            try KeyUsage(keyCertSign: true).makeCertificateExtension(),
        ]
        if let intermediateEKUs {
            intermediateExtensions.append(try ExtendedKeyUsage(intermediateEKUs).makeCertificateExtension())
        }
        intermediate = try Certificate(
            version: .v3, serialNumber: .init(bytes: [0x02]), publicKey: .init(intermediateKey.publicKey),
            notValidBefore: start, notValidAfter: end, issuer: rootName,
            subject: try DistinguishedName { CommonName("sigstore-swift test TSA intermediate") },
            signatureAlgorithm: .ecdsaWithSHA256, extensions: Certificate.Extensions(intermediateExtensions),
            issuerPrivateKey: .init(rootKey))

        leaf = try Self.issueLeaf(
            leafOptions, key: leafKey, issuer: intermediate, issuerKey: intermediateKey)
    }

    /// Issues another leaf under the same intermediate.
    func issueLeaf(_ o: LeafOptions) throws -> Certificate {
        try Self.issueLeaf(o, key: P256.Signing.PrivateKey(), issuer: intermediate, issuerKey: intermediateKey)
    }

    private static func issueLeaf(
        _ o: LeafOptions, key: P256.Signing.PrivateKey, issuer: Certificate, issuerKey: P256.Signing.PrivateKey
    ) throws -> Certificate {
        var eku = try ExtendedKeyUsage(o.ekus).makeCertificateExtension()
        eku.critical = o.ekuCritical
        let basicConstraints: BasicConstraints =
            o.isCA ? .isCertificateAuthority(maxPathLength: nil) : .notCertificateAuthority
        return try Certificate(
            version: .v3, serialNumber: .init(bytes: ArraySlice(o.serial)), publicKey: .init(key.publicKey),
            notValidBefore: o.notValidBefore, notValidAfter: o.notValidAfter, issuer: issuer.subject,
            subject: try DistinguishedName { CommonName("sigstore-swift test TSA") },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions([
                try Self.critical(basicConstraints),
                try KeyUsage(digitalSignature: true).makeCertificateExtension(),
                eku,
            ]),
            issuerPrivateKey: .init(issuerKey))
    }

    func authority(includeLeaf: Bool = true) -> SigstoreTimestampingAuthority {
        SigstoreTimestampingAuthority(
            root: root, intermediates: [intermediate], leaf: includeLeaf ? leaf : nil, uri: Self.uri)
    }

    func trustedMaterial() throws -> TrustedRoot {
        try TrustedRoot(
            mediaType: trustedRootMediaType01, certificateAuthorities: [],
            certificateTransparencyLogs: [:], timestampAuthorities: [authority()], transparencyLogs: [:])
    }

    /// A DER TimeStampResp over `artifact`.
    func response(for artifact: [UInt8], _ o: TokenOptions = .init()) throws -> Data {
        let imprint: [UInt8]
        switch o.hashOID {
        case Self.sha1: imprint = Array(Insecure.SHA1.hash(data: artifact))
        case Self.sha384: imprint = Array(SHA384.hash(data: artifact))
        default: imprint = Array(SHA256.hash(data: artifact))
        }

        // TSTInfo
        var t = DER.Serializer()
        try t.appendConstructedNode(identifier: .sequence) { s in
            try s.serialize(1)
            try s.serialize(o.policy)
            try s.appendConstructedNode(identifier: .sequence) { s in
                try s.appendConstructedNode(identifier: .sequence) { s in
                    try s.serialize(o.hashOID)
                    try s.serialize(ASN1Null())
                }
                try s.serialize(ASN1OctetString(contentBytes: imprint[...]))
            }
            try s.serialize(ArraySlice<UInt8>([0x2A]))  // serialNumber
            try s.serialize(Self.generalizedTime(o.time))
        }
        let tstInfo = t.serializedBytes

        // Signed attributes: contentType, messageDigest.
        var digest = Array(SHA256.hash(data: tstInfo))
        if o.wrongMessageDigest { digest[0] ^= 0xFF }
        var a = DER.Serializer()
        try a.appendConstructedNode(identifier: .set) { s in
            try s.appendConstructedNode(identifier: .sequence) { s in
                try s.serialize(([1, 2, 840, 113549, 1, 9, 3] as ASN1ObjectIdentifier))
                try s.appendConstructedNode(identifier: .set) { s in
                    try s.serialize(([1, 2, 840, 113549, 1, 9, 16, 1, 4] as ASN1ObjectIdentifier))
                }
            }
            try s.appendConstructedNode(identifier: .sequence) { s in
                try s.serialize(([1, 2, 840, 113549, 1, 9, 4] as ASN1ObjectIdentifier))
                try s.appendConstructedNode(identifier: .set) { s in
                    try s.serialize(ASN1OctetString(contentBytes: digest[...]))
                }
            }
        }
        let signedAttributes = a.serializedBytes
        var implicitAttributes = signedAttributes
        implicitAttributes[0] = 0xA0
        let signature = try leafKey.signature(
            for: o.tamperSignature ? signedAttributes + [0x00] : signedAttributes
        ).derRepresentation

        let context0 = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
        var r = DER.Serializer()
        try r.appendConstructedNode(identifier: .sequence) { s in
            try s.appendConstructedNode(identifier: .sequence) { s in try s.serialize(o.status) }
            // ContentInfo
            try s.appendConstructedNode(identifier: .sequence) { s in
                try s.serialize(([1, 2, 840, 113549, 1, 7, 2] as ASN1ObjectIdentifier))
                try s.appendConstructedNode(identifier: context0) { s in
                    // SignedData
                    try s.appendConstructedNode(identifier: .sequence) { s in
                        try s.serialize(3)
                        try s.appendConstructedNode(identifier: .set) { s in
                            try Self.algorithm(Self.sha256, &s)
                        }
                        try s.appendConstructedNode(identifier: .sequence) { s in
                            try s.serialize(([1, 2, 840, 113549, 1, 9, 16, 1, 4] as ASN1ObjectIdentifier))
                            try s.appendConstructedNode(identifier: context0) { s in
                                try s.serialize(ASN1OctetString(contentBytes: tstInfo[...]))
                            }
                        }
                        if o.embedCertificates {
                            try s.appendConstructedNode(identifier: context0) { s in
                                try s.serialize(leaf)
                                try s.serialize(intermediate)
                            }
                        }
                        try s.appendConstructedNode(identifier: .set) { s in
                            // SignerInfo
                            try s.appendConstructedNode(identifier: .sequence) { s in
                                try s.serialize(1)
                                try s.appendConstructedNode(identifier: .sequence) { s in
                                    try s.serialize(leaf.issuer)
                                    try s.serialize(leaf.serialNumber.bytes)
                                }
                                try Self.algorithm(Self.sha256, &s)
                                s.serializeRawBytes(implicitAttributes)
                                try s.appendConstructedNode(identifier: .sequence) { s in
                                    try s.serialize(([1, 2, 840, 10045, 4, 3, 2] as ASN1ObjectIdentifier))
                                }
                                try s.serialize(ASN1OctetString(contentBytes: ArraySlice(signature)))
                            }
                        }
                    }
                }
            }
        }
        return Data(r.serializedBytes)
    }

    private static func critical(_ e: some CertificateExtensionConvertible) throws -> Certificate.Extension {
        var ext = try e.makeCertificateExtension()
        ext.critical = true
        return ext
    }

    private static func algorithm(_ oid: ASN1ObjectIdentifier, _ s: inout DER.Serializer) throws {
        try s.appendConstructedNode(identifier: .sequence) { s in
            try s.serialize(oid)
            try s.serialize(ASN1Null())
        }
    }

    private static func generalizedTime(_ date: Date) throws -> GeneralizedTime {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let c = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        return try GeneralizedTime(
            year: c.year!, month: c.month!, day: c.day!, hours: c.hour!, minutes: c.minute!, seconds: c.second!,
            fractionalSeconds: 0)
    }
}
