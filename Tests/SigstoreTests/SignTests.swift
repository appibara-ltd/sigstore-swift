import Crypto
import Foundation
import Sigstore
import SwiftASN1
import Testing
import X509

/// sigstore-go pkg/sign keys_test.go, content_test.go and signer_test.go,
/// plus round trips through the verifier and negative cases.
@Suite("Signing")
struct SignTests {
    // MARK: Helpers

    /// Trusted material holding `keypair`'s public key (signer_test.go
    /// `trustedPublicKeyMaterial`), never expiring.
    private func trustedMaterial(_ keypair: any Keypair) -> TrustedPublicKeyMaterial {
        let hash: HashFunc? =
            switch keypair.hashAlgorithm {
            case .sha2256: .sha256
            case .sha2384: .sha384
            case .sha2512: .sha512
            default: nil
            }
        let publicKey = keypair.publicKey
        return TrustedPublicKeyMaterial(publicKeyVerifier: { _ in
            ExpiringKey(
                verifier: try SignatureVerifier(publicKey: publicKey, hashFunction: hash),
                validityPeriodStart: nil, validityPeriodEnd: nil)
        })
    }

    private static let statement: Data = {
        let digest = String(repeating: "ab", count: 32)
        let json = """
            {"_type":"https://in-toto.io/Statement/v1",\
            "subject":[{"name":"a","digest":{"sha256":"\(digest)"}}],\
            "predicateType":"https://example.com/p","predicate":{}}
            """
        return Data(json.utf8)
    }()

    /// A keypair whose signatures are corrupted.
    private struct CorruptingKeypair: Keypair {
        let base: EphemeralKeypair
        var hashAlgorithm: Dev_Sigstore_Common_V1_HashAlgorithm { base.hashAlgorithm }
        var signingAlgorithm: Dev_Sigstore_Common_V1_PublicKeyDetails { base.signingAlgorithm }
        var hint: Data { base.hint }
        var keyAlgorithm: String { base.keyAlgorithm }
        var publicKey: SigstorePublicKey { base.publicKey }
        func publicKeyPem() throws -> String { try base.publicKeyPem() }
        func signData(_ data: Data) async throws -> (signature: Data, digest: Data) {
            var (signature, digest) = try await base.signData(data)
            signature[signature.count - 1] ^= 1
            return (signature, digest)
        }
    }

    /// A keypair claiming an ML-DSA algorithm.
    private struct MLDSAClaimingKeypair: Keypair {
        let base: EphemeralKeypair
        var hashAlgorithm: Dev_Sigstore_Common_V1_HashAlgorithm { .unspecified }
        var signingAlgorithm: Dev_Sigstore_Common_V1_PublicKeyDetails { .mlDsa44 }
        var hint: Data { base.hint }
        var keyAlgorithm: String { "ML-DSA-44" }
        var publicKey: SigstorePublicKey { base.publicKey }
        func publicKeyPem() throws -> String { try base.publicKeyPem() }
        func signData(_ data: Data) async throws -> (signature: Data, digest: Data) {
            try await base.signData(data)
        }
    }

    private struct StaticChainProvider: CertificateChainProvider {
        let chain: [Data]
        func certificateChain(keypair _: any Keypair, options _: CertificateProviderOptions?) async throws -> [Data] {
            chain
        }
    }

    private struct StaticCertificateProvider: CertificateProvider {
        let der: Data
        func certificate(keypair _: any Keypair, options _: CertificateProviderOptions?) async throws -> Data { der }
    }

    private actor Calls {
        var pems: [Data] = []
        func record(_ pem: Data) { pems.append(pem) }
    }

    private struct RecordingLog: Transparency {
        let calls: Calls
        func transparencyLogEntry(keyOrCertPEM: Data, bundle _: inout Dev_Sigstore_Bundle_V1_Bundle) async throws {
            await calls.record(keyOrCertPEM)
        }
    }

    private struct FailingLog: Transparency {
        func transparencyLogEntry(keyOrCertPEM _: Data, bundle _: inout Dev_Sigstore_Bundle_V1_Bundle) async throws {
            throw SigstoreError("log unavailable")
        }
    }

    /// A certificate for a fresh P-256 key, issued by `issuerKey` under
    /// `issuerName` (self-signed when they are the subject's own).
    private func certificate(
        subject: String, issuer: String, issuerKey: P256.Signing.PrivateKey? = nil
    ) throws -> Data {
        let key = P256.Signing.PrivateKey()
        let subjectName = try DistinguishedName { CommonName(subject) }
        let issuerName = try DistinguishedName { CommonName(issuer) }
        let now = Date()
        let cert = try Certificate(
            version: .v3, serialNumber: Certificate.SerialNumber(),
            publicKey: Certificate.PublicKey(key.publicKey),
            notValidBefore: now - 60, notValidAfter: now + 3600,
            issuer: issuerName, subject: subjectName,
            signatureAlgorithm: .ecdsaWithSHA256, extensions: Certificate.Extensions(),
            issuerPrivateKey: Certificate.PrivateKey(issuerKey ?? key))
        var serializer = DER.Serializer()
        try serializer.serialize(cert)
        return Data(serializer.serializedBytes)
    }

    // MARK: Keys

    @Test func hintDefaultsToKeyFingerprint() throws {
        let custom = try EphemeralKeypair(options: EphemeralKeypairOptions(hint: Data("asdf".utf8)))
        #expect(custom.hint == Data("asdf".utf8))

        let keypair = try EphemeralKeypair()
        let expected = Base64.encode(Array(SHA256.hash(data: keypair.publicKey.pkixBytes)))
        #expect(keypair.hint == Data(expected.utf8))
        #expect(keypair.signingAlgorithm == .pkixEcdsaP256Sha256)
    }

    static let algorithms: [(Dev_Sigstore_Common_V1_PublicKeyDetails, String, Dev_Sigstore_Common_V1_HashAlgorithm)] = [
        (.unspecified, "ECDSA", .sha2256),
        (.pkixEcdsaP384Sha384, "ECDSA", .sha2384),
        (.pkixEcdsaP384Sha256, "ECDSA", .sha2256),
        (.pkixEcdsaP521Sha512, "ECDSA", .sha2512),
        (.pkixRsaPkcs1V152048Sha256, "RSA", .sha2256),
        (.pkixRsaPss3072Sha256, "RSA", .sha2256),
        (.pkixEd25519, "ED25519", .unspecified),
    ]

    @Test(arguments: algorithms)
    func ephemeralKeypairSignsAndVerifies(
        algorithm: Dev_Sigstore_Common_V1_PublicKeyDetails, keyAlgorithm: String,
        hash: Dev_Sigstore_Common_V1_HashAlgorithm
    ) async throws {
        let keypair = try EphemeralKeypair(options: EphemeralKeypairOptions(algorithm: algorithm))
        #expect(keypair.signingAlgorithm == (algorithm == .unspecified ? .pkixEcdsaP256Sha256 : algorithm))
        #expect(keypair.keyAlgorithm == keyAlgorithm)
        #expect(keypair.hashAlgorithm == hash)
        let pem = try keypair.publicKeyPem()
        #expect(pem.hasPrefix("-----BEGIN PUBLIC KEY-----\n") && pem.hasSuffix("-----END PUBLIC KEY-----\n"))

        let data = Data("hello world".utf8)
        let (signature, digest) = try await keypair.signData(data)
        let verifier = try trustedMaterial(keypair).publicKeyVerifier("").verifier
        #expect(verifier.verify(signature: signature, message: data))
        #expect(!verifier.verify(signature: signature, message: Data("hello worle".utf8)))
        if hash == .unspecified {
            #expect(digest == data)
        } else {
            #expect(digest.count == verifier.hashFunction.size)
            #expect(Array(digest) == verifier.hashFunction.digest(data))
        }
    }

    @Test(arguments: [
        Dev_Sigstore_Common_V1_PublicKeyDetails.UNRECOGNIZED(999),
        .pkixEd25519Ph,  // not implemented in this port
        .mlDsa44, .mlDsa65, .mlDsa87,
        .pkixRsaPkcs1V5, .pkixEcdsaP256HmacSha256, .lmsSha256,
    ])
    func unsupportedAlgorithmsThrow(algorithm: Dev_Sigstore_Common_V1_PublicKeyDetails) {
        #expect(throws: (any Error).self) {
            try EphemeralKeypair(options: EphemeralKeypairOptions(algorithm: algorithm))
        }
    }

    // MARK: Content

    @Test func plainDataBundlesAMessageSignature() {
        let content = PlainData(data: Data("qwerty".utf8))
        #expect(content.preAuthEncoding == Data("qwerty".utf8))
        var b = Dev_Sigstore_Bundle_V1_Bundle()
        content.bundle(&b, signature: Data([1]), digest: Data([2]), hashAlgorithm: .sha2256)
        #expect(b.messageSignature.signature == Data([1]))
        #expect(b.messageSignature.messageDigest.digest == Data([2]))
        #expect(b.messageSignature.messageDigest.algorithm == .sha2256)
        if case .dsseEnvelope = b.content { Issue.record("unexpected DSSE envelope") }
    }

    @Test func dsseDataPreAuthEncodingCountsBytes() {
        // DSSE protocol.md: PAE("http://example.com/HelloWorld", "hello world").
        let hello = DSSEData(data: Data("hello world".utf8), payloadType: "http://example.com/HelloWorld")
        #expect(hello.preAuthEncoding == Data("DSSEv1 29 http://example.com/HelloWorld 11 hello world".utf8))
        // Lengths are in bytes, not characters.
        let utf8 = DSSEData(data: Data("é".utf8), payloadType: "ü")
        #expect(utf8.preAuthEncoding == Data("DSSEv1 2 ü 2 é".utf8))

        var b = Dev_Sigstore_Bundle_V1_Bundle()
        hello.bundle(&b, signature: Data([1]), digest: Data([2]), hashAlgorithm: .sha2256)
        #expect(b.dsseEnvelope.payload == Data("hello world".utf8))
        #expect(b.dsseEnvelope.payloadType == "http://example.com/HelloWorld")
        #expect(b.dsseEnvelope.signatures.map(\.sig) == [Data([1])])
        if case .messageSignature = b.content { Issue.record("unexpected message signature") }
    }

    // MARK: Bundle

    @Test func ed25519MessageSignatureDoesNotVerify() async throws {
        // As in sigstore-go: pure Ed25519 signs the message itself, so the
        // bundle's message digest has algorithm UNSPECIFIED, which
        // verifyMessageSignatureContent (algStringToHashFunc) rejects.
        let keypair = try EphemeralKeypair(options: EphemeralKeypairOptions(algorithm: .pkixEd25519))
        await #expect(throws: (any Error).self) {
            try await bundle(
                PlainData(data: Data("qwerty".utf8)), keypair: keypair,
                options: BundleOptions(trustedRoot: self.trustedMaterial(keypair)))
        }
        // DSSE has no message digest, so Ed25519 works there.
        _ = try await bundle(
            DSSEData(data: Self.statement, payloadType: "application/vnd.in-toto+json"), keypair: keypair,
            options: BundleOptions(trustedRoot: trustedMaterial(keypair)))
    }

    @Test(arguments: algorithms.map(\.0).filter { $0 != .pkixEd25519 })
    func bundleRoundTripsThroughVerifier(algorithm: Dev_Sigstore_Common_V1_PublicKeyDetails) async throws {
        let keypair = try EphemeralKeypair(options: EphemeralKeypairOptions(algorithm: algorithm))
        let options = BundleOptions(trustedRoot: trustedMaterial(keypair))
        let content = PlainData(data: Data("qwerty".utf8))

        let signed = try await bundle(content, keypair: keypair, options: options)
        #expect(signed.mediaType == "application/vnd.dev.sigstore.bundle.v0.3+json")
        #expect(signed.verificationMaterial.publicKey.hint == String(decoding: keypair.hint, as: UTF8.self))

        // The JSON form parses and verifies on its own.
        let parsed = try Bundle(json: try signed.jsonUTF8Data())
        let verifier = try Verifier(
            trustedMaterial: trustedMaterial(keypair), options: [.withNoObserverTimestamps()])
        _ = try await verifier.verify(
            parsed, policy: PolicyBuilder(.withArtifact(content.data), .withoutIdentitiesUnsafe()))
        await #expect(throws: (any Error).self) {
            try await verifier.verify(
                parsed, policy: PolicyBuilder(.withArtifact(Data("qwertz".utf8)), .withoutIdentitiesUnsafe()))
        }
    }

    @Test func dsseBundleRoundTrips() async throws {
        let keypair = try EphemeralKeypair()
        let content = DSSEData(data: Self.statement, payloadType: "application/vnd.in-toto+json")
        let signed = try await bundle(content, keypair: keypair, options: BundleOptions(trustedRoot: trustedMaterial(keypair)))
        #expect(signed.dsseEnvelope.payload == Self.statement)

        let verifier = try Verifier(
            trustedMaterial: trustedMaterial(keypair), options: [.withNoObserverTimestamps()])
        let result = try await verifier.verify(
            try Bundle(signed),
            policy: PolicyBuilder(
                .withArtifactDigest(algorithm: "sha256", digest: Data(repeating: 0xab, count: 32)),
                .withoutIdentitiesUnsafe()))
        #expect(result.statement?.predicateType == "https://example.com/p")
    }

    @Test func bundleWithoutTrustedRootIsNotVerified() async throws {
        // Like sigstore-go's minimal happy path: no trusted root, no check.
        let signed = try await bundle(PlainData(data: Data("qwerty".utf8)), keypair: try EphemeralKeypair())
        #expect(!signed.messageSignature.signature.isEmpty)
    }

    @Test func bundleWithCorruptSignatureFailsVerification() async throws {
        let keypair = CorruptingKeypair(base: try EphemeralKeypair())
        await #expect(throws: (any Error).self) {
            try await bundle(
                PlainData(data: Data("qwerty".utf8)), keypair: keypair,
                options: BundleOptions(trustedRoot: self.trustedMaterial(keypair)))
        }
        await #expect(throws: (any Error).self) {
            try await bundle(
                DSSEData(data: Self.statement, payloadType: "application/vnd.in-toto+json"), keypair: keypair,
                options: BundleOptions(trustedRoot: self.trustedMaterial(keypair)))
        }
    }

    @Test func bundleWithUntrustedKeyFailsVerification() async throws {
        let keypair = try EphemeralKeypair()
        let other = try EphemeralKeypair()
        await #expect(throws: (any Error).self) {
            try await bundle(
                PlainData(data: Data("qwerty".utf8)), keypair: keypair,
                options: BundleOptions(trustedRoot: self.trustedMaterial(other)))
        }
    }

    @Test func nonUTF8HintIsRejected() async throws {
        let keypair = try EphemeralKeypair(options: EphemeralKeypairOptions(hint: Data([0xff, 0xfe])))
        await #expect(throws: (any Error).self) {
            try await bundle(PlainData(data: Data("qwerty".utf8)), keypair: keypair)
        }
    }

    @Test func mlDSAKeypairIsRejected() async throws {
        let keypair = MLDSAClaimingKeypair(base: try EphemeralKeypair())
        await #expect(throws: (any Error).self) {
            try await bundle(PlainData(data: Data("qwerty".utf8)), keypair: keypair)
        }
    }

    @Test func certificateProviderSetsCertificate() async throws {
        let der = try certificate(subject: "leaf", issuer: "ca", issuerKey: P256.Signing.PrivateKey())
        let signed = try await bundle(
            PlainData(data: Data("qwerty".utf8)), keypair: try EphemeralKeypair(),
            options: BundleOptions(certificateProvider: StaticCertificateProvider(der: der)))
        #expect(signed.verificationMaterial.certificate.rawBytes == der)
    }

    @Test func certificateChainProviderTakesPrecedence() async throws {
        let leaf = try certificate(subject: "leaf", issuer: "intermediate", issuerKey: P256.Signing.PrivateKey())
        let intermediate = try certificate(subject: "intermediate", issuer: "root", issuerKey: P256.Signing.PrivateKey())
        let other = try certificate(subject: "other", issuer: "ca", issuerKey: P256.Signing.PrivateKey())
        let signed = try await bundle(
            PlainData(data: Data("qwerty".utf8)), keypair: try EphemeralKeypair(),
            options: BundleOptions(
                certificateProvider: StaticCertificateProvider(der: other),
                certificateChainProvider: StaticChainProvider(chain: [leaf, intermediate])))
        #expect(signed.verificationMaterial.x509CertificateChain.certificates.map(\.rawBytes) == [leaf, intermediate])
    }

    @Test func emptyCertificateChainIsRejected() async throws {
        await #expect(throws: (any Error).self) {
            try await bundle(
                PlainData(data: Data("qwerty".utf8)), keypair: try EphemeralKeypair(),
                options: BundleOptions(certificateChainProvider: StaticChainProvider(chain: [])))
        }
    }

    @Test func selfSignedCertificateInChainIsRejected() async throws {
        let leaf = try certificate(subject: "leaf", issuer: "root", issuerKey: P256.Signing.PrivateKey())
        let root = try certificate(subject: "root", issuer: "root")
        await #expect(throws: (any Error).self) {
            try await bundle(
                PlainData(data: Data("qwerty".utf8)), keypair: try EphemeralKeypair(),
                options: BundleOptions(certificateChainProvider: StaticChainProvider(chain: [leaf, root])))
        }
        // Same subject and issuer, but signed by another key: not self-signed.
        let lookalike = try certificate(subject: "root", issuer: "root", issuerKey: P256.Signing.PrivateKey())
        _ = try await bundle(
            PlainData(data: Data("qwerty".utf8)), keypair: try EphemeralKeypair(),
            options: BundleOptions(certificateChainProvider: StaticChainProvider(chain: [leaf, lookalike])))
    }

    @Test func malformedChainCertificateIsRejected() async throws {
        let leaf = try certificate(subject: "leaf", issuer: "ca", issuerKey: P256.Signing.PrivateKey())
        await #expect(throws: (any Error).self) {
            try await bundle(
                PlainData(data: Data("qwerty".utf8)), keypair: try EphemeralKeypair(),
                options: BundleOptions(certificateChainProvider: StaticChainProvider(chain: [leaf, Data([0x30, 0x00])])))
        }
    }

    @Test func transparencyLogsGetTheVerifierPEM() async throws {
        let keypair = try EphemeralKeypair()
        let calls = Calls()
        _ = try await bundle(
            PlainData(data: Data("qwerty".utf8)), keypair: keypair,
            options: BundleOptions(transparencyLogs: [RecordingLog(calls: calls), RecordingLog(calls: calls)]))
        let pem = Data(try keypair.publicKeyPem().utf8)
        #expect(await calls.pems == [pem, pem])

        let der = try certificate(subject: "leaf", issuer: "ca", issuerKey: P256.Signing.PrivateKey())
        let certCalls = Calls()
        _ = try await bundle(
            PlainData(data: Data("qwerty".utf8)), keypair: keypair,
            options: BundleOptions(
                certificateProvider: StaticCertificateProvider(der: der),
                transparencyLogs: [RecordingLog(calls: certCalls)]))
        let certPEM = try await certCalls.pems.first.map { String(decoding: $0, as: UTF8.self) }
        #expect(certPEM?.hasPrefix("-----BEGIN CERTIFICATE-----\n") == true)
        #expect(try Certificate(pemEncoded: #require(certPEM)) == Certificate(derEncoded: Array(der)))
    }

    @Test func failingTransparencyLogFailsTheBundle() async throws {
        await #expect(throws: (any Error).self) {
            try await bundle(
                PlainData(data: Data("qwerty".utf8)), keypair: try EphemeralKeypair(),
                options: BundleOptions(transparencyLogs: [FailingLog()]))
        }
    }

    @Test func transparencyLogWithoutEntriesFailsVerification() async throws {
        // A log that adds no entry cannot meet the tlog threshold.
        let keypair = try EphemeralKeypair()
        await #expect(throws: (any Error).self) {
            try await bundle(
                PlainData(data: Data("qwerty".utf8)), keypair: keypair,
                options: BundleOptions(
                    transparencyLogs: [RecordingLog(calls: Calls())], trustedRoot: self.trustedMaterial(keypair)))
        }
    }
}
