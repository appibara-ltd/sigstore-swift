import Crypto
import Foundation
import Sigstore
import SwiftASN1
import Testing

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// sigstore-go pkg/sign timestamping_test.go and retry_test.go, against a
/// fake transport serving `TestTSA` responses.
@Suite("Signing: timestamp authorities")
struct TimestampingTests {
    static let url = "https://tsa.example.com/api/v1/timestamp"

    /// A transport that records requests and answers from a script.
    final class FakeTransport: HTTPTransport, @unchecked Sendable {
        typealias Handler = @Sendable (URLRequest, Int) async throws -> (Data, Int, [String: String])
        private let lock = NSLock()
        private var _requests: [URLRequest] = []
        private let handler: Handler

        init(_ handler: @escaping Handler) {
            self.handler = handler
        }

        var requests: [URLRequest] {
            lock.withLock { _requests }
        }

        func roundTrip(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
            let attempt = lock.withLock {
                _requests.append(request)
                return _requests.count
            }
            let (body, status, headers) = try await handler(request, attempt)
            guard let url = request.url,
                let response = HTTPURLResponse(
                    url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)
            else { throw SigstoreError("cannot build the response") }
            return (body, response)
        }
    }

    /// The (version, hash OID, NULL parameters, hashed message) of a DER
    /// TimeStampReq.
    static func parseRequest(_ body: Data) throws -> (Int, ASN1ObjectIdentifier, Bool, [UInt8]) {
        let root = try DER.parse(Array(body))
        return try DER.sequence(root, identifier: .sequence) { nodes in
            let version = try Int(derEncoded: &nodes)
            let imprint = try DER.sequence(try next(&nodes), identifier: .sequence) { nodes in
                let (oid, hasNull) = try DER.sequence(try next(&nodes), identifier: .sequence) { nodes in
                    let oid = try ASN1ObjectIdentifier(derEncoded: &nodes)
                    let hasNull = (try? ASN1Null(derEncoded: &nodes)) != nil
                    return (oid, hasNull)
                }
                let digest = try ASN1OctetString(derEncoded: &nodes)
                return (oid, hasNull, Array(digest.bytes))
            }
            guard nodes.next() == nil else { throw SigstoreError("unexpected optional fields") }
            return (version, imprint.0, imprint.1, imprint.2)
        }
    }

    private static func next(_ nodes: inout ASN1NodeCollection.Iterator) throws -> ASN1Node {
        guard let node = nodes.next() else { throw SigstoreError("truncated TimeStampReq") }
        return node
    }

    /// A transport answering every request with a timestamp from `tsa`.
    static func serving(_ tsa: TestTSA) -> FakeTransport {
        FakeTransport { request, _ in
            let (_, _, _, digest) = try parseRequest(try #require(request.httpBody))
            return (try tsa.response(imprint: digest), 200, [:])
        }
    }

    // MARK: Requests

    @Test func requestsATimestampOverTheSignatureDigest() async throws {
        let tsa = try TestTSA()
        let transport = Self.serving(tsa)
        let signature = Data("a signature".utf8)
        let authority = TimestampAuthority(options: TimestampAuthorityOptions(url: Self.url, transport: transport))

        let response = try await authority.timestamp(signature: signature)
        let parsed = try RFC3161Timestamp.parseResponse(Array(response))
        #expect(parsed.hashedMessage == Array(SHA256.hash(data: signature)))

        let request = try #require(transport.requests.first)
        #expect(transport.requests.count == 1)
        #expect(request.url?.absoluteString == Self.url)
        #expect(request.httpMethod == "POST")
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/timestamp-query")
        #expect(request.value(forHTTPHeaderField: "User-Agent") == "sigstore-swift")
        let (version, oid, hasNull, digest) = try Self.parseRequest(try #require(request.httpBody))
        #expect(version == 1)
        #expect(oid == [2, 16, 840, 1, 101, 3, 4, 2, 1])
        #expect(hasNull)
        #expect(digest == Array(SHA256.hash(data: signature)))
    }

    @Test func userAgentPrefix() async throws {
        let transport = Self.serving(try TestTSA())
        let authority = TimestampAuthority(
            options: TimestampAuthorityOptions(url: Self.url, transport: transport, userAgent: "my-tool/1.0"))
        _ = try await authority.timestamp(signature: Data([1]))
        #expect(transport.requests.first?.value(forHTTPHeaderField: "User-Agent") == "my-tool/1.0 sigstore-swift")
    }

    @Test func status201IsAccepted() async throws {
        let tsa = try TestTSA()
        let transport = FakeTransport { request, _ in
            let (_, _, _, digest) = try Self.parseRequest(try #require(request.httpBody))
            return (try tsa.response(imprint: digest), 201, [:])
        }
        let authority = TimestampAuthority(options: TimestampAuthorityOptions(url: Self.url, transport: transport))
        _ = try await authority.timestamp(signature: Data([1]))
    }

    // MARK: Failures

    @Test(arguments: [400, 404, 500, 501])
    func errorStatusFails(status: Int) async throws {
        let transport = FakeTransport { _, _ in (Data("nope".utf8), status, [:]) }
        let authority = TimestampAuthority(options: TimestampAuthorityOptions(url: Self.url, transport: transport))
        await #expect(throws: (any Error).self) { try await authority.timestamp(signature: Data([1])) }
        #expect(transport.requests.count == 1)
    }

    @Test func rejectedTimestampFails() async throws {
        let tsa = try TestTSA()
        var options = TestTSA.TokenOptions()
        options.status = 2
        let rejected = try tsa.response(for: [1], options)
        let transport = FakeTransport { _, _ in (rejected, 200, [:]) }
        let authority = TimestampAuthority(options: TimestampAuthorityOptions(url: Self.url, transport: transport))
        await #expect(throws: (any Error).self) { try await authority.timestamp(signature: Data([1])) }
    }

    @Test func tamperedTimestampFails() async throws {
        // The embedded certificate does not verify the token's signature.
        let tsa = try TestTSA()
        var options = TestTSA.TokenOptions()
        options.tamperSignature = true
        let tampered = options
        let transport = FakeTransport { request, _ in
            let (_, _, _, digest) = try Self.parseRequest(try #require(request.httpBody))
            return (try tsa.response(imprint: digest, tampered), 200, [:])
        }
        let authority = TimestampAuthority(options: TimestampAuthorityOptions(url: Self.url, transport: transport))
        await #expect(throws: (any Error).self) { try await authority.timestamp(signature: Data([1])) }
    }

    @Test(arguments: [Data(), Data("not DER".utf8), Data([0x30, 0x03, 0x02, 0x01, 0x00])])
    func malformedResponseFails(body: Data) async throws {
        let transport = FakeTransport { _, _ in (body, 200, [:]) }
        let authority = TimestampAuthority(options: TimestampAuthorityOptions(url: Self.url, transport: transport))
        await #expect(throws: (any Error).self) { try await authority.timestamp(signature: Data([1])) }
    }

    @Test func oversizedResponseFails() async throws {
        let tsa = try TestTSA()
        let transport = FakeTransport { request, _ in
            let (_, _, _, digest) = try Self.parseRequest(try #require(request.httpBody))
            var body = try tsa.response(imprint: digest)
            body.append(Data(count: 1 << 20))
            return (body, 200, [:])
        }
        let authority = TimestampAuthority(options: TimestampAuthorityOptions(url: Self.url, transport: transport))
        await #expect(throws: (any Error).self) { try await authority.timestamp(signature: Data([1])) }
    }

    @Test func invalidURLFails() async throws {
        let transport = FakeTransport { _, _ in (Data(), 200, [:]) }
        let authority = TimestampAuthority(options: TimestampAuthorityOptions(url: "", transport: transport))
        await #expect(throws: (any Error).self) { try await authority.timestamp(signature: Data([1])) }
        #expect(transport.requests.isEmpty)
    }

    @Test func timeoutCoversTheRequest() async throws {
        let transport = FakeTransport { _, _ in
            try await Task.sleep(nanoseconds: 60_000_000_000)
            return (Data(), 200, [:])
        }
        let authority = TimestampAuthority(
            options: TimestampAuthorityOptions(url: Self.url, timeout: 0.2, transport: transport))
        let start = Date()
        await #expect(throws: (any Error).self) { try await authority.timestamp(signature: Data([1])) }
        // Far below the transport's 60 s: the deadline cancelled it. Loose,
        // because busy CI runners (Windows) schedule tasks slowly.
        #expect(Date().timeIntervalSince(start) < 30)
    }

    // MARK: Retries

    @Test func retriesAreOffByDefault() async throws {
        let transport = FakeTransport { _, _ in (Data(), 503, [:]) }
        let authority = TimestampAuthority(options: TimestampAuthorityOptions(url: Self.url, transport: transport))
        await #expect(throws: (any Error).self) { try await authority.timestamp(signature: Data([1])) }
        #expect(transport.requests.count == 1)
    }

    @Test func transientFailureIsRetried() async throws {
        let tsa = try TestTSA()
        let transport = FakeTransport { request, attempt in
            if attempt == 1 { return (Data(), 503, [:]) }
            let (_, _, _, digest) = try Self.parseRequest(try #require(request.httpBody))
            return (try tsa.response(imprint: digest), 200, [:])
        }
        // One retry after the default 1 s backoff.
        let authority = TimestampAuthority(
            options: TimestampAuthorityOptions(url: Self.url, retries: 1, transport: transport))
        _ = try await authority.timestamp(signature: Data([1]))
        #expect(transport.requests.count == 2)
    }

    /// Statuses `httpretry.DefaultRetryPolicy` retries.
    @Test(arguments: [(429, true), (500, true), (502, true), (503, true), (501, false), (400, false), (404, false)])
    func retryPolicyByStatus(status: Int, retried: Bool) async throws {
        let transport = FakeTransport { _, _ in (Data(), status, [:]) }
        let retrying = HTTPRetryTransport(base: transport, maxRetries: 2, waitMin: 0, waitMax: 0)
        let (_, response) = try await retrying.roundTrip(URLRequest(url: try #require(URL(string: Self.url))))
        #expect(response.statusCode == status)
        #expect(transport.requests.count == (retried ? 3 : 1))
    }

    @Test(arguments: [
        (URLError(.networkConnectionLost) as any Error, true),
        (URLError(.cannotConnectToHost), true),
        (URLError(.serverCertificateUntrusted), false),
        (URLError(.serverCertificateHasUnknownRoot), false),
        (URLError(.unsupportedURL), false),
        (URLError(.cancelled), false),
        (CancellationError(), false),
    ])
    func retryPolicyByError(error: any Error, retried: Bool) async throws {
        let transport = FakeTransport { _, _ in throw error }
        let retrying = HTTPRetryTransport(base: transport, maxRetries: 2, waitMin: 0, waitMax: 0)
        await #expect(throws: (any Error).self) {
            try await retrying.roundTrip(URLRequest(url: try #require(URL(string: Self.url))))
        }
        #expect(transport.requests.count == (retried ? 3 : 1))
    }

    // MARK: URLSessionTransport

    private func stubTransport(maxResponseLength: Int = 16 << 20) -> URLSessionTransport {
        URLSessionTransport(maxResponseLength: maxResponseLength) {
            let c = URLSessionConfiguration.ephemeral
            c.protocolClasses = [StubURLProtocol.self]
            return c
        }
    }

    private func request(_ path: String) throws -> URLRequest {
        URLRequest(url: try #require(URL(string: "https://stub.test\(path)")))
    }

    @Test func urlSessionTransportReturnsBodyAndStatus() async throws {
        StubURLProtocol.script("/sign-ok", [StubResponse(status: 201, chunks: [Data("ab".utf8), Data("c".utf8)])])
        let (body, response) = try await stubTransport().roundTrip(try request("/sign-ok"))
        #expect(body == Data("abc".utf8))
        #expect(response.statusCode == 201)

        // An error status is a response, not a thrown error.
        StubURLProtocol.script("/sign-missing", [StubResponse(status: 404)])
        let (_, missing) = try await stubTransport().roundTrip(try request("/sign-missing"))
        #expect(missing.statusCode == 404)
    }

    @Test func urlSessionTransportRejectsLongBodies() async throws {
        let chunk = Data(repeating: 0x41, count: 1024)
        StubURLProtocol.script("/sign-big", [StubResponse(chunks: Array(repeating: chunk, count: 8))])
        await #expect(throws: (any Error).self) {
            try await self.stubTransport(maxResponseLength: 4096).roundTrip(try self.request("/sign-big"))
        }
        StubURLProtocol.script("/sign-declared", [StubResponse(contentLength: 1_000_000, chunks: [Data("x".utf8)])])
        await #expect(throws: (any Error).self) {
            try await self.stubTransport(maxResponseLength: 10).roundTrip(try self.request("/sign-declared"))
        }
    }

    // MARK: Bundles

    @Test func bundleWithTimestampAuthorityVerifies() async throws {
        let tsa = try TestTSA()
        let keypair = try EphemeralKeypair()
        let trusted = TrustedMaterialCollection([try tsa.trustedMaterial(), keyMaterial(keypair)])
        let content = PlainData(data: Data("qwerty".utf8))

        let signed = try await bundle(
            content, keypair: keypair,
            options: BundleOptions(
                timestampAuthorities: [
                    TimestampAuthority(options: TimestampAuthorityOptions(url: Self.url, transport: Self.serving(tsa)))
                ],
                trustedRoot: trusted))
        let timestamps = signed.verificationMaterial.timestampVerificationData.rfc3161Timestamps
        #expect(timestamps.count == 1)
        let parsed = try RFC3161Timestamp.parseResponse(Array(timestamps[0].signedTimestamp))
        #expect(parsed.hashedMessage == Array(SHA256.hash(data: signed.messageSignature.signature)))

        // The bundle needs the signed timestamp: one more than it has fails.
        let verifier = try Verifier(trustedMaterial: trusted, options: [.withSignedTimestamps(threshold: 2)])
        await #expect(throws: (any Error).self) {
            try await verifier.verify(
                try Bundle(signed), policy: PolicyBuilder(.withArtifact(content.data), .withoutIdentitiesUnsafe()))
        }
    }

    @Test func bundleWithTimestampFromUntrustedAuthorityFails() async throws {
        let trustedTSA = try TestTSA()
        let otherTSA = try TestTSA()
        let keypair = try EphemeralKeypair()
        await #expect(throws: (any Error).self) {
            try await bundle(
                PlainData(data: Data("qwerty".utf8)), keypair: keypair,
                options: BundleOptions(
                    timestampAuthorities: [
                        TimestampAuthority(
                            options: TimestampAuthorityOptions(url: Self.url, transport: Self.serving(otherTSA)))
                    ],
                    trustedRoot: TrustedMaterialCollection([try trustedTSA.trustedMaterial(), keyMaterial(keypair)])))
        }
    }

    @Test func failingTimestampAuthorityFailsTheBundle() async throws {
        let transport = FakeTransport { _, _ in (Data(), 500, [:]) }
        await #expect(throws: (any Error).self) {
            try await bundle(
                PlainData(data: Data("qwerty".utf8)), keypair: try EphemeralKeypair(),
                options: BundleOptions(timestampAuthorities: [
                    TimestampAuthority(options: TimestampAuthorityOptions(url: Self.url, transport: transport))
                ]))
        }
    }

    private func keyMaterial(_ keypair: EphemeralKeypair) -> TrustedPublicKeyMaterial {
        let publicKey = keypair.publicKey
        return TrustedPublicKeyMaterial(publicKeyVerifier: { _ in
            ExpiringKey(
                verifier: try SignatureVerifier(publicKey: publicKey), validityPeriodStart: nil,
                validityPeriodEnd: nil)
        })
    }
}
