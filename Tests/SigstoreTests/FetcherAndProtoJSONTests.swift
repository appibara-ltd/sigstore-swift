import Foundation
import Sigstore
import Testing

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Stub HTTP

/// A scripted response for `StubURLProtocol`.
struct StubResponse: Sendable {
    var status = 200
    var contentLength: Int?
    var chunks: [Data] = []
}

/// Serves scripted responses per URL path, in order (the last one repeats).
final class StubURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var scripts: [String: [StubResponse]] = [:]
    nonisolated(unsafe) private static var counts: [String: Int] = [:]

    static func script(_ path: String, _ responses: [StubResponse]) {
        lock.lock()
        scripts[path] = responses
        counts[path] = 0
        lock.unlock()
    }

    static func requestCount(_ path: String) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return counts[path] ?? 0
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let path = request.url?.path ?? ""
        Self.lock.lock()
        let list = Self.scripts[path] ?? [StubResponse(status: 404)]
        let n = Self.counts[path] ?? 0
        Self.counts[path] = n + 1
        Self.lock.unlock()
        let r = list[min(n, list.count - 1)]
        var headers: [String: String] = [:]
        if let l = r.contentLength { headers["Content-Length"] = String(l) }
        let response = HTTPURLResponse(url: request.url!, statusCode: r.status, httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        for chunk in r.chunks { client?.urlProtocol(self, didLoad: chunk) }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private func stubFetcher(maxAttempts: Int = 3) -> DefaultFetcher {
    DefaultFetcher(maxAttempts: maxAttempts) {
        let c = URLSessionConfiguration.ephemeral
        c.protocolClasses = [StubURLProtocol.self]
        return c
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

@Suite("TUF fetcher size limits", .serialized)
struct FetcherTests {
    @Test func bodyWithinLimitIsReturned() async throws {
        StubURLProtocol.script("/ok", [StubResponse(contentLength: 6, chunks: [Data("abc".utf8), Data("def".utf8)])])
        let data = try await stubFetcher().downloadFile("https://stub.test/ok", maxLength: 6)
        #expect(data == Data("abcdef".utf8))
    }

    /// No (or a lying) Content-Length: the body is cut off once it exceeds the limit.
    @Test func streamedBodyOverLimitIsRejected() async throws {
        let chunk = Data(repeating: 0x41, count: 1024)
        StubURLProtocol.script("/big", [StubResponse(chunks: Array(repeating: chunk, count: 64))])
        await expectError("is larger than expected 4096") {
            _ = try await stubFetcher().downloadFile("https://stub.test/big", maxLength: 4096)
        }
    }

    /// A Content-Length above the limit is rejected before the body is used.
    @Test func declaredLengthOverLimitIsRejected() async throws {
        StubURLProtocol.script("/declared", [StubResponse(contentLength: 1_000_000, chunks: [Data("x".utf8)])])
        await expectError("length 1000000 is larger than expected 10") {
            _ = try await stubFetcher().downloadFile("https://stub.test/declared", maxLength: 10)
        }
    }

    @Test func notFoundIsAnHTTPError() async throws {
        StubURLProtocol.script("/missing", [StubResponse(status: 404)])
        do {
            _ = try await stubFetcher().downloadFile("https://stub.test/missing", maxLength: 10)
            Issue.record("expected an error")
        } catch TUFError.downloadHTTP(let status, _) {
            #expect(status == 404)
        }
        #expect(StubURLProtocol.requestCount("/missing") == 1)  // 404 is not retried
    }

    @Test func serverErrorsAreRetried() async throws {
        StubURLProtocol.script(
            "/flaky", [StubResponse(status: 503), StubResponse(contentLength: 2, chunks: [Data("ok".utf8)])])
        let data = try await stubFetcher().downloadFile("https://stub.test/flaky", maxLength: 10)
        #expect(data == Data("ok".utf8))
        #expect(StubURLProtocol.requestCount("/flaky") == 2)
    }
}

// MARK: - protojson bytes

@Suite("protojson base64 (Go rules)")
struct ProtoJSONTests {
    /// Expected values from Go's encoding/base64 as protojson configures it.
    @Test func decodesLikeGo() {
        let cases: [(String, [UInt8]?)] = [
            ("QUJD", Array("ABC".utf8)),
            ("QUJDRA==", Array("ABCD".utf8)),
            ("QUJDRA", Array("ABCD".utf8)),  // len % 4 != 0: no padding
            ("QUJDRA=", nil),  // '=' not allowed without padding mode
            ("AAAA\nAAAA", [0, 0, 0, 0, 0, 0]),  // newlines skipped
            ("QUJD\nRA==", nil),  // len 9: no-padding mode, '=' invalid
            ("QUJDRA\n==", nil),
            ("-_8=", [0xFB, 0xFF]),  // URL alphabet
            ("+_8=", nil),  // mixed alphabets
            ("Q", nil),
        ]
        for (input, expected) in cases {
            #expect(Base64.decodeProtoJSON(input).map(Array.init) == expected, "\(input.debugDescription)")
        }
        // len("QUJD\r\nRA==") == 10: no-padding mode, so its '=' is invalid.
        #expect(Base64.decodeProtoJSON("QUJD\r\nRA==") == nil)
    }

    private func provenance(_ mutate: (inout [String: Any]) -> Void) throws -> Data {
        var json = try Fixtures.provenanceJSON()
        mutate(&json)
        return try JSONSerialization.data(withJSONObject: json)
    }

    private func setSig(_ json: inout [String: Any], _ transform: (String) -> String) {
        var env = json["dsseEnvelope"] as! [String: Any]
        var sigs = env["signatures"] as! [[String: Any]]
        sigs[0]["sig"] = transform(sigs[0]["sig"] as! String)
        env["signatures"] = sigs
        json["dsseEnvelope"] = env
    }

    /// Base64 wrapped with newlines (length a multiple of 4) is accepted, as
    /// Go accepts it, and the bundle still verifies.
    @Test func wrappedBase64IsAccepted() async throws {
        let data = try provenance { json in
            setSig(&json) { s in  // 96 chars + 4 newlines = 100
                stride(from: 0, to: s.count, by: 24).map { i in
                    let a = s.index(s.startIndex, offsetBy: i)
                    return String(s[a..<s.index(a, offsetBy: 24)])
                }.joined(separator: "\n") + "\n"
            }
        }
        let bundle = try SigstoreBundle.Bundle(json: data)
        _ = try await Fixtures.publicGoodVerifier().verify(bundle, policy: Fixtures.policy())
    }

    /// One newline in padded base64 makes the length not a multiple of 4, so
    /// Go switches to no-padding mode and rejects the '='.
    @Test func newlineWithPaddingIsRejectedLikeGo() throws {
        let data = try provenance { json in setSig(&json) { "\n" + $0 } }
        #expect { try SigstoreBundle.Bundle(json: data) } throws: {
            "\($0)".contains("invalid value for bytes field sig")
        }
    }

    @Test func duplicateFieldsAreRejected() throws {
        let json = #"{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","mediaType":"x"}"#
        #expect { try SigstoreBundle.Bundle(json: Data(json.utf8)) } throws: { "\($0)".contains("duplicate field") }
    }

    /// Struct-valued fields are free-form JSON: a predicate may use any key,
    /// including names of bytes fields elsewhere, with non-base64 values.
    @Test func freeFormPredicateIsNotTreatedAsBytes() throws {
        let json = #"{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"a","digest":{"sha256":"ab"}}],"predicateType":"x","predicate":{"content":"not base64!","signature":"x y z","nested":{"digest":"sha256:ab"}}}"#
        let statement = try Statement(json: Data(json.utf8))
        #expect(statement.predicate?.fields["content"]?.stringValue == "not base64!")
    }

    @Test func stringFieldsAreNotTouched() throws {
        let input = #"{"envelope":"a\nb","hint":"x-y","sig":"QUJD\nRA=="}"#
        // `sig` is a bytes field (here invalid per Go); the others are strings.
        #expect(throws: (any Error).self) { try ProtoJSON.normalizeBytesFields(Data(input.utf8)) }
        let ok = try ProtoJSON.normalizeBytesFields(Data(#"{"envelope":"a\nb","hint":"x-y","sig":"QUJD"}"#.utf8))
        let v = try JSONValue(parsing: ok)
        #expect(v["envelope"]?.stringValue == "a\nb")
        #expect(v["hint"]?.stringValue == "x-y")
    }
}
