import Foundation
import Sigstore
import Testing

// Port of sigstore-go v1.4.1 pkg/root/signing_config_test.go, plus strict
// parsing and TUF checks.

/// Deterministic generator (SplitMix64) for the random selectors.
private struct SeededGenerator: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

/// Whole seconds, so dates survive the protobuf `Timestamp` round trip exactly.
private let now = Date(timeIntervalSince1970: 1_767_225_600)  // 2026-01-01T00:00:00Z
private let hour: TimeInterval = 3600

private func fixture(_ name: String) throws -> Data {
    try Fixtures.file("\(name).json")
}

private func expectError(_ prefix: String, sourceLocation: SourceLocation = #_sourceLocation, _ body: () throws -> Void) {
    do {
        try body()
        Issue.record("expected an error starting with \"\(prefix)\"", sourceLocation: sourceLocation)
    } catch {
        #expect("\(error)".hasPrefix(prefix), "\(error)", sourceLocation: sourceLocation)
    }
}

private func jsonObject(_ data: Data) throws -> NSDictionary {
    try #require(JSONSerialization.jsonObject(with: data) as? NSDictionary)
}

@Suite("SigningConfig")
struct SigningConfigTests {
    // MARK: SelectService (TestSelectService)

    private let selectServiceFixtures: [Service] = [
        Service(url: "past-future-v1", majorAPIVersion: 1, validityPeriodStart: now - hour, validityPeriodEnd: now + hour, operator: "operator"),
        // Never selected: now-future-v2 is newer.
        Service(url: "past-future-v2", majorAPIVersion: 2, validityPeriodStart: now - hour, validityPeriodEnd: now + hour, operator: "operator"),
        Service(url: "now-future-v2", majorAPIVersion: 2, validityPeriodStart: now - 60, validityPeriodEnd: now + hour, operator: "operator"),
        Service(url: "farfuture-present-v2", majorAPIVersion: 2, validityPeriodStart: now + 2 * hour, validityPeriodEnd: nil, operator: "operator"),
    ]

    @Test func selectServiceMatches() throws {
        let s = selectServiceFixtures
        #expect(try selectService(s, supportedAPIVersions: [1], currentTime: now).url == "past-future-v1")
        #expect(try selectService(s, supportedAPIVersions: [2], currentTime: now).url == "now-future-v2")
        // Valid with no end time.
        #expect(try selectService(s, supportedAPIVersions: [2], currentTime: now + 2 * hour).url == "farfuture-present-v2")
        // Highest supported API version first.
        #expect(try selectService(s, supportedAPIVersions: [1, 2], currentTime: now).url == "now-future-v2")
        let v1Only = [Service(url: "past-future-v1", majorAPIVersion: 1, validityPeriodStart: now - hour, validityPeriodEnd: now + hour)]
        #expect(try selectService(v1Only, supportedAPIVersions: [2, 1], currentTime: now).url == "past-future-v1")
    }

    @Test func selectServiceErrors() {
        let s = selectServiceFixtures
        expectError("no matching service found for API versions [3] and current time") {
            _ = try selectService(s, supportedAPIVersions: [3], currentTime: now)
        }
        expectError("no matching service found for API versions [1] and current time") {
            _ = try selectService([], supportedAPIVersions: [1], currentTime: now)
        }
        expectError("no supported API versions") { _ = try selectService(s, supportedAPIVersions: [], currentTime: now) }
        // Outside every validity window.
        expectError("no matching service found for API versions [1 2] and current time") {
            _ = try selectService(s, supportedAPIVersions: [1, 2], currentTime: now - 2 * hour)
        }
    }

    @Test func validityBoundsAreInclusive() {
        let s = Service(url: "u", majorAPIVersion: 1, validityPeriodStart: now, validityPeriodEnd: now + hour)
        #expect(s.validAtTime(now))
        #expect(s.validAtTime(now + hour))
        #expect(!s.validAtTime(now - 1))
        #expect(!s.validAtTime(now + hour + 1))
        #expect(Service(url: "u", majorAPIVersion: 1).validAtTime(.distantPast))
    }

    // MARK: SelectServices (TestSelectServices)

    private let selectServicesFixtures: [Service] = [
        Service(url: "past-future-v1", majorAPIVersion: 1, validityPeriodStart: now - hour, validityPeriodEnd: now + hour, operator: "operator"),
        // Never selected: now-future-v2 is newer and has the same operator.
        Service(url: "past-future-v2", majorAPIVersion: 2, validityPeriodStart: now - hour, validityPeriodEnd: now + hour, operator: "operator"),
        Service(url: "now-future-v2", majorAPIVersion: 2, validityPeriodStart: now, validityPeriodEnd: now + hour, operator: "operator"),
        Service(url: "past-future-v2-diff-op", majorAPIVersion: 2, validityPeriodStart: now - hour, validityPeriodEnd: now + hour, operator: "operator-other"),
    ]

    private func urls(_ selector: Dev_Sigstore_Trustroot_V1_ServiceSelector, count: UInt32 = 0, versions: [UInt32],
                      services: [Service]? = nil, seed: UInt64 = 1) throws -> [String] {
        var rng = SeededGenerator(state: seed)
        return try selectServices(services ?? selectServicesFixtures, config: ServiceConfiguration(selector: selector, count: count),
                                  supportedAPIVersions: versions, currentTime: now, using: &rng).map(\.url)
    }

    @Test func selectServicesAll() throws {
        #expect(try urls(.all, versions: [2]) == ["now-future-v2", "past-future-v2-diff-op"])
        #expect(try urls(.all, versions: [1]) == ["past-future-v1"])
        #expect(try urls(.all, versions: [1, 2]) == ["now-future-v2", "past-future-v2-diff-op"])
        let v1Only = [Service(url: "past-future-v1", majorAPIVersion: 1, validityPeriodStart: now - hour, validityPeriodEnd: now + hour)]
        #expect(try urls(.all, versions: [2, 1], services: v1Only) == ["past-future-v1"])
        // The highest API version wins even when a lower-version service is newer.
        let mixed = [
            Service(url: "svc-v2", majorAPIVersion: 2, validityPeriodStart: now - hour, operator: "operator"),
            Service(url: "svc-v1", majorAPIVersion: 1, validityPeriodStart: now, operator: "operator"),
            Service(url: "svc-op-other-v2", majorAPIVersion: 2, validityPeriodStart: now - 2 * hour, operator: "operator-other"),
        ]
        #expect(try urls(.all, versions: [1, 2], services: mixed) == ["svc-v2", "svc-op-other-v2"])
    }

    @Test func selectServicesAnyAndExactPickFromTheCandidates() throws {
        var seenAny = Set<[String]>()
        var seenExact2 = Set<[String]>()
        for seed in UInt64(0)..<64 {
            let any = try urls(.any, versions: [2], seed: seed)
            #expect([["now-future-v2"], ["past-future-v2-diff-op"]].contains(any))
            seenAny.insert(any)
            let exact1 = try urls(.exact, count: 1, versions: [2], seed: seed)
            #expect([["now-future-v2"], ["past-future-v2-diff-op"]].contains(exact1))
            let exact2 = try urls(.exact, count: 2, versions: [2], seed: seed)
            #expect([["now-future-v2", "past-future-v2-diff-op"], ["past-future-v2-diff-op", "now-future-v2"]].contains(exact2))
            seenExact2.insert(exact2)
        }
        #expect(seenAny.count == 2)
        #expect(seenExact2.count == 2)
        #expect(try urls(.any, versions: [1]) == ["past-future-v1"])
        #expect(try urls(.exact, count: 1, versions: [1]) == ["past-future-v1"])
        // The system generator overload.
        let all = try selectServices(selectServicesFixtures, config: ServiceConfiguration(selector: .exact, count: 2),
                                     supportedAPIVersions: [2], currentTime: now)
        #expect(Set(all.map(\.url)) == ["now-future-v2", "past-future-v2-diff-op"])
    }

    @Test func selectServicesErrors() {
        for selector in [Dev_Sigstore_Trustroot_V1_ServiceSelector.all, .any, .exact] {
            expectError("no matching services found for API versions [3] and current time") {
                _ = try urls(selector, count: 1, versions: [3])
            }
        }
        expectError("service selector count must be greater than 0") { _ = try urls(.exact, count: 0, versions: [2]) }
        expectError("service selector count 3 must be less than or equal to the slice length 2") {
            _ = try urls(.exact, count: 3, versions: [2])
        }
        expectError("service selector count 3 must be less than or equal to the slice length 2") {
            _ = try urls(.exact, count: 3, versions: [1, 2])
        }
        expectError("service selector count 100 must be less than or equal to the slice length 2") {
            _ = try urls(.exact, count: 100, versions: [2])
        }
        expectError("invalid service selector") { _ = try urls(.UNRECOGNIZED(99), versions: [2]) }
        expectError("invalid service selector") { _ = try urls(.undefined, versions: [2]) }
        expectError("no supported API versions") { _ = try urls(.all, versions: []) }
    }

    // MARK: Accessors

    @Test func accessorsReadTheProtobuf() throws {
        var pb = Dev_Sigstore_Trustroot_V1_SigningConfig()
        pb.mediaType = signingConfigMediaType02
        func service(_ url: String, end: Bool = true) -> Dev_Sigstore_Trustroot_V1_Service {
            Service(url: url, majorAPIVersion: 1, validityPeriodStart: now, validityPeriodEnd: end ? now : nil, operator: "op")
                .toServiceProtobuf()
        }
        pb.caUrls = [service("https://fulcio.sigstore.dev")]
        pb.oidcUrls = [service("https://oauth2.sigstore.dev/auth")]
        pb.rekorTlogUrls = [service("https://rekor.sigstore.dev")]
        pb.tsaUrls = [service("https://timestamp.sigstore.dev", end: false)]
        pb.rekorTlogConfig.selector = .exact
        pb.rekorTlogConfig.count = 1

        let sc = try SigningConfig(protobuf: pb)
        let expected = { (url: String) in Service(url: url, majorAPIVersion: 1, validityPeriodStart: now, validityPeriodEnd: now, operator: "op") }
        #expect(sc.fulcioCertificateAuthorityURLs == [expected("https://fulcio.sigstore.dev")])
        #expect(sc.oidcProviderURLs == [expected("https://oauth2.sigstore.dev/auth")])
        #expect(sc.rekorLogURLs == [expected("https://rekor.sigstore.dev")])
        #expect(sc.timestampAuthorityURLs == [Service(url: "https://timestamp.sigstore.dev", majorAPIVersion: 1, validityPeriodStart: now, operator: "op")])
        #expect(sc.rekorLogURLsConfig == ServiceConfiguration(selector: .exact, count: 1))
        // Unset configurations read as empty (Go dereferences nil here).
        #expect(sc.timestampAuthorityURLsConfig == ServiceConfiguration())

        let empty = try SigningConfig(protobuf: { var p = Dev_Sigstore_Trustroot_V1_SigningConfig(); p.mediaType = signingConfigMediaType02; return p }())
        #expect(empty.fulcioCertificateAuthorityURLs.isEmpty)
        #expect(empty.oidcProviderURLs.isEmpty)
        #expect(empty.rekorLogURLs.isEmpty)
        #expect(empty.timestampAuthorityURLs.isEmpty)
        #expect(empty.rekorLogURLsConfig == ServiceConfiguration())
    }

    // MARK: NewSigningConfig and builders

    @Test func newSigningConfig() throws {
        let svc = { (url: String) in Service(url: url, majorAPIVersion: 1, validityPeriodStart: now, validityPeriodEnd: now + hour, operator: "operator") }
        let config = ServiceConfiguration(selector: .any)
        let sc = try SigningConfig(
            mediaType: signingConfigMediaType02,
            fulcioCertificateAuthorities: [svc("https://fulcio.sigstore.dev")], oidcProviders: [svc("https://oauth2.sigstore.dev/auth")],
            rekorLogs: [svc("https://rekor.sigstore.dev")], rekorLogsConfig: config,
            timestampAuthorities: [svc("https://timestamp.sigstore.dev")], timestampAuthoritiesConfig: config
        )
        #expect(sc.fulcioCertificateAuthorityURLs == [svc("https://fulcio.sigstore.dev")])
        #expect(sc.oidcProviderURLs == [svc("https://oauth2.sigstore.dev/auth")])
        #expect(sc.rekorLogURLs == [svc("https://rekor.sigstore.dev")])
        #expect(sc.timestampAuthorityURLs == [svc("https://timestamp.sigstore.dev")])
        #expect(sc.rekorLogURLsConfig == config)
        #expect(sc.timestampAuthorityURLsConfig == config)

        expectError("unsupported SigningConfig media type, must be: \(signingConfigMediaType02)") {
            _ = try SigningConfig(mediaType: "application/json", fulcioCertificateAuthorities: [], oidcProviders: [], rekorLogs: [],
                                  rekorLogsConfig: config, timestampAuthorities: [], timestampAuthoritiesConfig: config)
        }
    }

    @Test func withAndAddBuilders() throws {
        let svc = { (url: String) in Service(url: url, majorAPIVersion: 1, validityPeriodStart: now - hour, validityPeriodEnd: now + hour, operator: "operator") }
        let base = try SigningConfig(mediaType: signingConfigMediaType02, fulcioCertificateAuthorities: [], oidcProviders: [], rekorLogs: [],
                                     rekorLogsConfig: ServiceConfiguration(), timestampAuthorities: [], timestampAuthoritiesConfig: ServiceConfiguration())
        let sc = base.withFulcioCertificateAuthorityURLs(svc("ca-url"))
            .withOIDCProviderURLs(svc("oidc-url"))
            .withRekorLogURLs(svc("rekor-url"))
            .withTimestampAuthorityURLs(svc("tsa-url"))
            .withRekorTlogConfig(selector: .exact, count: 1)
            .withTsaConfig(selector: .exact, count: 1)
        #expect(sc.fulcioCertificateAuthorityURLs == [svc("ca-url")])
        #expect(sc.oidcProviderURLs == [svc("oidc-url")])
        #expect(sc.rekorLogURLs == [svc("rekor-url")])
        #expect(sc.timestampAuthorityURLs == [svc("tsa-url")])
        #expect(sc.rekorLogURLsConfig == ServiceConfiguration(selector: .exact, count: 1))
        #expect(sc.timestampAuthorityURLsConfig == ServiceConfiguration(selector: .exact, count: 1))

        let added = sc.addFulcioCertificateAuthorityURLs(svc("ca-url2")).addOIDCProviderURLs(svc("oidc-url2"))
            .addRekorLogURLs(svc("rekor-url2")).addTimestampAuthorityURLs(svc("tsa-url2"))
        #expect(added.fulcioCertificateAuthorityURLs == [svc("ca-url"), svc("ca-url2")])
        #expect(added.oidcProviderURLs == [svc("oidc-url"), svc("oidc-url2")])
        #expect(added.rekorLogURLs == [svc("rekor-url"), svc("rekor-url2")])
        #expect(added.timestampAuthorityURLs == [svc("tsa-url"), svc("tsa-url2")])
        // Value semantics: builders return copies.
        #expect(base.fulcioCertificateAuthorityURLs.isEmpty)
        #expect(sc.fulcioCertificateAuthorityURLs.count == 1)
        // `with…` replaces.
        #expect(added.withRekorLogURLs(svc("only")).rekorLogURLs == [svc("only")])
    }

    // MARK: JSON

    /// TestSigningConfig_MarshalJSON: same JSON as Go's `protojson.Marshal`.
    @Test func marshalJSONMatchesGo() throws {
        let start = Date(timeIntervalSince1970: 1_672_531_200)  // 2023-01-01T00:00:00Z
        let s = { (url: String, end: Bool) in
            Service(url: url, majorAPIVersion: 1, validityPeriodStart: start, validityPeriodEnd: end ? start + hour : nil, operator: "operator")
        }
        let sc = try SigningConfig(
            mediaType: signingConfigMediaType02,
            fulcioCertificateAuthorities: [s("fulcio", true)], oidcProviders: [s("oidc", false)],
            rekorLogs: [s("rekor", true)], rekorLogsConfig: ServiceConfiguration(selector: .any, count: 1),
            timestampAuthorities: [s("tsa", true)], timestampAuthoritiesConfig: ServiceConfiguration(selector: .exact, count: 1)
        )
        let goJSON = """
        {"mediaType":"\(signingConfigMediaType02)",
         "caUrls":[{"url":"fulcio","majorApiVersion":1,"validFor":{"start":"2023-01-01T00:00:00Z","end":"2023-01-01T01:00:00Z"},"operator":"operator"}],
         "oidcUrls":[{"url":"oidc","majorApiVersion":1,"validFor":{"start":"2023-01-01T00:00:00Z"},"operator":"operator"}],
         "rekorTlogUrls":[{"url":"rekor","majorApiVersion":1,"validFor":{"start":"2023-01-01T00:00:00Z","end":"2023-01-01T01:00:00Z"},"operator":"operator"}],
         "rekorTlogConfig":{"selector":"ANY","count":1},
         "tsaUrls":[{"url":"tsa","majorApiVersion":1,"validFor":{"start":"2023-01-01T00:00:00Z","end":"2023-01-01T01:00:00Z"},"operator":"operator"}],
         "tsaConfig":{"selector":"EXACT","count":1}}
        """
        #expect(try jsonObject(sc.marshalJSON()) == jsonObject(Data(goJSON.utf8)))
        // Round trip.
        #expect(try SigningConfig(json: sc.marshalJSON()).protobuf == sc.protobuf)
    }

    /// Go's `ToServiceProtobuf` writes its zero time for an unset start.
    @Test func unsetStartSerializesAsGoZeroTime() throws {
        let pb = Service(url: "u", majorAPIVersion: 1).toServiceProtobuf()
        let json = try jsonObject(pb.jsonUTF8Data())
        #expect((json["validFor"] as? NSDictionary)?["start"] as? String == "0001-01-01T00:00:00Z")
        #expect((json["validFor"] as? NSDictionary)?["end"] == nil)
        // Read back, it is still valid at any time after year 1.
        #expect(Service(protobuf: pb).validAtTime(now))
    }

    /// TestNewSigningConfigFromPath: sigstore-go examples/signing_config.v0.2.json.
    @Test func parsesTheSigstoreGoExample() throws {
        // NewSigningConfigFromPath: write the fixture out and load it by path.
        let path = NSTemporaryDirectory() + "signing_config-\(UUID().uuidString).json"
        try fixture("signing_config.v0.2").write(to: URL(fileURLWithPath: path))
        defer { try? FileManager.default.removeItem(atPath: path) }
        let sc = try SigningConfig(path: path)
        #expect(sc.fulcioCertificateAuthorityURLs.map(\.url) == ["https://fulcio.sigstore.dev"])
        #expect(sc.oidcProviderURLs.map(\.url) == ["https://oauth2.sigstore.dev/auth"])
        #expect(sc.rekorLogURLs.map(\.url) == ["https://rekor.sigstore.dev"])
        #expect(sc.timestampAuthorityURLs.map(\.url) == ["https://timestamp.sigstore.dev/api/v1/timestamp"])
        #expect(sc.rekorLogURLsConfig.selector == .any)
        #expect(sc.timestampAuthorityURLsConfig.selector == .any)
        #expect(sc.fulcioCertificateAuthorityURLs.first?.validityPeriodStart == ISO8601DateFormatter().date(from: "2022-04-13T20:06:15Z"))
        #expect(sc.fulcioCertificateAuthorityURLs.first?.validityPeriodEnd == nil)
        #expect(sc.fulcioCertificateAuthorityURLs.first?.operator == "sigstore.dev")
        #expect(try selectService(sc.rekorLogURLs, supportedAPIVersions: [1, 2], currentTime: now).url == "https://rekor.sigstore.dev")
    }

    @Test func strictParsingRejectsMalformedConfigs() throws {
        let example = String(decoding: try fixture("signing_config.v0.2"), as: UTF8.self)
        let cases: [(String, String)] = [
            ("unknown field", example.replacingOccurrences(of: "\"caUrls\"", with: "\"unknownField\": 1, \"caUrls\"")),
            ("duplicate key", example.replacingOccurrences(of: "\"caUrls\"", with: "\"tsaConfig\": {}, \"caUrls\"")),
            ("wrong media type", example.replacingOccurrences(of: "signingconfig.v0.2", with: "signingconfig.v0.1")),
            ("bad selector", example.replacingOccurrences(of: "\"selector\": \"ANY\"", with: "\"selector\": \"SOME\"")),
            ("bad timestamp", example.replacingOccurrences(of: "2022-04-13T20:06:15.000Z", with: "yesterday")),
            ("not JSON", "{"),
        ]
        for (name, json) in cases {
            #expect(json != example || name == "not JSON", "\(name): fixture text not found")
            #expect(throws: (any Error).self, "\(name)") { _ = try SigningConfig(json: Data(json.utf8)) }
        }
        expectError("unsupported SigningConfig media type: ") { _ = try SigningConfig(protobuf: .init()) }
        expectError("failed to read signing config") { _ = try SigningConfig(path: "/nonexistent/signing_config.json") }
    }

    // MARK: TUF

    @Test func getSigningConfigFromTUF() async throws {
        var repo = TestTUFRepo()
        _ = repo.publishRoot(version: 1)
        repo.publish(targets: [defaultSigningConfigTarget: try fixture("signing_config.v0.2")])
        let opts = SigstoreTUF.Options().withRoot(repo.files["1.root.json"]!).withRepositoryBaseURL(TestTUFRepo.baseURL)
            .withFetcher(MemoryFetcher(repo.files)).withDisableLocalCache()

        let sc = try await fetchSigningConfigWithOptions(opts)
        #expect(sc.rekorLogURLs.map(\.url) == ["https://rekor.sigstore.dev"])

        // A repository without the target fails.
        let standard = TestTUFRepo.standard()
        let missing = SigstoreTUF.Options().withRoot(standard.files["1.root.json"]!).withRepositoryBaseURL(TestTUFRepo.baseURL)
            .withFetcher(MemoryFetcher(standard.files)).withDisableLocalCache()
        await #expect(throws: (any Error).self) { _ = try await fetchSigningConfigWithOptions(missing) }
    }
}
