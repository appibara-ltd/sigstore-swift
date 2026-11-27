// Port of sigstore-go v1.4.1 pkg/root/signing_config.go.

import Foundation
import SigstoreCommon
import SigstoreProtobufSpecs
import SwiftProtobuf

/// Mirrors `SigningConfigMediaType02`.
public let signingConfigMediaType02 = "application/vnd.dev.sigstore.signingconfig.v0.2+json"

/// The TUF target holding the signing config (the name `GetSigningConfig`
/// requests).
public let defaultSigningConfigTarget = "signing_config.v0.2.json"

/// Go's zero `time.Time` (0001-01-01T00:00:00Z). `Service.ToServiceProtobuf`
/// always writes a start time, so an unset start is serialized as this.
private let goZeroTime = Date(timeIntervalSince1970: -62_135_596_800)

/// Mirrors `root.Service`. An unset validity bound (Go's zero `time.Time`)
/// is `nil`.
public struct Service: Sendable, Equatable, CustomStringConvertible {
    public var url: String
    public var majorAPIVersion: UInt32
    public var validityPeriodStart: Date?
    public var validityPeriodEnd: Date?
    public var `operator`: String

    public init(
        url: String,
        majorAPIVersion: UInt32,
        validityPeriodStart: Date? = nil,
        validityPeriodEnd: Date? = nil,
        operator: String = ""
    ) {
        self.url = url
        self.majorAPIVersion = majorAPIVersion
        self.validityPeriodStart = validityPeriodStart
        self.validityPeriodEnd = validityPeriodEnd
        self.operator = `operator`
    }

    /// Mirrors `NewService`.
    public init(protobuf s: Dev_Sigstore_Trustroot_V1_Service) {
        let validFor = s.validFor
        self.init(
            url: s.url,
            majorAPIVersion: s.majorApiVersion,
            validityPeriodStart: validFor.hasStart ? validFor.start.date : nil,
            validityPeriodEnd: validFor.hasEnd ? validFor.end.date : nil,
            operator: s.operator
        )
    }

    /// Mirrors `Service.ValidAtTime`: an unset bound does not restrict.
    public func validAtTime(_ t: Date) -> Bool {
        if let start = validityPeriodStart, t < start { return false }
        if let end = validityPeriodEnd, t > end { return false }
        return true
    }

    /// Mirrors `Service.ToServiceProtobuf`. As in Go, the start time is
    /// always set (Go's zero time when unset); the end time only when set.
    public func toServiceProtobuf() -> Dev_Sigstore_Trustroot_V1_Service {
        var tr = Dev_Sigstore_Common_V1_TimeRange()
        tr.start = Google_Protobuf_Timestamp(date: validityPeriodStart ?? goZeroTime)
        if let end = validityPeriodEnd {
            tr.end = Google_Protobuf_Timestamp(date: end)
        }
        var s = Dev_Sigstore_Trustroot_V1_Service()
        s.url = url
        s.majorApiVersion = majorAPIVersion
        s.validFor = tr
        s.operator = `operator`
        return s
    }

    /// Sort key: Go orders an unset start as its zero time.
    fileprivate var startKey: Date { validityPeriodStart ?? goZeroTime }

    public var description: String {
        let start = validityPeriodStart.map { "\($0)" } ?? "unset"
        let end = validityPeriodEnd.map { "\($0)" } ?? "unset"
        return "{\(url) v\(majorAPIVersion) \(start) \(end) \(`operator`)}"
    }
}

/// Mirrors `root.ServiceConfiguration`.
public struct ServiceConfiguration: Sendable, Equatable {
    public var selector: Dev_Sigstore_Trustroot_V1_ServiceSelector
    public var count: UInt32

    public init(selector: Dev_Sigstore_Trustroot_V1_ServiceSelector = .undefined, count: UInt32 = 0) {
        self.selector = selector
        self.count = count
    }

    /// Mirrors `ServiceConfiguration.ToConfigProtobuf`.
    public func toConfigProtobuf() -> Dev_Sigstore_Trustroot_V1_ServiceConfiguration {
        var c = Dev_Sigstore_Trustroot_V1_ServiceConfiguration()
        c.selector = selector
        c.count = count
        return c
    }

    init(protobuf c: Dev_Sigstore_Trustroot_V1_ServiceConfiguration) {
        self.init(selector: c.selector, count: c.count)
    }
}

// MARK: - Service selection

/// Go formats `[]uint32` with `%v` as `[1 2]`.
private func goFormat(_ versions: [UInt32]) -> String {
    "[" + versions.map(String.init).joined(separator: " ") + "]"
}

/// Services ordered from newest to oldest validity start, as Go's
/// `slices.SortFunc` + `slices.Reverse`. Ties keep Go's order for the slice
/// sizes signing configs have (pdqsort uses a stable insertion sort below 13
/// elements): ascending stable sort, then reversed.
private func newestFirst(_ services: [Service]) -> [Service] {
    services.enumerated()
        .sorted { ($0.element.startKey, $0.offset) < ($1.element.startKey, $1.offset) }
        .map(\.element)
        .reversed()
}

/// Mirrors `SelectService`: the newest service with the highest supported
/// API version that is valid at `currentTime`.
public func selectService(
    _ services: [Service], supportedAPIVersions: [UInt32], currentTime: Date
) throws -> Service {
    guard !supportedAPIVersions.isEmpty else {
        throw SigstoreError("no supported API versions")
    }
    let sortedServices = newestFirst(services)
    for version in supportedAPIVersions.sorted(by: >) {
        for s in sortedServices where s.majorAPIVersion == version && s.validAtTime(currentTime) {
            return s
        }
    }
    throw SigstoreError(
        "no matching service found for API versions \(goFormat(supportedAPIVersions)) and current time \(currentTime)"
    )
}

/// Mirrors `SelectServices`, using the system random number generator for
/// the `ANY` and `EXACT` selectors.
public func selectServices(
    _ services: [Service], config: ServiceConfiguration, supportedAPIVersions: [UInt32], currentTime: Date
) throws -> [Service] {
    var rng = SystemRandomNumberGenerator()
    return try selectServices(
        services, config: config, supportedAPIVersions: supportedAPIVersions, currentTime: currentTime, using: &rng
    )
}

/// Mirrors `SelectServices`: services of the highest supported API version
/// that has any service valid at `currentTime`, at most one (the newest) per
/// operator, then `ALL` of them, `ANY` one, or `EXACT` `count` distinct ones
/// chosen at random.
public func selectServices<G: RandomNumberGenerator>(
    _ services: [Service], config: ServiceConfiguration, supportedAPIVersions: [UInt32], currentTime: Date,
    using generator: inout G
) throws -> [Service] {
    guard !supportedAPIVersions.isEmpty else {
        throw SigstoreError("no supported API versions")
    }
    let sortedServices = newestFirst(services)

    var operators = Set<String>()
    var selected: [Service] = []
    for version in supportedAPIVersions.sorted(by: >) {
        for s in sortedServices where s.majorAPIVersion == version && s.validAtTime(currentTime) {
            // The newest service for a given operator.
            if operators.insert(s.operator).inserted {
                selected.append(s)
            }
        }
        if !selected.isEmpty { break }
    }
    guard !selected.isEmpty else {
        throw SigstoreError(
            "no matching services found for API versions \(goFormat(supportedAPIVersions)) and current time \(currentTime)"
        )
    }

    switch config.selector {
    case .all:
        return selected
    case .any:
        return [selected[Int.random(in: 0..<selected.count, using: &generator)]]
    case .exact:
        return try selectExact(selected, count: config.count, using: &generator)
    case .undefined, .UNRECOGNIZED:
        throw SigstoreError("invalid service selector")
    }
}

/// Mirrors `selectExact`: `count` distinct elements in random order.
func selectExact<T, G: RandomNumberGenerator>(_ slice: [T], count: UInt32, using generator: inout G) throws -> [T] {
    guard count > 0 else {
        throw SigstoreError("service selector count must be greater than 0")
    }
    guard Int(count) <= slice.count else {
        throw SigstoreError(
            "service selector count \(count) must be less than or equal to the slice length \(slice.count)"
        )
    }
    var remaining = slice
    var result: [T] = []
    for _ in 0..<count {
        let i = Int.random(in: 0..<remaining.count, using: &generator)
        result.append(remaining[i])
        remaining.swapAt(i, remaining.count - 1)
        remaining.removeLast()
    }
    return result
}

// MARK: - SigningConfig

/// Mirrors `root.SigningConfig`.
///
/// A value type: the `with…` / `add…` methods return a modified copy (Go
/// mutates the receiver and returns it). A missing `rekorTlogConfig` /
/// `tsaConfig` reads as an empty configuration (Go dereferences nil).
public struct SigningConfig: Sendable, CustomStringConvertible {
    public private(set) var protobuf: Dev_Sigstore_Trustroot_V1_SigningConfig

    /// Mirrors `NewSigningConfigFromProtobuf`.
    public init(protobuf: Dev_Sigstore_Trustroot_V1_SigningConfig) throws {
        guard protobuf.mediaType == signingConfigMediaType02 else {
            throw SigstoreError("unsupported SigningConfig media type: \(protobuf.mediaType)")
        }
        self.protobuf = protobuf
    }

    /// Mirrors `NewSigningConfigFromJSON`.
    public init(json: Data) throws {
        try self.init(protobuf: newSigningConfigProtobuf(json))
    }

    /// Mirrors `NewSigningConfigFromPath`.
    public init(path: String) throws {
        let data: Data
        do {
            data = try Data(contentsOf: URL(fileURLWithPath: path))
        } catch {
            throw SigstoreError("failed to read signing config", underlying: error)
        }
        try self.init(json: data)
    }

    /// Mirrors `NewSigningConfig`.
    public init(
        mediaType: String,
        fulcioCertificateAuthorities: [Service],
        oidcProviders: [Service],
        rekorLogs: [Service],
        rekorLogsConfig: ServiceConfiguration,
        timestampAuthorities: [Service],
        timestampAuthoritiesConfig: ServiceConfiguration
    ) throws {
        guard mediaType == signingConfigMediaType02 else {
            throw SigstoreError("unsupported SigningConfig media type, must be: \(signingConfigMediaType02)")
        }
        var sc = Dev_Sigstore_Trustroot_V1_SigningConfig()
        sc.mediaType = mediaType
        sc.caUrls = fulcioCertificateAuthorities.map { $0.toServiceProtobuf() }
        sc.oidcUrls = oidcProviders.map { $0.toServiceProtobuf() }
        sc.rekorTlogUrls = rekorLogs.map { $0.toServiceProtobuf() }
        sc.rekorTlogConfig = rekorLogsConfig.toConfigProtobuf()
        sc.tsaUrls = timestampAuthorities.map { $0.toServiceProtobuf() }
        sc.tsaConfig = timestampAuthoritiesConfig.toConfigProtobuf()
        self.protobuf = sc
    }

    // MARK: Accessors

    /// Mirrors `FulcioCertificateAuthorityURLs`.
    public var fulcioCertificateAuthorityURLs: [Service] { protobuf.caUrls.map(Service.init(protobuf:)) }

    /// Mirrors `OIDCProviderURLs`.
    public var oidcProviderURLs: [Service] { protobuf.oidcUrls.map(Service.init(protobuf:)) }

    /// Mirrors `RekorLogURLs`.
    public var rekorLogURLs: [Service] { protobuf.rekorTlogUrls.map(Service.init(protobuf:)) }

    /// Mirrors `RekorLogURLsConfig`.
    public var rekorLogURLsConfig: ServiceConfiguration { ServiceConfiguration(protobuf: protobuf.rekorTlogConfig) }

    /// Mirrors `TimestampAuthorityURLs`.
    public var timestampAuthorityURLs: [Service] { protobuf.tsaUrls.map(Service.init(protobuf:)) }

    /// Mirrors `TimestampAuthorityURLsConfig`.
    public var timestampAuthorityURLsConfig: ServiceConfiguration { ServiceConfiguration(protobuf: protobuf.tsaConfig) }

    // MARK: Builders

    /// Mirrors `WithFulcioCertificateAuthorityURLs`.
    public func withFulcioCertificateAuthorityURLs(_ services: Service...) -> SigningConfig {
        var copy = self
        copy.protobuf.caUrls = services.map { $0.toServiceProtobuf() }
        return copy
    }

    /// Mirrors `AddFulcioCertificateAuthorityURLs`.
    public func addFulcioCertificateAuthorityURLs(_ services: Service...) -> SigningConfig {
        var copy = self
        copy.protobuf.caUrls += services.map { $0.toServiceProtobuf() }
        return copy
    }

    /// Mirrors `WithOIDCProviderURLs`.
    public func withOIDCProviderURLs(_ services: Service...) -> SigningConfig {
        var copy = self
        copy.protobuf.oidcUrls = services.map { $0.toServiceProtobuf() }
        return copy
    }

    /// Mirrors `AddOIDCProviderURLs`.
    public func addOIDCProviderURLs(_ services: Service...) -> SigningConfig {
        var copy = self
        copy.protobuf.oidcUrls += services.map { $0.toServiceProtobuf() }
        return copy
    }

    /// Mirrors `WithRekorLogURLs`.
    public func withRekorLogURLs(_ services: Service...) -> SigningConfig {
        var copy = self
        copy.protobuf.rekorTlogUrls = services.map { $0.toServiceProtobuf() }
        return copy
    }

    /// Mirrors `AddRekorLogURLs`.
    public func addRekorLogURLs(_ services: Service...) -> SigningConfig {
        var copy = self
        copy.protobuf.rekorTlogUrls += services.map { $0.toServiceProtobuf() }
        return copy
    }

    /// Mirrors `WithRekorTlogConfig`.
    public func withRekorTlogConfig(selector: Dev_Sigstore_Trustroot_V1_ServiceSelector, count: UInt32) -> SigningConfig {
        var copy = self
        copy.protobuf.rekorTlogConfig.selector = selector
        copy.protobuf.rekorTlogConfig.count = count
        return copy
    }

    /// Mirrors `WithTimestampAuthorityURLs`.
    public func withTimestampAuthorityURLs(_ services: Service...) -> SigningConfig {
        var copy = self
        copy.protobuf.tsaUrls = services.map { $0.toServiceProtobuf() }
        return copy
    }

    /// Mirrors `AddTimestampAuthorityURLs`.
    public func addTimestampAuthorityURLs(_ services: Service...) -> SigningConfig {
        var copy = self
        copy.protobuf.tsaUrls += services.map { $0.toServiceProtobuf() }
        return copy
    }

    /// Mirrors `WithTsaConfig`.
    public func withTsaConfig(selector: Dev_Sigstore_Trustroot_V1_ServiceSelector, count: UInt32) -> SigningConfig {
        var copy = self
        copy.protobuf.tsaConfig.selector = selector
        copy.protobuf.tsaConfig.count = count
        return copy
    }

    // MARK: Encoding

    /// Mirrors `SigningConfig.MarshalJSON` (`protojson.Marshal`).
    public func marshalJSON() throws -> Data {
        try protobuf.jsonUTF8Data()
    }

    /// Mirrors `SigningConfig.String`.
    public var description: String {
        "{CA: \(fulcioCertificateAuthorityURLs), OIDC: \(oidcProviderURLs), RekorLogs: \(rekorLogURLs), "
            + "TSAs: \(timestampAuthorityURLs), MediaType: \(signingConfigMediaType02)}"
    }
}

/// Mirrors `NewSigningConfigProtobuf`: strict protojson (unknown fields and
/// duplicate keys rejected, as Go's `protojson.Unmarshal`).
public func newSigningConfigProtobuf(_ scJSON: Data) throws -> Dev_Sigstore_Trustroot_V1_SigningConfig {
    do {
        return try Dev_Sigstore_Trustroot_V1_SigningConfig(jsonUTF8Data: ProtoJSON.normalizeBytesFields(scJSON))
    } catch {
        throw SigstoreError("failed to proto-json unmarshal signing config", underlying: error)
    }
}
