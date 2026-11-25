// Port of sigstore-go pkg/root/timestamping_authority.go.

import Foundation
import SigstoreCommon
import X509

/// Mirrors `root.Timestamp`.
public struct Timestamp: Sendable, Hashable {
    public var time: Date
    public var uri: String

    public init(time: Date, uri: String) {
        self.time = time
        self.uri = uri
    }
}

/// Mirrors `root.TimestampingAuthority`.
///
/// `verify` is `async` because swift-certificates' path validator is async.
public protocol TimestampingAuthority: Sendable {
    func verify(signedTimestamp: Data, signature: Data) async throws -> Timestamp
}

/// Mirrors `root.SigstoreTimestampingAuthority`.
public struct SigstoreTimestampingAuthority: TimestampingAuthority {
    public var root: Certificate?
    public var intermediates: [Certificate]
    public var leaf: Certificate?
    public var validityPeriodStart: Date?
    public var validityPeriodEnd: Date?
    public var uri: String

    public init(
        root: Certificate? = nil,
        intermediates: [Certificate] = [],
        leaf: Certificate? = nil,
        validityPeriodStart: Date? = nil,
        validityPeriodEnd: Date? = nil,
        uri: String = ""
    ) {
        self.root = root
        self.intermediates = intermediates
        self.leaf = leaf
        self.validityPeriodStart = validityPeriodStart
        self.validityPeriodEnd = validityPeriodEnd
        self.uri = uri
    }

    public func verify(signedTimestamp: Data, signature: Data) async throws -> Timestamp {
        guard let root else {
            let display = uri.isEmpty ? "" : uri + " "
            throw SigstoreError("timestamping authority \(display)root certificate is nil")
        }
        let opts = TSAVerification.VerifyOpts(tsaCertificate: leaf, intermediates: intermediates, roots: [root])
        let timestamp = try await TSAVerification.verifyTimestampResponse(
            Array(signedTimestamp), artifact: Array(signature), opts: opts)

        if let start = validityPeriodStart, timestamp.time < start {
            throw SigstoreError("timestamp is before the validity period start")
        }
        if let end = validityPeriodEnd, timestamp.time > end {
            throw SigstoreError("timestamp is after the validity period end")
        }
        return Timestamp(time: timestamp.time, uri: uri)
    }
}
