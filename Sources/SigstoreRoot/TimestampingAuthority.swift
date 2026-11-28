// Port of sigstore-go pkg/root/timestamping_authority.go.

import Foundation
import SigstoreCommon
import X509

/// Mirrors `root.Timestamp`.
public struct Timestamp: Sendable, Hashable {
    /// The verified time asserted by the timestamping authority.
    public var time: Date
    /// URI of the timestamping authority that issued the timestamp.
    public var uri: String

    /// Creates a timestamp from a verified time and the issuer's URI.
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
    /// The trusted root certificate; ``verify(signedTimestamp:signature:)``
    /// throws when it is `nil`.
    public var root: Certificate?
    /// Intermediate certificates for building the signer's chain to `root`.
    public var intermediates: [Certificate]
    /// The expected TSA signing certificate, if pinned (passed to
    /// `TSAVerification` as `tsaCertificate`).
    public var leaf: Certificate?
    /// Start of the period this authority is trusted for; `nil` means
    /// unbounded. Timestamps before it are rejected.
    public var validityPeriodStart: Date?
    /// End of the period this authority is trusted for; `nil` means
    /// unbounded. Timestamps after it are rejected.
    public var validityPeriodEnd: Date?
    /// The authority's URI, copied into returned ``Timestamp`` values.
    public var uri: String

    /// Creates a timestamping authority from its certificates, optional
    /// validity period and URI.
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

    /// Mirrors sigstore-go `SigstoreTimestampingAuthority.Verify`: verifies an
    /// RFC 3161 timestamp over `signature` against this authority.
    ///
    /// - Parameters:
    ///   - signedTimestamp: A DER-encoded RFC 3161 TimeStampResp.
    ///   - signature: The bytes whose hash the timestamp's message imprint must
    ///     match (the bundle's signature).
    /// - Returns: The timestamp's time and this authority's `uri`.
    /// - Throws: If `root` is `nil`, the response fails
    ///   ``TSAVerification/verifyTimestampResponse(_:artifact:opts:)``, or its
    ///   time is outside the validity period.
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
