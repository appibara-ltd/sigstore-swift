// Port of sigstore-go pkg/root/timestamping_authority.go.
//
// RFC 3161 timestamp verification is NOT implemented yet (see PROGRESS.md).
// The types exist so trusted roots with TSAs parse, and so the verifier can
// report signed timestamps as unverified.

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
public protocol TimestampingAuthority: Sendable {
    func verify(signedTimestamp: Data, signature: Data) throws -> Timestamp
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

    public func verify(signedTimestamp: Data, signature: Data) throws -> Timestamp {
        throw SigstoreError("RFC 3161 timestamp verification is not implemented")
    }
}
