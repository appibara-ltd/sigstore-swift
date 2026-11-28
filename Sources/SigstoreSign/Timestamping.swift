// Port of sigstore-go v1.4.1 pkg/sign/timestamping.go, with the request
// encoding of digitorus/timestamp `Request.Marshal`.

import Crypto
import Foundation
import SigstoreCommon
import SigstoreRoot
import SwiftASN1

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Mirrors `sign.TimestampAuthorityAPIVersions`.
public let timestampAuthorityAPIVersions: [UInt32] = [1]

/// Mirrors `sign.TimestampAuthorityOptions`.
public struct TimestampAuthorityOptions: Sendable {
    /// Full URL (with path) of the timestamp authority endpoint.
    public var url: String
    /// Timeout in seconds for the whole request, retries included: zero
    /// means 30 s, a negative value no timeout.
    public var timeout: TimeInterval
    /// Retries on transient failures (transport errors, HTTP 429, HTTP 5xx
    /// other than 501); zero disables retrying.
    public var retries: UInt
    /// Optional base transport, wrapped by the retrying transport; defaults
    /// to ``URLSessionTransport``.
    public var transport: (any HTTPTransport)?
    /// Optional User-Agent prefix; "sigstore-swift" is always appended.
    public var userAgent: String

    /// Creates options for the authority at `url`.
    public init(
        url: String, timeout: TimeInterval = 0, retries: UInt = 0, transport: (any HTTPTransport)? = nil,
        userAgent: String = ""
    ) {
        self.url = url
        self.timeout = timeout
        self.retries = retries
        self.transport = transport
        self.userAgent = userAgent
    }
}

/// Mirrors `sign.TimestampAuthority`: an RFC 3161 timestamp authority
/// client.
public struct TimestampAuthority: Sendable {
    /// The options the client was created with.
    public let options: TimestampAuthorityOptions
    private let transport: HTTPRetryTransport

    /// Mirrors `NewTimestampAuthority`.
    public init(options: TimestampAuthorityOptions) {
        self.options = options
        self.transport = HTTPRetryTransport(
            base: options.transport, maxRetries: Int(clamping: options.retries))
    }

    /// Mirrors `TimestampAuthority.GetTimestamp`: requests a timestamp over
    /// the SHA-256 digest of `signature` and returns the DER
    /// TimeStampResp.
    ///
    /// The response is parsed (and, when it embeds certificates, its CMS
    /// signature checked) but not verified against trusted material.
    ///
    /// - Throws: For an invalid URL, a transport error, a status other
    ///   than 200 or 201, a body over 1 MiB, or a response that does not
    ///   parse or reports a failure status.
    public func timestamp(signature: Data) async throws -> Data {
        guard let url = URL(string: options.url) else {
            throw SigstoreError("invalid timestamp authority URL: \(options.url)")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = Data(try timestampRequest(digest: Array(SHA256.hash(data: signature))))
        request.setValue("application/timestamp-query", forHTTPHeaderField: "Content-Type")
        request.setValue(userAgent(options.userAgent), forHTTPHeaderField: "User-Agent")

        let transport = self.transport
        let finalRequest = request
        let (body, response) = try await withDeadline(effectiveTimeout(options.timeout)) {
            try await transport.roundTrip(finalRequest)
        }
        // Go reads at most 1 MiB (io.LimitReader), so a longer response
        // cannot parse there either.
        guard body.count <= 1 << 20 else {
            throw SigstoreError("timestamp authority response larger than 1 MiB")
        }
        guard response.statusCode == 200 || response.statusCode == 201 else {
            let text = String(bytes: body, encoding: .utf8) ?? "<\(body.count) bytes>"
            throw SigstoreError("timestamp authority returned \(response.statusCode): \(text)")
        }
        _ = try RFC3161Timestamp.parseResponse(Array(body))
        return body
    }
}

/// Mirrors digitorus `Request.Marshal` for a SHA-256 imprint, no policy,
/// nonce or extensions, and `certReq` false (omitted as the DEFAULT):
///
///     TimeStampReq ::= SEQUENCE {
///       version INTEGER { v1(1) },
///       messageImprint MessageImprint, ... }
///     MessageImprint ::= SEQUENCE {
///       hashAlgorithm AlgorithmIdentifier, hashedMessage OCTET STRING }
func timestampRequest(digest: [UInt8]) throws -> [UInt8] {
    let sha256: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    var serializer = DER.Serializer()
    try serializer.appendConstructedNode(identifier: .sequence) { s in
        try s.serialize(1)
        try s.appendConstructedNode(identifier: .sequence) { s in
            try s.appendConstructedNode(identifier: .sequence) { s in
                try s.serialize(sha256)
                try s.serialize(ASN1Null())
            }
            try s.serialize(ASN1OctetString(contentBytes: ArraySlice(digest)))
        }
    }
    return serializer.serializedBytes
}
