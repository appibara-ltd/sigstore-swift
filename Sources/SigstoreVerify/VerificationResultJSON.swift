// JSON encoding of verification results, mirroring sigstore-go v1.4.1:
// `VerificationResult.MarshalJSON` / `UnmarshalJSON` (statement as
// protojson), the struct tags of `SignatureVerificationResult`,
// `TimestampVerificationResult`, `CertificateIdentity` (with the custom
// `SubjectAlternativeNameMatcher` / `IssuerMatcher` marshalers) and
// fulcio/certificate `Summary` / `Extensions` (embedded, `omitempty`).
//
// Keys are emitted sorted (Go emits struct order); values are identical.

import Foundation
import SigstoreCommon
import SigstoreFulcio
import SigstoreProtobufSpecs
import SwiftProtobuf

extension VerificationResult {
    /// Mirrors `VerificationResult.MarshalJSON`. A missing statement encodes
    /// as `{}` and no verified timestamps as `null`, as Go does.
    public func jsonData() throws -> Data { try jsonValue().serialized() }

    func jsonValue() throws -> JSONValue {
        var o: [String: JSONValue] = ["mediaType": .string(mediaType)]
        // protojson.Marshal(nil) is "{}", which `omitempty` does not drop.
        o["statement"] = try statement.map { try JSONValue(parsing: $0.jsonData()) } ?? .object([:])
        if let signature { o["signature"] = signature.jsonValue }
        o["verifiedTimestamps"] = verifiedTimestamps.isEmpty ? .null : .array(verifiedTimestamps.map(\.jsonValue))
        if let verifiedIdentity { o["verifiedIdentity"] = verifiedIdentity.jsonValue }
        return .object(o)
    }

    /// Mirrors `VerificationResult.UnmarshalJSON`.
    public init(json: Data) throws {
        let value = try JSONValue(parsing: json)
        guard case .object(let o) = value else { throw SigstoreError("verification result is not a JSON object") }
        self.init()
        mediaType = try o.string("mediaType")
        if let s = o["statement"], s != .null {
            statement = Statement(protobuf: try InTotoAttestation_V1_Statement(jsonUTF8Data: s.serialized()))
        }
        if let s = o["signature"], s != .null { signature = try SignatureVerificationResult(jsonValue: s) }
        if case .array(let a)? = o["verifiedTimestamps"] {
            verifiedTimestamps = try a.map(TimestampVerificationResult.init(jsonValue:))
        }
        if let i = o["verifiedIdentity"], i != .null { verifiedIdentity = try CertificateIdentity(jsonValue: i) }
    }
}

extension SignatureVerificationResult {
    var jsonValue: JSONValue {
        var o: [String: JSONValue] = [:]
        if let publicKeyID { o["publicKeyId"] = .string(publicKeyID.base64EncodedString()) }  // []byte → base64
        if let certificate { o["certificate"] = .object(certificate.jsonObject) }
        return .object(o)
    }

    init(jsonValue: JSONValue) throws {
        guard case .object(let o) = jsonValue else { throw SigstoreError("signature is not a JSON object") }
        self.init()
        if case .string(let s)? = o["publicKeyId"] {
            guard let d = Data(base64Encoded: s) else { throw SigstoreError("publicKeyId is not base64") }
            publicKeyID = d
        }
        if let c = o["certificate"], c != .null { certificate = try Summary(jsonObject: c) }
    }
}

extension TimestampVerificationResult {
    var jsonValue: JSONValue {
        .object(["type": .string(type), "uri": .string(uri), "timestamp": .string(formatRFC3339Nano(timestamp))])
    }

    init(jsonValue: JSONValue) throws {
        guard case .object(let o) = jsonValue else { throw SigstoreError("timestamp is not a JSON object") }
        guard let date = parseGoTime(try o.string("timestamp")) else {
            throw SigstoreError("timestamp is not an RFC 3339 time")
        }
        self.init(type: try o.string("type"), uri: try o.string("uri"), timestamp: date)
    }
}

extension CertificateIdentity {
    var jsonValue: JSONValue {
        var o = extensions.jsonObject  // embedded certificate.Extensions
        var san: [String: JSONValue] = ["subjectAlternativeName": .string(subjectAlternativeName.subjectAlternativeName)]
        if !subjectAlternativeName.regexp.source.isEmpty { san["regexp"] = .string(subjectAlternativeName.regexp.source) }
        var iss: [String: JSONValue] = ["issuer": .string(issuer.issuer)]
        if !issuer.regexp.source.isEmpty { iss["regexp"] = .string(issuer.regexp.source) }
        o["subjectAlternativeName"] = .object(san)
        o["issuer"] = .object(iss)
        return .object(o)
    }

    /// Go's default decoding (no validation, unlike `NewCertificateIdentity`).
    init(jsonValue: JSONValue) throws {
        guard case .object(let o) = jsonValue else { throw SigstoreError("identity is not a JSON object") }
        let san = o["subjectAlternativeName"]?.objectValue ?? [:]
        let iss = o["issuer"]?.objectValue ?? [:]
        self.init(
            unchecked: try SubjectAlternativeNameMatcher(san.string("subjectAlternativeName"), regexp: san.string("regexp")),
            issuer: try IssuerMatcher(iss.string("issuer"), regexp: iss.string("regexp")),
            // Go: the identity's own `issuer` field shadows the embedded
            // `Extensions.Issuer` (shallower field wins), so it is skipped.
            extensions: try Extensions(jsonObject: jsonValue, skipping: ["issuer"]))
    }
}

extension Summary {
    /// `certificateIssuer` and `subjectAlternativeName` plus the embedded
    /// extensions (`omitempty`).
    public var jsonObject: [String: JSONValue] {
        var o = extensions.jsonObject
        o["certificateIssuer"] = .string(certificateIssuer)
        o["subjectAlternativeName"] = .string(subjectAlternativeName)
        return o
    }

    public init(jsonObject value: JSONValue) throws {
        guard case .object(let o) = value else { throw SigstoreError("certificate summary is not a JSON object") }
        self.init(
            certificateIssuer: try o.string("certificateIssuer"),
            subjectAlternativeName: try o.string("subjectAlternativeName"),
            extensions: try Extensions(jsonObject: value))
    }
}

extension Extensions {
    /// Go JSON keys (struct tags) of `certificate.Extensions`, all `omitempty`.
    nonisolated(unsafe) static let jsonFields: [(String, WritableKeyPath<Extensions, String>)] = [
        ("issuer", \.issuer), ("githubWorkflowTrigger", \.githubWorkflowTrigger),
        ("githubWorkflowSHA", \.githubWorkflowSHA), ("githubWorkflowName", \.githubWorkflowName),
        ("githubWorkflowRepository", \.githubWorkflowRepository), ("githubWorkflowRef", \.githubWorkflowRef),
        ("buildSignerURI", \.buildSignerURI), ("buildSignerDigest", \.buildSignerDigest),
        ("runnerEnvironment", \.runnerEnvironment), ("sourceRepositoryURI", \.sourceRepositoryURI),
        ("sourceRepositoryDigest", \.sourceRepositoryDigest), ("sourceRepositoryRef", \.sourceRepositoryRef),
        ("sourceRepositoryIdentifier", \.sourceRepositoryIdentifier),
        ("sourceRepositoryOwnerURI", \.sourceRepositoryOwnerURI),
        ("sourceRepositoryOwnerIdentifier", \.sourceRepositoryOwnerIdentifier),
        ("buildConfigURI", \.buildConfigURI), ("buildConfigDigest", \.buildConfigDigest),
        ("buildTrigger", \.buildTrigger), ("runInvocationURI", \.runInvocationURI),
        ("sourceRepositoryVisibilityAtSigning", \.sourceRepositoryVisibilityAtSigning),
    ]

    public var jsonObject: [String: JSONValue] {
        var o: [String: JSONValue] = [:]
        for (key, path) in Self.jsonFields where !self[keyPath: path].isEmpty { o[key] = .string(self[keyPath: path]) }
        return o
    }

    public init(jsonObject value: JSONValue) throws {
        try self.init(jsonObject: value, skipping: [])
    }

    init(jsonObject value: JSONValue, skipping: Set<String>) throws {
        guard case .object(let o) = value else { throw SigstoreError("extensions are not a JSON object") }
        self.init()
        for (key, path) in Self.jsonFields where !skipping.contains(key) { self[keyPath: path] = try o.string(key) }
    }
}

extension Dictionary where Key == String, Value == JSONValue {
    /// Go `encoding/json` into a string field: missing/null → "".
    fileprivate func string(_ key: String) throws -> String {
        switch self[key] {
        case nil, .null?: return ""
        case .string(let s)?: return s
        default: throw SigstoreError("\(key) is not a string")
        }
    }
}

/// Go `time.Time.MarshalJSON` (RFC 3339 with nanoseconds, trailing zeros
/// trimmed), in UTC.
func formatRFC3339Nano(_ date: Date) -> String {
    let seconds = date.timeIntervalSince1970.rounded(.down)
    var nanos = Int(((date.timeIntervalSince1970 - seconds) * 1e9).rounded())
    var whole = Date(timeIntervalSince1970: seconds)
    if nanos >= 1_000_000_000 {
        nanos -= 1_000_000_000
        whole = whole.addingTimeInterval(1)
    }
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    var s = f.string(from: whole)  // ...Z
    if nanos > 0 {
        var frac = String(format: "%09d", nanos)
        while frac.hasSuffix("0") { frac.removeLast() }
        s.removeLast()
        s += ".\(frac)Z"
    }
    return s
}

/// Go `time.Time.UnmarshalJSON` (RFC 3339, optional fractional seconds).
func parseGoTime(_ s: String) -> Date? {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    if let d = f.date(from: s) { return d }
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f.date(from: s)
}
