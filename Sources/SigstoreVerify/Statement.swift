// in-toto Statement v1 (github.com/in-toto/attestation/go/v1) and
// sigstore-go pkg/verify/statement.go.

import Foundation
import SigstoreCommon
import SwiftProtobuf

public let intotoMediaType = "application/vnd.in-toto+json"

/// Mirrors in-toto `v1.ResourceDescriptor`.
public struct ResourceDescriptor: Sendable, Hashable {
    public var name: String
    public var uri: String
    /// Algorithm name → lowercase hex digest.
    public var digest: [String: String]
    public var downloadLocation: String
    public var mediaType: String

    public init(
        name: String = "", uri: String = "", digest: [String: String] = [:],
        downloadLocation: String = "", mediaType: String = ""
    ) {
        self.name = name
        self.uri = uri
        self.digest = digest
        self.downloadLocation = downloadLocation
        self.mediaType = mediaType
    }
}

/// Mirrors in-toto `v1.Statement`. `predicate` is nil when the verifier was
/// configured with `.withoutStatementPredicate()`.
public struct Statement: Sendable {
    public var type: String
    public var subject: [ResourceDescriptor]
    public var predicateType: String
    public var predicate: Google_Protobuf_Struct?

    public init(
        type: String, subject: [ResourceDescriptor], predicateType: String,
        predicate: Google_Protobuf_Struct? = nil
    ) {
        self.type = type
        self.subject = subject
        self.predicateType = predicateType
        self.predicate = predicate
    }

    /// Parses an in-toto statement from JSON, including the predicate.
    public init(json: Data) throws {
        try self.init(json: json, includePredicate: true)
    }

    init(json: Data, includePredicate: Bool) throws {
        guard let obj = try JSONSerialization.jsonObject(with: json) as? [String: Any] else {
            throw SigstoreError("in-toto statement is not a JSON object")
        }
        func string(_ any: Any?, _ field: String) throws -> String {
            guard let any else { return "" }
            guard let s = any as? String else { throw SigstoreError("in-toto statement: \(field) is not a string") }
            return s
        }
        type = try string(obj["_type"], "_type")
        predicateType = try string(obj["predicateType"], "predicateType")
        var subjects: [ResourceDescriptor] = []
        if let raw = obj["subject"] {
            guard let list = raw as? [Any] else { throw SigstoreError("in-toto statement: subject is not a list") }
            for item in list {
                guard let s = item as? [String: Any] else {
                    throw SigstoreError("in-toto statement: subject entry is not an object")
                }
                var digest: [String: String] = [:]
                if let d = s["digest"] {
                    guard let dict = d as? [String: Any] else {
                        throw SigstoreError("in-toto statement: digest is not an object")
                    }
                    for (k, v) in dict {
                        guard let hex = v as? String else {
                            throw SigstoreError("in-toto statement: digest value is not a string")
                        }
                        digest[k] = hex
                    }
                }
                subjects.append(
                    ResourceDescriptor(
                        name: try string(s["name"], "name"),
                        uri: try string(s["uri"], "uri"),
                        digest: digest,
                        downloadLocation: try string(s["downloadLocation"], "downloadLocation"),
                        mediaType: try string(s["mediaType"], "mediaType")
                    ))
            }
        }
        subject = subjects
        if includePredicate, let p = obj["predicate"] {
            guard p is [String: Any] else { throw SigstoreError("in-toto statement: predicate is not an object") }
            let data = try JSONSerialization.data(withJSONObject: p)
            predicate = try Google_Protobuf_Struct(jsonUTF8Data: data)
        } else {
            predicate = nil
        }
    }
}

/// Mirrors `summarizeStatement`: type, subjects and predicate type only.
func summarizeStatement(_ envelope: any EnvelopeContent) throws -> Statement {
    let raw = envelope.rawEnvelope
    guard raw.payloadType == intotoMediaType else {
        throw SigstoreError("unsupported DSSE payload type: \(raw.payloadType)")
    }
    do {
        return try Statement(json: raw.payload, includePredicate: false)
    } catch {
        throw SigstoreError("parsing in-toto statement", underlying: error)
    }
}
