// in-toto Statement v1 (github.com/in-toto/attestation v1.2.0, generated as
// `InTotoAttestation_V1_Statement`) and sigstore-go pkg/verify/statement.go.

import Foundation
import SigstoreCommon
import SigstoreProtobufSpecs
import SwiftProtobuf

public let intotoMediaType = "application/vnd.in-toto+json"

/// Mirrors in-toto `v1.ResourceDescriptor`.
public struct ResourceDescriptor: Sendable, Hashable {
    public var name: String
    public var uri: String
    /// Algorithm name → lowercase hex digest.
    public var digest: [String: String]
    public var content: Data
    public var downloadLocation: String
    public var mediaType: String
    public var annotations: Google_Protobuf_Struct?

    public init(
        name: String = "", uri: String = "", digest: [String: String] = [:], content: Data = Data(),
        downloadLocation: String = "", mediaType: String = "", annotations: Google_Protobuf_Struct? = nil
    ) {
        self.name = name
        self.uri = uri
        self.digest = digest
        self.content = content
        self.downloadLocation = downloadLocation
        self.mediaType = mediaType
        self.annotations = annotations
    }

    init(_ pb: InTotoAttestation_V1_ResourceDescriptor) {
        self.init(
            name: pb.name, uri: pb.uri, digest: pb.digest, content: pb.content,
            downloadLocation: pb.downloadLocation, mediaType: pb.mediaType,
            annotations: pb.hasAnnotations ? pb.annotations : nil)
    }

    var protobuf: InTotoAttestation_V1_ResourceDescriptor {
        var pb = InTotoAttestation_V1_ResourceDescriptor()
        pb.name = name
        pb.uri = uri
        pb.digest = digest
        pb.content = content
        pb.downloadLocation = downloadLocation
        pb.mediaType = mediaType
        if let annotations { pb.annotations = annotations }
        return pb
    }
}

/// Mirrors in-toto `v1.Statement` (Go `*in_toto.Statement`). `predicate` is
/// nil when the verifier was configured with `.withoutStatementPredicate()`.
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

    public init(protobuf pb: InTotoAttestation_V1_Statement) {
        self.init(
            type: pb.type, subject: pb.subject.map(ResourceDescriptor.init), predicateType: pb.predicateType,
            predicate: pb.hasPredicate ? pb.predicate : nil)
    }

    /// The statement as the in-toto protobuf.
    public var protobuf: InTotoAttestation_V1_Statement {
        var pb = InTotoAttestation_V1_Statement()
        pb.type = type
        pb.subject = subject.map(\.protobuf)
        pb.predicateType = predicateType
        if let predicate { pb.predicate = predicate }
        return pb
    }

    /// Parses an in-toto statement with protojson, as Go's
    /// `protojson.Unmarshal` into `in_toto.Statement`: unknown or duplicate
    /// fields are errors and bytes fields use Go's base64 rules.
    public init(json: Data) throws {
        let pb = try InTotoAttestation_V1_Statement(jsonUTF8Data: ProtoJSON.normalizeBytesFields(json))
        self.init(protobuf: pb)
    }

    /// Go protojson output of the statement (`protojson.Marshal`).
    public func jsonData() throws -> Data { try protobuf.jsonUTF8Data() }

    /// Mirrors the "lite" decode in sigstore-go `summarizeStatement`: Go
    /// `encoding/json` into {_type, predicateType, subject[{name, digest}]},
    /// ignoring every other field (and the predicate).
    static func lite(json: Data) throws -> Statement {
        let value: JSONValue
        do {
            value = try JSONValue(parsing: json)
        } catch {
            throw SigstoreError("parsing in-toto statement", underlying: error)
        }
        guard case .object(let obj) = value else {
            if value == .null { return Statement(type: "", subject: [], predicateType: "") }
            throw SigstoreError("parsing in-toto statement: not a JSON object")
        }
        func string(_ v: JSONValue?, _ field: String) throws -> String {
            switch v {
            case nil, .null?: return ""
            case .string(let s)?: return s
            default: throw SigstoreError("parsing in-toto statement: \(field) is not a string")
            }
        }
        var subjects: [ResourceDescriptor] = []
        switch goField(obj, "subject") {
        case nil, .null?: break
        case .array(let list)?:
            for item in list {
                guard case .object(let s) = item else {
                    if item == .null { subjects.append(ResourceDescriptor()); continue }
                    throw SigstoreError("parsing in-toto statement: subject entry is not an object")
                }
                var digest: [String: String] = [:]
                switch goField(s, "digest") {
                case nil, .null?: break
                case .object(let d)?:
                    for (k, v) in d {
                        guard case .string(let hex) = v else {
                            throw SigstoreError("parsing in-toto statement: digest value is not a string")
                        }
                        digest[k] = hex
                    }
                default: throw SigstoreError("parsing in-toto statement: digest is not an object")
                }
                subjects.append(ResourceDescriptor(name: try string(goField(s, "name"), "name"), digest: digest))
            }
        default:
            throw SigstoreError("parsing in-toto statement: subject is not a list")
        }
        return Statement(
            type: try string(goField(obj, "_type"), "_type"), subject: subjects,
            predicateType: try string(goField(obj, "predicateType"), "predicateType"))
    }
}

/// Go `encoding/json` field lookup: an exact key match, else a
/// case-insensitive one.
private func goField(_ obj: [String: JSONValue], _ name: String) -> JSONValue? {
    if let v = obj[name] { return v }
    let lower = name.lowercased()
    return obj.first { $0.key.lowercased() == lower }?.value
}

/// Mirrors `summarizeStatement`: type, subject names/digests and predicate
/// type only, decoded leniently.
func summarizeStatement(_ envelope: any EnvelopeContent) throws -> Statement {
    let raw = envelope.rawEnvelope
    guard raw.payloadType == intotoMediaType else {
        throw SigstoreError("unsupported DSSE payload type: \(raw.payloadType)")
    }
    return try Statement.lite(json: raw.payload)
}
