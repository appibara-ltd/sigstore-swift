// Go protojson's base64 rules for `bytes` fields, applied before
// swift-protobuf decodes Sigstore JSON (bundles, trusted roots, Rekor v2
// bodies).
//
// google.golang.org/protobuf v1.36.12 encoding/protojson `unmarshalBytes`
// decodes with `base64.StdEncoding` (or `URLEncoding` when the string has
// `-` or `_`), without padding when the length is not a multiple of 4, and
// Go's base64 decoder skips `\r` and `\n`. swift-protobuf rejects escaped
// newlines but is laxer about padding and mixed alphabets, so each bytes
// field is decoded here with Go's rules and re-encoded canonically (or the
// input is rejected, as Go would).

import Foundation

public enum ProtoJSON {
    /// JSON names (and proto names) of the `bytes` fields reachable from
    /// `Bundle`, `TrustedRoot` and the Rekor v2 `Entry` (protobuf-specs
    /// a84bc5ff572a, rekor-tiles v2.4.2). No string field in those protos
    /// uses any of these names.
    public static let bytesFieldNames: Set<String> = [
        "rawBytes", "raw_bytes",
        "keyId", "key_id",
        "canonicalizedBody", "canonicalized_body",
        "signedEntryTimestamp", "signed_entry_timestamp",
        "rootHash", "root_hash",
        "hashes",
        "signedTimestamp", "signed_timestamp",
        "digest",
        "signature",
        "payload",
        "sig",
        "content",
    ]

    /// Re-encodes every string (or array of strings) under a `bytesFieldNames`
    /// key using Go protojson's base64 rules. Duplicate keys are rejected,
    /// as protojson does. Throws when Go would reject a value.
    public static func normalizeBytesFields(_ json: Data) throws -> Data {
        let value: JSONValue
        do {
            value = try JSONValue(parsing: json, rejectDuplicateKeys: true)
        } catch {
            throw SigstoreError("invalid JSON", underlying: error)
        }
        return try normalize(value, key: nil).serialized()
    }

    private static func normalize(_ value: JSONValue, key: String?) throws -> JSONValue {
        switch value {
        case .object(let o):
            var out: [String: JSONValue] = [:]
            for (k, v) in o { out[k] = try normalize(v, key: k) }
            return .object(out)
        case .array(let a):
            return .array(try a.map { try normalize($0, key: key) })
        case .string(let s):
            guard let key, bytesFieldNames.contains(key) else { return value }
            guard let decoded = Base64.decodeProtoJSON(s) else {
                throw SigstoreError("invalid value for bytes field \(key): \"\(s.prefix(32))…\"")
            }
            return .string(decoded.base64EncodedString())
        default:
            return value
        }
    }
}

extension Base64 {
    /// Go protojson `unmarshalBytes` + encoding/base64 decoding (non-strict:
    /// `\r`/`\n` skipped, trailing bits ignored).
    public static func decodeProtoJSON(_ s: String) -> Data? {
        let urlAlphabet = s.contains("-") || s.contains("_")
        let padded = s.utf8.count % 4 == 0
        var chars = Array(s.utf8.filter { $0 != 0x0A && $0 != 0x0D })
        if urlAlphabet {
            // URLEncoding has no '+' or '/'.
            guard !chars.contains(UInt8(ascii: "+")), !chars.contains(UInt8(ascii: "/")) else { return nil }
            chars = chars.map {
                $0 == UInt8(ascii: "-") ? UInt8(ascii: "+") : $0 == UInt8(ascii: "_") ? UInt8(ascii: "/") : $0
            }
        }
        if padded {
            guard chars.count % 4 == 0 else { return nil }
        } else {
            // NoPadding: '=' is not in the alphabet; a lone trailing digit is invalid.
            guard !chars.contains(UInt8(ascii: "=")), chars.count % 4 != 1 else { return nil }
            chars += Array(repeating: UInt8(ascii: "="), count: (4 - chars.count % 4) % 4)
        }
        return Data(base64Encoded: Data(chars))
    }
}
