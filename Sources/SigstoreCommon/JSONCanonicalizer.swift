// RFC 8785 JSON Canonicalization Scheme (JCS), for the JSON shapes Sigstore
// canonicalizes (protojson output: objects, arrays, strings, booleans, null
// and integers). Stands in for github.com/cyberphone/json-canonicalization
// `jsoncanonicalizer.Transform`. Non-integer numbers are rejected rather
// than formatted (RFC 8785 §3.2.2.3 ECMAScript number serialization is not
// implemented).

import Foundation

/// RFC 8785 JSON canonicalization for the JSON shapes Sigstore
/// canonicalizes; non-integer numbers are rejected.
public enum JSONCanonicalizer {
    /// Mirrors `jsoncanonicalizer.Transform`.
    public static func transform(_ json: Data) throws -> Data {
        let object: Any
        do {
            object = try JSONSerialization.jsonObject(with: json, options: [.fragmentsAllowed])
        } catch {
            throw SigstoreError("invalid JSON", underlying: error)
        }
        var out = ""
        try serialize(object, into: &out)
        return Data(out.utf8)
    }

    private static func serialize(_ value: Any, into out: inout String) throws {
        switch value {
        case let dict as [String: Any]:
            out += "{"
            // RFC 8785 §3.2.3: sort by UTF-16 code units.
            let keys = dict.keys.sorted { $0.utf16.lexicographicallyPrecedes($1.utf16) }
            for (i, key) in keys.enumerated() {
                if i > 0 { out += "," }
                serializeString(key, into: &out)
                out += ":"
                try serialize(dict[key]!, into: &out)
            }
            out += "}"
        case let array as [Any]:
            out += "["
            for (i, element) in array.enumerated() {
                if i > 0 { out += "," }
                try serialize(element, into: &out)
            }
            out += "]"
        case let string as String:
            serializeString(string, into: &out)
        case is NSNull:
            out += "null"
        case let number as NSNumber:
            if isBoolean(number) {
                out += number.boolValue ? "true" : "false"
            } else if let i = Int64(exactly: number.doubleValue), Double(i) == number.doubleValue,
                abs(number.doubleValue) < 9_007_199_254_740_992
            {
                out += String(i)
            } else {
                throw SigstoreError("JCS: non-integer numbers are not supported")
            }
        default:
            throw SigstoreError("JCS: unsupported JSON value")
        }
    }

    /// JSONSerialization returns booleans as NSNumbers whose ObjC type is
    /// `c` (char); JSON numbers decode as `q` (Int64) or `d` (Double).
    private static func isBoolean(_ number: NSNumber) -> Bool {
        String(cString: number.objCType) == "c"
    }

    /// RFC 8785 §3.2.2.2: escape `"`, `\` and control characters only;
    /// short escapes where JSON has them, otherwise lowercase `\u00xx`.
    private static func serializeString(_ s: String, into out: inout String) {
        out += "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{0C}": out += "\\f"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case _ where scalar.value < 0x20:
                out += String(format: "\\u%04x", scalar.value)
            default:
                out.unicodeScalars.append(scalar)
            }
        }
        out += "\""
    }
}
