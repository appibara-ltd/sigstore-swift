// JSON values with exact number text, plain serialization, and OLPC
// canonical JSON.
//
// TUF signatures cover the canonical JSON of the `signed` object. go-tuf
// computes it as secure-systems-lab/go-securesystemslib v0.11.1
// `cjson.EncodeCanonical` over its re-marshalled metadata; we canonicalize
// the received `signed` value directly (see PROGRESS.md → Decisions).
// Numbers are kept as their literal text, as `json.Decoder.UseNumber` does.

import Foundation

/// A parsed JSON value.
public indirect enum JSONValue: Sendable, Equatable {
    case object([String: JSONValue])
    case array([JSONValue])
    case string(String)
    /// The literal number text.
    case number(String)
    case bool(Bool)
    case null

    /// Parses `data` (RFC 8259). Duplicate object keys: last wins, as Go's
    /// encoding/json; with `rejectDuplicateKeys` they are an error, as Go's
    /// protojson ("duplicate field").
    public init(parsing data: Data, rejectDuplicateKeys: Bool = false) throws {
        var parser = JSONParser(bytes: Array(data))
        parser.rejectDuplicateKeys = rejectDuplicateKeys
        parser.skipWhitespace()
        self = try parser.parseValue(depth: 0)
        parser.skipWhitespace()
        guard parser.index == parser.bytes.count else { throw SigstoreError("invalid JSON: trailing data") }
    }

    /// The member named `key` if this is an object; otherwise `nil`.
    public subscript(key: String) -> JSONValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }

    /// The members if this is an object; otherwise `nil`.
    public var objectValue: [String: JSONValue]? { if case .object(let o) = self { return o } else { return nil } }
    /// The elements if this is an array; otherwise `nil`.
    public var arrayValue: [JSONValue]? { if case .array(let a) = self { return a } else { return nil } }
    /// The string if this is a string; otherwise `nil`.
    public var stringValue: String? { if case .string(let s) = self { return s } else { return nil } }
    /// The boolean if this is a boolean; otherwise `nil`.
    public var boolValue: Bool? { if case .bool(let b) = self { return b } else { return nil } }

    /// The value as an Int64 if it is a JSON number Go's `json.Number.Int64`
    /// accepts (decimal integer text within range).
    public var int64Value: Int64? {
        guard case .number(let text) = self else { return nil }
        return Int64(text)
    }

    /// Plain JSON text: keys sorted, strings escaping `"`, `\` and control
    /// characters only, numbers as their original text.
    public func serialized() -> Data {
        var out: [UInt8] = []
        serialize(into: &out)
        return Data(out)
    }

    private func serialize(into out: inout [UInt8]) {
        switch self {
        case .object(let o):
            out.append(UInt8(ascii: "{"))
            for (i, k) in o.keys.sorted().enumerated() {
                if i > 0 { out.append(UInt8(ascii: ",")) }
                JSONValue.string(k).serialize(into: &out)
                out.append(UInt8(ascii: ":"))
                o[k]!.serialize(into: &out)
            }
            out.append(UInt8(ascii: "}"))
        case .array(let a):
            out.append(UInt8(ascii: "["))
            for (i, v) in a.enumerated() {
                if i > 0 { out.append(UInt8(ascii: ",")) }
                v.serialize(into: &out)
            }
            out.append(UInt8(ascii: "]"))
        case .string(let s):
            out.append(UInt8(ascii: "\""))
            for u in s.unicodeScalars {
                switch u {
                case "\"": out += Array("\\\"".utf8)
                case "\\": out += Array("\\\\".utf8)
                case _ where u.value < 0x20:
                    let hex = String(u.value, radix: 16)
                    out += Array(("\\u" + String(repeating: "0", count: 4 - hex.count) + hex).utf8)
                default: out += Array(String(u).utf8)
                }
            }
            out.append(UInt8(ascii: "\""))
        case .number(let n): out += Array(n.utf8)
        case .bool(let b): out += Array((b ? "true" : "false").utf8)
        case .null: out += Array("null".utf8)
        }
    }

    /// OLPC canonical JSON (securesystemslib `EncodeCanonical`): keys sorted
    /// bytewise, no whitespace, strings escape only `\` and `"`, numbers must
    /// be integers.
    public func canonicalBytes() throws -> [UInt8] {
        var out: [UInt8] = []
        try encodeCanonical(into: &out)
        return out
    }

    private func encodeCanonical(into out: inout [UInt8]) throws {
        switch self {
        case .string(let s):
            Self.encodeCanonicalString(s, into: &out)
        case .bool(let b):
            out += Array((b ? "true" : "false").utf8)
        case .number(let text):
            guard Int64(text) != nil else {
                throw SigstoreError("Can't canonicalize floating point number '\(text)'")
            }
            out += Array(text.utf8)
        case .null:
            out += Array("null".utf8)
        case .array(let a):
            out.append(UInt8(ascii: "["))
            for (i, v) in a.enumerated() {
                if i > 0 { out.append(UInt8(ascii: ",")) }
                try v.encodeCanonical(into: &out)
            }
            out.append(UInt8(ascii: "]"))
        case .object(let o):
            out.append(UInt8(ascii: "{"))
            // sort.Strings: bytewise (UTF-8) order.
            let keys = o.keys.sorted { Array($0.utf8).lexicographicallyPrecedes(Array($1.utf8)) }
            for (i, k) in keys.enumerated() {
                if i > 0 { out.append(UInt8(ascii: ",")) }
                Self.encodeCanonicalString(k, into: &out)
                out.append(UInt8(ascii: ":"))
                try o[k]!.encodeCanonical(into: &out)
            }
            out.append(UInt8(ascii: "}"))
        }
    }

    private static func encodeCanonicalString(_ s: String, into out: inout [UInt8]) {
        out.append(UInt8(ascii: "\""))
        for b in s.utf8 {
            if b == UInt8(ascii: "\\") || b == UInt8(ascii: "\"") { out.append(UInt8(ascii: "\\")) }
            out.append(b)
        }
        out.append(UInt8(ascii: "\""))
    }
}

/// A small RFC 8259 parser that keeps number literals verbatim.
struct JSONParser {
    let bytes: [UInt8]
    var index = 0
    var rejectDuplicateKeys = false
    static let maxDepth = 512

    init(bytes: [UInt8]) { self.bytes = bytes }

    mutating func skipWhitespace() {
        while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
    }

    private func error(_ msg: String) -> SigstoreError { SigstoreError("invalid JSON at offset \(index): \(msg)") }

    mutating func parseValue(depth: Int) throws -> JSONValue {
        guard depth < Self.maxDepth else { throw error("nesting too deep") }
        guard index < bytes.count else { throw error("unexpected end") }
        switch bytes[index] {
        case UInt8(ascii: "{"): return try parseObject(depth: depth)
        case UInt8(ascii: "["): return try parseArray(depth: depth)
        case UInt8(ascii: "\""): return .string(try parseString())
        case UInt8(ascii: "t"): try expect("true"); return .bool(true)
        case UInt8(ascii: "f"): try expect("false"); return .bool(false)
        case UInt8(ascii: "n"): try expect("null"); return .null
        default: return .number(try parseNumber())
        }
    }

    private mutating func expect(_ literal: String) throws {
        let l = Array(literal.utf8)
        guard index + l.count <= bytes.count, Array(bytes[index..<(index + l.count)]) == l else {
            throw error("invalid literal")
        }
        index += l.count
    }

    private mutating func parseObject(depth: Int) throws -> JSONValue {
        index += 1
        var o: [String: JSONValue] = [:]
        skipWhitespace()
        if index < bytes.count, bytes[index] == UInt8(ascii: "}") { index += 1; return .object(o) }
        while true {
            skipWhitespace()
            guard index < bytes.count, bytes[index] == UInt8(ascii: "\"") else { throw error("expected key") }
            let key = try parseString()
            skipWhitespace()
            guard index < bytes.count, bytes[index] == UInt8(ascii: ":") else { throw error("expected ':'") }
            index += 1
            skipWhitespace()
            if rejectDuplicateKeys && o[key] != nil { throw error("duplicate field \(key)") }
            o[key] = try parseValue(depth: depth + 1)
            skipWhitespace()
            guard index < bytes.count else { throw error("unexpected end") }
            if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
            if bytes[index] == UInt8(ascii: "}") { index += 1; return .object(o) }
            throw error("expected ',' or '}'")
        }
    }

    private mutating func parseArray(depth: Int) throws -> JSONValue {
        index += 1
        var a: [JSONValue] = []
        skipWhitespace()
        if index < bytes.count, bytes[index] == UInt8(ascii: "]") { index += 1; return .array(a) }
        while true {
            skipWhitespace()
            a.append(try parseValue(depth: depth + 1))
            skipWhitespace()
            guard index < bytes.count else { throw error("unexpected end") }
            if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
            if bytes[index] == UInt8(ascii: "]") { index += 1; return .array(a) }
            throw error("expected ',' or ']'")
        }
    }

    private mutating func parseNumber() throws -> String {
        let start = index
        func digits() -> Int {
            let s = index
            while index < bytes.count, bytes[index] >= 0x30, bytes[index] <= 0x39 { index += 1 }
            return index - s
        }
        if index < bytes.count, bytes[index] == UInt8(ascii: "-") { index += 1 }
        guard index < bytes.count else { throw error("invalid number") }
        if bytes[index] == UInt8(ascii: "0") {
            index += 1
        } else {
            guard digits() > 0 else { throw error("invalid number") }
        }
        if index < bytes.count, bytes[index] == UInt8(ascii: ".") {
            index += 1
            guard digits() > 0 else { throw error("invalid number") }
        }
        if index < bytes.count, bytes[index] == UInt8(ascii: "e") || bytes[index] == UInt8(ascii: "E") {
            index += 1
            if index < bytes.count, bytes[index] == UInt8(ascii: "+") || bytes[index] == UInt8(ascii: "-") {
                index += 1
            }
            guard digits() > 0 else { throw error("invalid number") }
        }
        return String(decoding: bytes[start..<index], as: UTF8.self)
    }

    private mutating func parseString() throws -> String {
        index += 1
        var scalars = String.UnicodeScalarView()
        var raw: [UInt8] = []
        func flushRaw() throws {
            guard !raw.isEmpty else { return }
            guard let s = String(bytes: raw, encoding: .utf8) else { throw error("invalid UTF-8") }
            scalars.append(contentsOf: s.unicodeScalars)
            raw.removeAll()
        }
        while true {
            guard index < bytes.count else { throw error("unterminated string") }
            let b = bytes[index]
            if b == UInt8(ascii: "\"") {
                index += 1
                try flushRaw()
                return String(scalars)
            }
            if b < 0x20 { throw error("control character in string") }
            if b != UInt8(ascii: "\\") {
                raw.append(b)
                index += 1
                continue
            }
            try flushRaw()
            index += 1
            guard index < bytes.count else { throw error("unterminated escape") }
            let e = bytes[index]
            index += 1
            switch e {
            case UInt8(ascii: "\""): scalars.append("\"")
            case UInt8(ascii: "\\"): scalars.append("\\")
            case UInt8(ascii: "/"): scalars.append("/")
            case UInt8(ascii: "b"): scalars.append("\u{08}")
            case UInt8(ascii: "f"): scalars.append("\u{0C}")
            case UInt8(ascii: "n"): scalars.append("\n")
            case UInt8(ascii: "r"): scalars.append("\r")
            case UInt8(ascii: "t"): scalars.append("\t")
            case UInt8(ascii: "u"):
                let first = try hex4()
                if (0xD800..<0xDC00).contains(first) {
                    // High surrogate: combine with a following \uDC00-\uDFFF.
                    if index + 6 <= bytes.count, bytes[index] == UInt8(ascii: "\\"), bytes[index + 1] == UInt8(ascii: "u")
                    {
                        let save = index
                        index += 2
                        let second = try hex4()
                        if (0xDC00..<0xE000).contains(second) {
                            scalars.append(Unicode.Scalar(0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00))!)
                            continue
                        }
                        index = save
                    }
                    scalars.append("\u{FFFD}")  // Go: unpaired surrogate → U+FFFD
                } else if (0xDC00..<0xE000).contains(first) {
                    scalars.append("\u{FFFD}")
                } else {
                    scalars.append(Unicode.Scalar(first)!)
                }
            default:
                throw error("invalid escape")
            }
        }
    }

    private mutating func hex4() throws -> UInt32 {
        guard index + 4 <= bytes.count, let v = UInt32(String(decoding: bytes[index..<(index + 4)], as: UTF8.self), radix: 16)
        else { throw error("invalid \\u escape") }
        // UInt32(radix:) accepts a leading '+'; JSON does not.
        guard bytes[index] != UInt8(ascii: "+") else { throw error("invalid \\u escape") }
        index += 4
        return v
    }
}
