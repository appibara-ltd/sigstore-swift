import Crypto
import Foundation

/// Hexadecimal encoding and decoding.
public enum Hex {
    /// Encodes `bytes` as lowercase hex.
    public static func encode<B: Sequence>(_ bytes: B) -> String where B.Element == UInt8 {
        let digits = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        out.reserveCapacity(64)
        for b in bytes {
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Decodes a hex string (either case). Returns nil on malformed input.
    public static func decode(_ string: String) -> [UInt8]? {
        let chars = Array(string.utf8)
        guard chars.count % 2 == 0 else { return nil }
        func value(_ c: UInt8) -> UInt8? {
            switch c {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
            case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
            default: return nil
            }
        }
        var out = [UInt8]()
        out.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = value(chars[i]), let lo = value(chars[i + 1]) else { return nil }
            out.append(hi << 4 | lo)
            i += 2
        }
        return out
    }
}

/// Standard-alphabet base64 encoding and decoding.
public enum Base64 {
    /// Strict standard-alphabet base64 decoding (Go's `base64.StdEncoding`).
    public static func decode(_ string: String) -> Data? {
        Data(base64Encoded: string)
    }

    /// Encodes `data` as padded standard-alphabet base64.
    public static func encode<D: DataProtocol>(_ data: D) -> String {
        Data(data).base64EncodedString()
    }
}

/// Hash functions supported by Sigstore (Go's `crypto.Hash` subset).
public enum HashFunc: String, Sendable, Hashable, CaseIterable {
    case sha256
    case sha384
    case sha512

    /// Returns the digest of `data` under this hash function.
    public func digest<D: DataProtocol>(_ data: D) -> [UInt8] {
        switch self {
        case .sha256: return Array(SHA256.hash(data: data))
        case .sha384: return Array(SHA384.hash(data: data))
        case .sha512: return Array(SHA512.hash(data: data))
        }
    }

    /// The digest size in bytes.
    public var size: Int {
        switch self {
        case .sha256: return 32
        case .sha384: return 48
        case .sha512: return 64
        }
    }

    /// Mirrors sigstore-go `algStringToHashFunc`: accepts in-toto digest
    /// names ("sha256") and protobuf-specs `HashAlgorithm` names ("SHA2_256").
    public init(algorithmString alg: String) throws {
        switch alg {
        case "sha256", "SHA2_256": self = .sha256
        case "sha384", "SHA2_384": self = .sha384
        case "sha512", "SHA2_512": self = .sha512
        case "": throw SigstoreError("empty digest algorithm")
        default: throw SigstoreError("unsupported digest algorithm")
        }
    }
}
