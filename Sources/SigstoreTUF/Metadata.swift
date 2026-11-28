// TUF metadata. Port of theupdateframework/go-tuf v2.4.2 metadata
// (types.go, metadata.go, marshal.go, keys.go, errors.go), the version
// sigstore-go v1.4.1 depends on.

import Crypto
import Foundation
import SigstoreCommon
import SigstoreCryptoExtras
import X509
import _CryptoExtras

// MARK: - Errors

/// Mirrors go-tuf's error types. `isRepository` / `isBadVersionNumber`
/// follow their `errors.Is` hierarchy.
public enum TUFError: Error, CustomStringConvertible, Sendable {
    case repository(String)
    case unsignedMetadata(String)
    case badVersionNumber(String)
    case equalVersionNumber(String)
    case expiredMetadata(String)
    case lengthOrHashMismatch(String)
    case download(String)
    case downloadLengthMismatch(String)
    case downloadHTTP(statusCode: Int, url: String)
    case value(String)
    case type(String)
    case runtime(String)

    /// `errors.Is(err, &ErrRepository{})`.
    public var isRepository: Bool {
        switch self {
        case .repository, .unsignedMetadata, .badVersionNumber, .equalVersionNumber, .expiredMetadata,
            .lengthOrHashMismatch:
            return true
        default: return false
        }
    }

    /// The error message, prefixed by its kind as in go-tuf's `Error()`.
    public var description: String {
        switch self {
        case .repository(let m): return "repository error: \(m)"
        case .unsignedMetadata(let m): return "unsigned metadata error: \(m)"
        case .badVersionNumber(let m): return "bad version number error: \(m)"
        case .equalVersionNumber(let m): return "equal version number error: \(m)"
        case .expiredMetadata(let m): return "expired metadata error: \(m)"
        case .lengthOrHashMismatch(let m): return "length/hash verification error: \(m)"
        case .download(let m): return "download error: \(m)"
        case .downloadLengthMismatch(let m): return "download length mismatch error: \(m)"
        case .downloadHTTP(let code, let url): return "failed to download \(url), http status code: \(code)"
        case .value(let m): return "value error: \(m)"
        case .type(let m): return "type error: \(m)"
        case .runtime(let m): return "runtime error: \(m)"
        }
    }
}

// MARK: - Role names

/// Mirrors go-tuf `metadata.ROOT`, `SNAPSHOT`, `TARGETS`, `TIMESTAMP`: the
/// top-level role names.
public enum TUFRole {
    /// The `root` role.
    public static let root = "root"
    /// The `snapshot` role.
    public static let snapshot = "snapshot"
    /// The top-level `targets` role.
    public static let targets = "targets"
    /// The `timestamp` role.
    public static let timestamp = "timestamp"
}

// MARK: - Decoding helpers (Go encoding/json semantics)

/// Field accessors with Go `json.Unmarshal` leniency: a missing or null
/// field takes its zero value; a value of the wrong JSON type is an error.
struct Fields {
    let object: [String: JSONValue]

    init(_ value: JSONValue, _ what: String) throws {
        switch value {
        case .object(let o): object = o
        case .null: object = [:]
        default: throw TUFError.type("\(what) is not a JSON object")
        }
    }

    private func present(_ key: String) -> JSONValue? {
        guard let v = object[key], v != .null else { return nil }
        return v
    }

    func string(_ key: String) throws -> String {
        guard let v = present(key) else { return "" }
        guard let s = v.stringValue else { throw TUFError.type("\(key) is not a string") }
        return s
    }

    func int64(_ key: String) throws -> Int64 {
        guard let v = present(key) else { return 0 }
        guard case .number = v else { throw TUFError.type("\(key) is not a number") }
        guard let i = v.int64Value else { throw TUFError.type("\(key) is not an int64") }
        return i
    }

    func int(_ key: String) throws -> Int {
        let i = try int64(key)
        guard let n = Int(exactly: i) else { throw TUFError.type("\(key) out of range") }
        return n
    }

    func bool(_ key: String) throws -> Bool {
        guard let v = present(key) else { return false }
        guard let b = v.boolValue else { throw TUFError.type("\(key) is not a bool") }
        return b
    }

    func strings(_ key: String) throws -> [String]? {
        guard let v = present(key) else { return nil }
        guard let a = v.arrayValue else { throw TUFError.type("\(key) is not an array") }
        return try a.map {
            guard let s = $0.stringValue else { throw TUFError.type("\(key) element is not a string") }
            return s
        }
    }

    func map<T>(_ key: String, _ f: (String, JSONValue) throws -> T) throws -> [String: T] {
        guard let v = present(key) else { return [:] }
        guard let o = v.objectValue else { throw TUFError.type("\(key) is not an object") }
        var out: [String: T] = [:]
        for (k, e) in o { out[k] = try f(k, e) }
        return out
    }

    func date(_ key: String) throws -> Date {
        // Zero time.Time: always expired.
        guard let v = present(key) else { return .distantPast }
        guard let s = v.stringValue, let d = parseRFC3339(s) else {
            throw TUFError.type("\(key) is not an RFC 3339 time")
        }
        return d
    }

    func hashes(_ key: String) throws -> [String: [UInt8]] {
        try map(key) { _, v in
            guard let s = v.stringValue, let b = decodeHexBytes(s) else {
                throw TUFError.value("tuf: invalid JSON hex bytes")
            }
            return b
        }
    }
}

/// Go `time.Time.UnmarshalJSON` (RFC 3339, optional fractional seconds).
func parseRFC3339(_ s: String) -> Date? {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    if let d = f.date(from: s) { return d }
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f.date(from: s)
}

/// go-tuf `HexBytes`: an even-length hex string (either case).
func decodeHexBytes(_ s: String) -> [UInt8]? {
    let chars = Array(s.utf8)
    guard chars.count % 2 == 0 else { return nil }
    var out: [UInt8] = []
    out.reserveCapacity(chars.count / 2)
    func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x61...0x66: return c - 0x61 + 10
        case 0x41...0x46: return c - 0x41 + 10
        default: return nil
        }
    }
    var i = 0
    while i < chars.count {
        guard let hi = nibble(chars[i]), let lo = nibble(chars[i + 1]) else { return nil }
        out.append(hi << 4 | lo)
        i += 2
    }
    return out
}

// MARK: - Types

/// Mirrors `metadata.Key`.
public struct TUFKey: Sendable {
    /// Mirrors `metadata.KeyTypeEd25519`: hex-encoded raw Ed25519 key.
    public static let typeEd25519 = "ed25519"
    /// Mirrors `metadata.KeyTypeECDSA_SHA2_P256_COMPAT`: PEM ECDSA key
    /// (legacy key type name).
    public static let typeECDSAP256Compat = "ecdsa-sha2-nistp256"
    /// Mirrors `metadata.KeyTypeECDSA_SHA2_P256`: PEM ECDSA key.
    public static let typeECDSAP256 = "ecdsa"
    /// Mirrors `metadata.KeyTypeRSASSA_PSS_SHA256`: PEM RSA key, RSASSA-PSS
    /// with SHA-256.
    public static let typeRSASSAPSSSHA256 = "rsa"
    /// Mirrors `metadata.KeySchemeECDSA_SHA2_P256`: ECDSA with SHA-256.
    public static let schemeECDSAP256 = "ecdsa-sha2-nistp256"
    /// Mirrors `metadata.KeySchemeECDSA_SHA2_P384`: ECDSA with SHA-384.
    public static let schemeECDSAP384 = "ecdsa-sha2-nistp384"

    /// The key type (`keytype`), e.g. ``typeEd25519``.
    public var type: String
    /// The signature scheme (`scheme`).
    public var scheme: String
    /// The public key (`keyval.public`): hex for Ed25519, PEM otherwise.
    public var publicKey: String

    init(_ v: JSONValue) throws {
        let f = try Fields(v, "key")
        type = try f.string("keytype")
        scheme = try f.string("scheme")
        publicKey = try Fields(f.object["keyval"] ?? .null, "keyval").string("public")
    }

    /// A verifier for this key (`ToPublicKey` + sigstore `LoadVerifier`).
    func verifier() throws -> TUFKeyVerifier {
        switch type {
        case Self.typeRSASSAPSSSHA256:
            let key = try Certificate.PublicKey(pemEncoded: publicKey)
            guard let rsa = _RSA.Signing.PublicKey(key) else { throw TUFError.type("invalid rsa public key") }
            let components = try RSAPublicKeyComponents(pkcs1DER: rsa.pkcs1DERRepresentation)
            return TUFKeyVerifier(fingerprint: Array(SHA256.hash(data: key.pkixBytes)), kind: .rsaPSS(components))
        case Self.typeECDSAP256, Self.typeECDSAP256Compat:
            let key = try Certificate.PublicKey(pemEncoded: publicKey)
            let hash: HashFunc = scheme == Self.schemeECDSAP384 ? .sha384 : .sha256
            let v = try SignatureVerifier(publicKey: key, hashFunction: hash)
            switch v.key {
            case .ecdsaP256, .ecdsaP384, .ecdsaP521: break
            default: throw TUFError.type("invalid ecdsa public key")
            }
            return TUFKeyVerifier(fingerprint: Array(SHA256.hash(data: key.pkixBytes)), kind: .standard(v))
        case Self.typeEd25519:
            guard let raw = decodeHexBytes(publicKey) else { throw TUFError.value("invalid ed25519 public key hex") }
            let k = try Curve25519.Signing.PublicKey(rawRepresentation: raw)
            let key = Certificate.PublicKey(k)
            return TUFKeyVerifier(
                fingerprint: Array(SHA256.hash(data: key.pkixBytes)),
                kind: .standard(try SignatureVerifier(publicKey: key)))
        default:
            throw TUFError.type("unsupported public key type")
        }
    }
}

struct TUFKeyVerifier {
    enum Kind {
        case standard(SignatureVerifier)
        case rsaPSS(RSAPublicKeyComponents)
    }
    /// SHA-256 of the PKIX public key: threshold counts distinct keys.
    var fingerprint: [UInt8]
    var kind: Kind

    func verify(signature: [UInt8], payload: [UInt8]) -> Bool {
        switch kind {
        case .standard(let v):
            return v.verify(signature: signature, message: payload)
        case .rsaPSS(let k):
            // go-tuf: rsa.VerifyPSS(SHA-256, PSSOptions{Hash: SHA256}): salt
            // length 0 means auto-detect.
            return RSADigestVerifier.isValidPSS(
                signature, digest: Array(SHA256.hash(data: payload)), hash: .sha256, key: k, saltLength: nil)
        }
    }
}

/// Mirrors `metadata.Role`.
public struct TUFRoleKeys: Sendable {
    /// IDs of the keys authorized to sign for the role.
    public var keyIDs: [String]
    /// The role's signature threshold.
    public var threshold: Int

    init(_ v: JSONValue) throws {
        let f = try Fields(v, "role")
        keyIDs = try f.strings("keyids") ?? []
        threshold = try f.int("threshold")
    }
}

/// Mirrors `metadata.MetaFiles`.
public struct MetaFiles: Sendable {
    /// Expected length in bytes; 0 when absent (not checked).
    public var length: Int64
    /// Expected digests by algorithm name; empty when absent (not checked).
    public var hashes: [String: [UInt8]]
    /// Version of the referenced metadata file.
    public var version: Int64

    init(_ v: JSONValue) throws {
        let f = try Fields(v, "meta")
        length = try f.int64("length")
        hashes = try f.hashes("hashes")
        version = try f.int64("version")
    }

    /// Mirrors `MetaFiles.VerifyLengthHashes`: hashes and length are checked
    /// only when present.
    public func verifyLengthHashes(_ data: Data) throws {
        if !hashes.isEmpty { try verifyHashes(data, hashes) }
        if length != 0 { try verifyLength(data, length) }
    }
}

/// Mirrors `metadata.TargetFiles`.
public struct TargetFiles: Sendable {
    /// Length of the target in bytes.
    public var length: Int64
    /// Digests of the target by algorithm name (never empty).
    public var hashes: [String: [UInt8]]
    /// The target's `custom` JSON, if any.
    public var custom: JSONValue?
    /// The target path (its key in the targets map).
    public var path: String

    init(path: String, _ v: JSONValue) throws {
        let f = try Fields(v, "target")
        length = try f.int64("length")
        hashes = try f.hashes("hashes")
        guard !hashes.isEmpty else { throw TUFError.value("hashes must not be empty for target files") }
        custom = f.object["custom"]
        self.path = path
    }

    /// Mirrors `TargetFiles.VerifyLengthHashes`.
    public func verifyLengthHashes(_ data: Data) throws {
        guard !hashes.isEmpty else {
            throw TUFError.lengthOrHashMismatch("hashes must not be empty for target files")
        }
        try verifyHashes(data, hashes)
        try verifyLength(data, length)
    }
}

func verifyLength(_ data: Data, _ length: Int64) throws {
    if Int64(data.count) != length {
        throw TUFError.lengthOrHashMismatch("length verification failed - expected \(length), got \(data.count)")
    }
}

func verifyHashes(_ data: Data, _ hashes: [String: [UInt8]]) throws {
    for (alg, expected) in hashes {
        let actual: [UInt8]
        switch alg {
        case "sha256": actual = Array(SHA256.hash(data: data))
        case "sha512": actual = Array(SHA512.hash(data: data))
        default:
            throw TUFError.lengthOrHashMismatch("hash verification failed - unknown hashing algorithm - \(alg)")
        }
        if actual != expected {
            throw TUFError.lengthOrHashMismatch("hash verification failed - mismatch for algorithm \(alg)")
        }
    }
}

/// Mirrors `metadata.DelegatedRole`.
public struct DelegatedRole: Sendable {
    /// The delegated role's name.
    public var name: String
    /// IDs of the keys authorized to sign for the role.
    public var keyIDs: [String]
    /// The role's signature threshold.
    public var threshold: Int
    /// Whether the search for a target stops at this role.
    public var terminating: Bool
    /// Prefixes of the base64url SHA-256 of target paths the role is trusted
    /// for; mutually exclusive with ``paths``.
    public var pathHashPrefixes: [String]?
    /// Path patterns the role is trusted for; mutually exclusive with
    /// ``pathHashPrefixes``.
    public var paths: [String]?

    /// Decodes a delegated role from its JSON object.
    ///
    /// - Throws: ``TUFError`` if a field has the wrong JSON type or both
    ///   `paths` and `path_hash_prefixes` are present.
    public init(_ v: JSONValue) throws {
        let f = try Fields(v, "delegated role")
        name = try f.string("name")
        keyIDs = try f.strings("keyids") ?? []
        threshold = try f.int("threshold")
        terminating = try f.bool("terminating")
        pathHashPrefixes = try f.strings("path_hash_prefixes")
        paths = try f.strings("paths")
        // go-tuf refuses to (re-)marshal a role with both, so its signature
        // can never verify; reject up front.
        if paths != nil && pathHashPrefixes != nil {
            throw TUFError.value(
                "not allowed to have both \"paths\" and \"path_hash_prefixes\" present")
        }
    }

    /// Mirrors `DelegatedRole.IsDelegatedPath`.
    public func isDelegatedPath(_ target: String) -> Bool {
        if let paths, !paths.isEmpty {
            return paths.contains { isTargetInPathPattern(target, $0) }
        }
        if let prefixes = pathHashPrefixes, !prefixes.isEmpty {
            // go-tuf compares against base64url(sha256(path)), not hex.
            let encoded = Data(SHA256.hash(data: Data(target.utf8))).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            return prefixes.contains { encoded.hasPrefix($0) }
        }
        return false
    }
}

/// Mirrors `metadata.SuccinctRoles`.
public struct SuccinctRoles: Sendable {
    /// IDs of the keys authorized to sign for every bin role.
    public var keyIDs: [String]
    /// The signature threshold of every bin role.
    public var threshold: Int
    /// Number of leading bits of the target path hash that pick the bin
    /// (0...32).
    public var bitLength: Int
    /// Prefix of the bin role names (`<prefix>-<hex bin>`).
    public var namePrefix: String

    /// Decodes succinct roles from their JSON object.
    ///
    /// - Throws: ``TUFError`` if a field has the wrong JSON type or
    ///   `bit_length` is outside 0...32.
    public init(_ v: JSONValue) throws {
        let f = try Fields(v, "succinct roles")
        keyIDs = try f.strings("keyids") ?? []
        threshold = try f.int("threshold")
        bitLength = try f.int("bit_length")
        namePrefix = try f.string("name_prefix")
        guard (0...32).contains(bitLength) else { throw TUFError.value("bit_length out of range") }
    }

    /// Mirrors `SuccinctRoles.GetSuffixLen`.
    var suffixLenAndBins: (Int, Int) {
        let bins = 1 << bitLength
        return (String(bins - 1, radix: 16).count, bins)
    }

    /// Mirrors `SuccinctRoles.GetRolesForTarget`.
    public func rolesForTarget(_ target: String) -> [(name: String, terminating: Bool)] {
        let (suffixLen, _) = suffixLenAndBins
        let hash = Array(SHA256.hash(data: Data(target.utf8)))
        let prefix = hash.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        let bin = bitLength == 0 ? 0 : prefix >> UInt32(32 - bitLength)
        let hex = String(bin, radix: 16)
        let suffix = String(repeating: "0", count: max(0, suffixLen - hex.count)) + hex
        return [("\(namePrefix)-\(suffix)", true)]
    }
}

/// Mirrors `metadata.Delegations`.
public struct Delegations: Sendable {
    /// Keys usable by the delegated roles, by key ID.
    public var keys: [String: TUFKey]
    /// The delegated roles, in priority order.
    public var roles: [DelegatedRole]?
    /// Hash-bin delegations, if used instead of ``roles``.
    public var succinctRoles: SuccinctRoles?

    init(_ v: JSONValue) throws {
        let f = try Fields(v, "delegations")
        keys = try f.map("keys") { _, k in try TUFKey(k) }
        if let r = f.object["roles"], r != .null {
            guard let a = r.arrayValue else { throw TUFError.type("roles is not an array") }
            roles = try a.map(DelegatedRole.init)
        }
        if let s = f.object["succinct_roles"], s != .null { succinctRoles = try SuccinctRoles(s) }
        // go-tuf re-marshals only one of the two, so such metadata never verifies.
        if roles != nil && succinctRoles != nil {
            throw TUFError.value("delegations cannot have both roles and succinct_roles")
        }
    }

    /// Mirrors `Delegations.GetRolesForTarget`.
    public func rolesForTarget(_ target: String) -> [(name: String, terminating: Bool)] {
        if let roles {
            return roles.filter { $0.isDelegatedPath(target) }.map { ($0.name, $0.terminating) }
        }
        if let succinctRoles { return succinctRoles.rolesForTarget(target) }
        return []
    }
}

/// go-tuf `isTargetInPathPattern`: same number of `/`-separated segments,
/// each matching with `filepath.Match` (a malformed pattern never matches,
/// as go-tuf ignores the error).
func isTargetInPathPattern(_ target: String, _ pattern: String) -> Bool {
    let t = target.split(separator: "/", omittingEmptySubsequences: false)
    let p = pattern.split(separator: "/", omittingEmptySubsequences: false)
    guard t.count == p.count else { return false }
    return zip(p, t).allSatisfy { goPathMatch(Array($0.utf8), Array($1.utf8)) == true }
}

/// Port of Go's `path.Match` (go1.27 src/path/match.go): returns nil for a
/// malformed pattern (`ErrBadPattern`). Byte-oriented like Go, decoding
/// UTF-8 runes for `?` and character classes. Runs in polynomial time: only
/// the last star backtracks.
func goPathMatch(_ patternIn: [UInt8], _ nameIn: [UInt8]) -> Bool? {
    var pattern = patternIn[...]
    var name = nameIn[...]
    let slash = UInt8(ascii: "/")
    patternLoop: while !pattern.isEmpty {
        let (star, chunk, rest) = scanChunk(pattern)
        pattern = rest
        if star && chunk.isEmpty {
            return !name.contains(slash)  // trailing * matches the rest without '/'
        }
        let (t, ok, bad) = matchChunk(chunk, name)
        if ok && (t.isEmpty || !pattern.isEmpty) {
            name = t
            continue
        }
        if bad { return nil }
        if star {
            var i = name.startIndex
            while i < name.endIndex && name[i] != slash {
                let (t, ok, bad) = matchChunk(chunk, name[(i + 1)...])
                if ok {
                    // The last chunk must consume the whole name.
                    if pattern.isEmpty && !t.isEmpty {
                        i += 1
                        continue
                    }
                    name = t
                    continue patternLoop
                }
                if bad { return nil }
                i += 1
            }
        }
        // Report malformed patterns even after a mismatch, as Go does.
        while !pattern.isEmpty {
            let (_, chunk, rest) = scanChunk(pattern)
            pattern = rest
            if matchChunk(chunk, [][...]).bad { return nil }
        }
        return false
    }
    return name.isEmpty
}

private func scanChunk(_ p: ArraySlice<UInt8>) -> (star: Bool, chunk: ArraySlice<UInt8>, rest: ArraySlice<UInt8>) {
    var pattern = p
    var star = false
    while let f = pattern.first, f == UInt8(ascii: "*") {
        pattern = pattern.dropFirst()
        star = true
    }
    var inRange = false
    var i = pattern.startIndex
    while i < pattern.endIndex {
        switch pattern[i] {
        case UInt8(ascii: "\\"):
            if i + 1 < pattern.endIndex { i += 1 }
        case UInt8(ascii: "["): inRange = true
        case UInt8(ascii: "]"): inRange = false
        case UInt8(ascii: "*"):
            if !inRange { return (star, pattern[..<i], pattern[i...]) }
        default: break
        }
        i += 1
    }
    return (star, pattern, [][...])
}

/// Decodes one UTF-8 rune (Go `utf8.DecodeRune`): (0xFFFD, 1) when invalid.
private func decodeRune(_ s: ArraySlice<UInt8>) -> (UInt32, Int) {
    guard let b0 = s.first else { return (0xFFFD, 0) }
    if b0 < 0x80 { return (UInt32(b0), 1) }
    let len = b0 >= 0xF0 ? 4 : b0 >= 0xE0 ? 3 : b0 >= 0xC0 ? 2 : 0
    guard len > 0, s.count >= len,
        let scalar = String(bytes: s.prefix(len), encoding: .utf8)?.unicodeScalars.first,
        scalar.utf8.count == len
    else { return (0xFFFD, 1) }
    return (scalar.value, len)
}

/// Go `getEsc`: one possibly escaped rune of a character class.
private func getEsc(_ c: ArraySlice<UInt8>) -> (UInt32, ArraySlice<UInt8>)? {
    var chunk = c
    guard let f = chunk.first, f != UInt8(ascii: "-"), f != UInt8(ascii: "]") else { return nil }
    if f == UInt8(ascii: "\\") {
        chunk = chunk.dropFirst()
        if chunk.isEmpty { return nil }
    }
    let (r, n) = decodeRune(chunk)
    if r == 0xFFFD && n == 1 { return nil }
    let next = chunk.dropFirst(n)
    if next.isEmpty { return nil }
    return (r, next)
}

/// Go `matchChunk`: (rest, ok, badPattern).
private func matchChunk(_ c: ArraySlice<UInt8>, _ str: ArraySlice<UInt8>) -> (ArraySlice<UInt8>, Bool, bad: Bool) {
    var chunk = c
    var s = str
    var failed = false
    while let head = chunk.first {
        failed = failed || s.isEmpty
        switch head {
        case UInt8(ascii: "["):
            var r: UInt32 = 0
            if !failed {
                let (rr, n) = decodeRune(s)
                r = rr
                s = s.dropFirst(n)
            }
            chunk = chunk.dropFirst()
            var negated = false
            if chunk.first == UInt8(ascii: "^") {
                negated = true
                chunk = chunk.dropFirst()
            }
            var match = false
            var nrange = 0
            while true {
                if chunk.first == UInt8(ascii: "]") && nrange > 0 {
                    chunk = chunk.dropFirst()
                    break
                }
                guard let (lo, afterLo) = getEsc(chunk) else { return ([][...], false, true) }
                chunk = afterLo
                var hi = lo
                if chunk.first == UInt8(ascii: "-") {
                    guard let (h, afterHi) = getEsc(chunk.dropFirst()) else { return ([][...], false, true) }
                    hi = h
                    chunk = afterHi
                }
                match = match || (lo <= r && r <= hi)
                nrange += 1
            }
            failed = failed || match == negated
        case UInt8(ascii: "?"):
            if !failed {
                failed = s.first == UInt8(ascii: "/")
                s = s.dropFirst(decodeRune(s).1)
            }
            chunk = chunk.dropFirst()
        case UInt8(ascii: "\\"):
            chunk = chunk.dropFirst()
            guard let lit = chunk.first else { return ([][...], false, true) }
            if !failed {
                failed = lit != s.first
                s = s.dropFirst()
            }
            chunk = chunk.dropFirst()
        default:
            if !failed {
                failed = head != s.first
                s = s.dropFirst()
            }
            chunk = chunk.dropFirst()
        }
    }
    return failed ? ([][...], false, false) : (s, true, false)
}

// MARK: - Signed metadata

/// A top-level TUF role's `signed` payload.
public protocol SignedRole: Sendable {
    static var roleType: String { get }
    init(_ signed: JSONValue) throws
    var type: String { get }
    var version: Int64 { get }
    var expires: Date { get }
}

extension SignedRole {
    /// Mirrors `IsExpired`: expired when the reference time is after `expires`.
    public func isExpired(_ referenceTime: Date) -> Bool { referenceTime > expires }
}

/// Mirrors `metadata.RootType`.
public struct RootType: SignedRole {
    /// The role name, `root`.
    public static let roleType = TUFRole.root
    /// The `_type` field.
    public var type: String
    /// The TUF specification version.
    public var specVersion: String
    /// Whether the repository serves version- and hash-prefixed files.
    public var consistentSnapshot: Bool
    /// The metadata version.
    public var version: Int64
    /// The expiry time.
    public var expires: Date
    /// Keys of the top-level roles, by key ID.
    public var keys: [String: TUFKey]
    /// Key IDs and threshold of each top-level role, by role name.
    public var roles: [String: TUFRoleKeys]

    /// Decodes the `signed` payload.
    ///
    /// - Throws: ``TUFError`` if a field has the wrong JSON type.
    public init(_ signed: JSONValue) throws {
        let f = try Fields(signed, "signed")
        type = try f.string("_type")
        specVersion = try f.string("spec_version")
        consistentSnapshot = try f.bool("consistent_snapshot")
        version = try f.int64("version")
        expires = try f.date("expires")
        keys = try f.map("keys") { _, k in try TUFKey(k) }
        roles = try f.map("roles") { _, r in try TUFRoleKeys(r) }
    }
}

/// Mirrors `metadata.TimestampType`.
public struct TimestampType: SignedRole {
    /// The role name, `timestamp`.
    public static let roleType = TUFRole.timestamp
    /// The `_type` field.
    public var type: String
    /// The TUF specification version.
    public var specVersion: String
    /// The metadata version.
    public var version: Int64
    /// The expiry time.
    public var expires: Date
    /// The snapshot metadata it describes (`snapshot.json`).
    public var meta: [String: MetaFiles]

    /// Decodes the `signed` payload.
    ///
    /// - Throws: ``TUFError`` if a field has the wrong JSON type.
    public init(_ signed: JSONValue) throws {
        let f = try Fields(signed, "signed")
        type = try f.string("_type")
        specVersion = try f.string("spec_version")
        version = try f.int64("version")
        expires = try f.date("expires")
        meta = try f.map("meta") { _, m in try MetaFiles(m) }
    }
}

/// Mirrors `metadata.SnapshotType`.
public struct SnapshotType: SignedRole {
    /// The role name, `snapshot`.
    public static let roleType = TUFRole.snapshot
    /// The `_type` field.
    public var type: String
    /// The TUF specification version.
    public var specVersion: String
    /// The metadata version.
    public var version: Int64
    /// The expiry time.
    public var expires: Date
    /// The targets metadata files it describes, by file name.
    public var meta: [String: MetaFiles]

    /// Decodes the `signed` payload.
    ///
    /// - Throws: ``TUFError`` if a field has the wrong JSON type.
    public init(_ signed: JSONValue) throws {
        let f = try Fields(signed, "signed")
        type = try f.string("_type")
        specVersion = try f.string("spec_version")
        version = try f.int64("version")
        expires = try f.date("expires")
        meta = try f.map("meta") { _, m in try MetaFiles(m) }
    }
}

/// Mirrors `metadata.TargetsType`.
public struct TargetsType: SignedRole {
    /// The role name, `targets`.
    public static let roleType = TUFRole.targets
    /// The `_type` field.
    public var type: String
    /// The TUF specification version.
    public var specVersion: String
    /// The metadata version.
    public var version: Int64
    /// The expiry time.
    public var expires: Date
    /// The targets this role signs for, by path.
    public var targets: [String: TargetFiles]
    /// Delegations to other targets roles, if any.
    public var delegations: Delegations?

    /// Decodes the `signed` payload.
    ///
    /// - Throws: ``TUFError`` if a field has the wrong JSON type or a target
    ///   has no hashes.
    public init(_ signed: JSONValue) throws {
        let f = try Fields(signed, "signed")
        type = try f.string("_type")
        specVersion = try f.string("spec_version")
        version = try f.int64("version")
        expires = try f.date("expires")
        targets = try f.map("targets") { path, t in try TargetFiles(path: path, t) }
        if let d = f.object["delegations"], d != .null { delegations = try Delegations(d) }
    }
}

/// Mirrors `metadata.Signature`.
public struct TUFSignature: Sendable {
    /// ID of the signing key.
    public var keyID: String
    /// The raw signature bytes.
    public var signature: [UInt8]
}

/// Mirrors `metadata.Metadata[T]`.
public struct Metadata<T: SignedRole>: Sendable {
    /// The decoded `signed` payload.
    public var signed: T
    /// The signatures over the canonical `signed` payload.
    public var signatures: [TUFSignature]
    /// The received `signed` value, canonicalized for signature checks.
    let signedJSON: JSONValue

    /// Mirrors `Metadata[T].FromBytes`: checks `_type`, decodes, and rejects
    /// duplicate signature key IDs.
    public init(fromBytes data: Data) throws {
        let json: JSONValue
        do {
            json = try JSONValue(parsing: data)
        } catch {
            throw TUFError.value("invalid metadata JSON: \(error)")
        }
        guard let top = json.objectValue else { throw TUFError.value("metadata is not a JSON object") }
        // checkType
        guard let signed = top["signed"], case .object = signed else {
            throw TUFError.value("metadata 'signed' field is missing or not an object")
        }
        guard let signedType = signed["_type"]?.stringValue else { throw TUFError.value("no _type found in signed") }
        guard signedType == T.roleType else {
            throw TUFError.value("expected metadata type \(T.roleType), got - \(signedType)")
        }

        self.signed = try T(signed)
        self.signedJSON = signed
        var sigs: [TUFSignature] = []
        if let s = top["signatures"], s != .null {
            guard let a = s.arrayValue else { throw TUFError.type("signatures is not an array") }
            for e in a {
                let f = try Fields(e, "signature")
                let keyID = try f.string("keyid")
                let sigHex = try f.string("sig")
                guard let sig = decodeHexBytes(sigHex) else { throw TUFError.value("tuf: invalid JSON hex bytes") }
                sigs.append(TUFSignature(keyID: keyID, signature: sig))
            }
        }
        // checkUniqueSignatures
        var seen = Set<String>()
        for s in sigs where !seen.insert(s.keyID).inserted {
            throw TUFError.value("multiple signatures found for key ID \(s.keyID)")
        }
        self.signatures = sigs
    }

    func canonicalSigned() throws -> [UInt8] { try signedJSON.canonicalBytes() }
}

/// A delegator: root (top-level roles) or targets (delegated roles).
protocol Delegator {
    func delegation(for role: String) throws -> (keys: [String: TUFKey], keyIDs: [String], threshold: Int)
}

extension Metadata: Delegator {
    func delegation(for role: String) throws -> (keys: [String: TUFKey], keyIDs: [String], threshold: Int) {
        if let root = signed as? RootType {
            guard let r = root.roles[role] else { throw TUFError.value("no delegation found for \(role)") }
            return (root.keys, r.keyIDs, r.threshold)
        }
        if let targets = signed as? TargetsType {
            guard let d = targets.delegations else { throw TUFError.value("no delegations found") }
            if let roles = d.roles {
                guard let r = roles.first(where: { $0.name == role }) else {
                    throw TUFError.value("no delegation found for \(role)")
                }
                return (d.keys, r.keyIDs, r.threshold)
            }
            if let s = d.succinctRoles { return (d.keys, s.keyIDs, s.threshold) }
            return (d.keys, [], 0)
        }
        throw TUFError.type("call is valid only on delegator metadata (should be either root or targets)")
    }

    /// Mirrors `Metadata.VerifyDelegate`: `delegated` must carry valid
    /// signatures from at least `threshold` distinct keys of `role`.
    public func verifyDelegate<D: SignedRole>(_ role: String, _ delegated: Metadata<D>) throws {
        let (keys, keyIDs, threshold) = try delegation(for: role)
        guard !keyIDs.isEmpty else { throw TUFError.value("no delegation found for \(role)") }
        guard threshold >= 1 else {
            throw TUFError.value("insufficient threshold (\(threshold)) configured for \(role)")
        }
        let payload = try delegated.canonicalSigned()
        var signingKeys = Set<[UInt8]>()
        for keyID in keyIDs {
            guard let key = keys[keyID] else {
                throw TUFError.value("key with ID \(keyID) not found in \(role) keyids")
            }
            let verifier = try key.verifier()
            let sig = delegated.signatures.last(where: { $0.keyID == keyID })?.signature ?? []
            if verifier.verify(signature: sig, payload: payload) {
                signingKeys.insert(verifier.fingerprint)
            }
        }
        if signingKeys.count < threshold {
            throw TUFError.unsignedMetadata(
                "Verifying \(role) failed, not enough signatures, got \(signingKeys.count), want \(threshold)")
        }
    }
}
