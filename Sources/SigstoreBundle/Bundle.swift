// Port of sigstore-go pkg/bundle/bundle.go (protobuf bundle v0.1–v0.3).
//
// Name note: `Bundle` mirrors sigstore-go but clashes with
// `Foundation.Bundle` in files importing both; write `SigstoreBundle.Bundle`
// there.

import Foundation
import SigstoreCommon
import SigstoreProtobufSpecs
import SigstoreTLog
import SigstoreVerify
import SwiftProtobuf
import X509

let mediaTypeBase = "application/vnd.dev.sigstore.bundle"

/// Mirrors the bundle package's sentinel errors (`ErrValidation`,
/// `ErrUnsupportedMediaType`, ...).
public enum BundleError: Error, CustomStringConvertible, Sendable, Equatable {
    case validation(String)
    case unsupportedMediaType(String)
    case emptyBundle
    case missingVerificationMaterial
    case missingBundleContent
    case invalidAttestation(String)
    case missingEnvelope
    case decodingJSON
    case decodingB64

    public var description: String {
        switch self {
        case .validation(let m): return "validation error: \(m)"
        case .unsupportedMediaType(let m): return "validation error: unsupported media type: \(m)"
        case .emptyBundle: return "validation error: empty protobuf bundle"
        case .missingVerificationMaterial: return "validation error: missing verification material"
        case .missingBundleContent: return "validation error: missing bundle content"
        case .invalidAttestation(let m): return "validation error: invalid attestation: \(m)"
        case .missingEnvelope: return "validation error: invalid attestation: missing valid envelope"
        case .decodingJSON: return "validation error: invalid attestation: decoding json"
        case .decodingB64: return "validation error: invalid attestation: decoding base64"
        }
    }
}

/// Mirrors `bundle.Option`.
public struct BundleOption: Sendable {
    let apply: @Sendable (inout Bundle) -> Void

    /// Mirrors `WithAllowCertificateChain` (v0.3+ bundles carrying an
    /// X.509 chain instead of a single certificate).
    public static func withAllowCertificateChain() -> BundleOption {
        BundleOption { $0.allowCertificateChain = true }
    }
}

/// Mirrors `bundle.Bundle`.
public struct Bundle: SignedEntity {
    public private(set) var protobuf: Dev_Sigstore_Bundle_V1_Bundle
    public private(set) var hasInclusionPromise = false
    public private(set) var hasInclusionProof = false
    var allowCertificateChain = false

    /// Mirrors `NewBundle`.
    public init(_ pbundle: Dev_Sigstore_Bundle_V1_Bundle, options: [BundleOption] = []) throws {
        protobuf = pbundle
        for option in options { option.apply(&self) }
        try validate()
    }

    /// Mirrors `Bundle.UnmarshalJSON` (protojson; unknown fields are errors).
    public init(json: Data, options: [BundleOption] = []) throws {
        let pb: Dev_Sigstore_Bundle_V1_Bundle
        do {
            pb = try Dev_Sigstore_Bundle_V1_Bundle(jsonUTF8Data: json)
        } catch {
            throw SigstoreError("failed to unmarshal bundle JSON", underlying: error)
        }
        try self.init(pb, options: options)
    }

    /// Mirrors `LoadJSONFromPath`.
    public static func loadJSONFromPath(_ path: String, options: [BundleOption] = []) throws -> Bundle {
        try Bundle(json: Data(contentsOf: URL(fileURLWithPath: path)), options: options)
    }

    /// Mirrors `Bundle.MarshalJSON`.
    public func marshalJSON() throws -> Data {
        try protobuf.jsonUTF8Data()
    }

    private mutating func validate() throws {
        let bundleVersion: String
        do {
            bundleVersion = try version()
        } catch {
            throw error.wrapped("error getting bundle version")
        }
        if semverCompare(bundleVersion, "v0.1") < 0 {
            throw BundleError.unsupportedMediaType("bundle version \(bundleVersion) is not supported")
        }
        do {
            try validateBundle(protobuf)
        } catch {
            throw error.wrapped("invalid bundle")
        }

        let entries = try tlogEntries()
        for entry in entries {
            if entry.hasInclusionPromise { hasInclusionPromise = true }
            if entry.hasInclusionProof { hasInclusionProof = true }
        }

        if semverCompare(bundleVersion, "v0.1") == 0 {
            if !entries.isEmpty && !hasInclusionPromise {
                throw SigstoreError("inclusion promises missing in bundle (required for bundle v0.1)")
            }
        } else if !entries.isEmpty && !hasInclusionProof {
            throw SigstoreError("inclusion proof missing in bundle (required for bundle v0.2)")
        }

        if semverCompare(bundleVersion, "v0.3") >= 0 {
            if !allowCertificateChain, case .x509CertificateChain = protobuf.verificationMaterial.content {
                throw SigstoreError("verification material cannot be X.509 certificate chain (for bundle v0.3)")
            }
        } else if allowCertificateChain {
            throw SigstoreError("certificate chain verification is only supported for bundle v0.3 and later")
        }

        if semverCompare(bundleVersion, "v0.4") >= 0 {
            throw BundleError.unsupportedMediaType("bundle version \(bundleVersion) is not yet supported")
        }
    }

    /// Mirrors `Bundle.Version`.
    public func version() throws -> String {
        try getBundleVersion(protobuf.mediaType)
    }

    /// Mirrors `Bundle.MinVersion`.
    public func minVersion(_ expectVersion: String) -> Bool {
        guard let v = try? version() else { return false }
        let expect = expectVersion.hasPrefix("v") ? expectVersion : "v" + expectVersion
        return semverCompare(v, expect) >= 0
    }

    // MARK: SignedEntity

    public func verificationContent() throws -> any VerificationContent {
        guard protobuf.hasVerificationMaterial else { throw BundleError.missingVerificationMaterial }
        switch protobuf.verificationMaterial.content {
        case .x509CertificateChain(let chain):
            let certs = chain.certificates
            guard let first = certs.first, !first.rawBytes.isEmpty else {
                throw BundleError.missingVerificationMaterial
            }
            let parsed: X509.Certificate
            do {
                parsed = try X509.Certificate(derEncoded: Array(first.rawBytes))
            } catch {
                throw BundleError.validation("\(error)")
            }
            var intermediates: [X509.Certificate] = []
            if allowCertificateChain {
                intermediates = try parseIntermediateCertificates(Array(certs.dropFirst()))
            }
            return Certificate(certificate: parsed, intermediates: intermediates)
        case .certificate(let cert):
            guard !cert.rawBytes.isEmpty else { throw BundleError.missingVerificationMaterial }
            do {
                return Certificate(certificate: try X509.Certificate(derEncoded: Array(cert.rawBytes)))
            } catch {
                throw BundleError.validation("\(error)")
            }
        case .publicKey(let pk):
            return PublicKey(hint: pk.hint)
        case nil:
            throw BundleError.missingVerificationMaterial
        }
    }

    public func tlogEntries() throws -> [Entry] {
        guard protobuf.hasVerificationMaterial else { throw BundleError.missingVerificationMaterial }
        let raw = protobuf.verificationMaterial.tlogEntries
        if raw.count > maxAllowedTlogEntries {
            throw BundleError.validation("too many tlog entries: \(raw.count) > \(maxAllowedTlogEntries)")
        }
        return try raw.map { tle in
            do {
                return try parseTransparencyLogEntry(tle)
            } catch {
                throw BundleError.validation("\(error)")
            }
        }
    }

    public func signatureContent() throws -> any SignatureContent {
        switch protobuf.content {
        case .dsseEnvelope(let env):
            return try parseEnvelope(env)
        case .messageSignature(let ms):
            guard ms.hasMessageDigest else { throw BundleError.missingVerificationMaterial }
            return MessageSignature(
                digest: ms.messageDigest.digest,
                digestAlgorithm: hashAlgorithmName(ms.messageDigest.algorithm),
                signature: ms.signature
            )
        case nil:
            throw BundleError.missingVerificationMaterial
        }
    }

    /// Mirrors `Bundle.Envelope`.
    public func envelope() throws -> Envelope {
        guard case .dsseEnvelope(let env) = protobuf.content else {
            throw BundleError.missingVerificationMaterial
        }
        return try parseEnvelope(env)
    }

    public func timestamps() throws -> [Data] {
        guard protobuf.hasVerificationMaterial else { throw BundleError.missingVerificationMaterial }
        let vm = protobuf.verificationMaterial
        guard vm.hasTimestampVerificationData else { return [] }
        return vm.timestampVerificationData.rfc3161Timestamps.map(\.signedTimestamp)
    }
}

/// Mirrors `MediaTypeString`.
public func mediaTypeString(_ version: String) throws -> String {
    guard !version.isEmpty else {
        throw SigstoreError("unable to build media type string, no version defined")
    }
    let v = version.hasPrefix("v") ? String(version.dropFirst()) : version
    var mt = "\(mediaTypeBase).v\(v)+json"
    if v == "0.1" || v == "0.2" {
        mt = "\(mediaTypeBase)+json;version=\(v)"
    }
    do {
        _ = try getBundleVersion(mt)
    } catch {
        throw error.wrapped("unable to build mediatype")
    }
    return mt
}

func getBundleVersion(_ mediaType: String) throws -> String {
    switch mediaType {
    case mediaTypeBase + "+json;version=0.1": return "v0.1"
    case mediaTypeBase + "+json;version=0.2": return "v0.2"
    case mediaTypeBase + "+json;version=0.3": return "v0.3"
    default: break
    }
    let prefix = mediaTypeBase + ".v"
    if mediaType.hasPrefix(prefix) && mediaType.hasSuffix("+json") {
        let version = String(mediaType.dropFirst(mediaTypeBase.count + 1).dropLast("+json".count))
        if semverIsValid(version) {
            return version
        }
        throw BundleError.unsupportedMediaType("invalid bundle version: \(version)")
    }
    throw BundleError.unsupportedMediaType(mediaType)
}

func validateBundle(_ b: Dev_Sigstore_Bundle_V1_Bundle) throws {
    guard b.content != nil else { throw BundleError.missingBundleContent }
    guard b.hasVerificationMaterial, b.verificationMaterial.content != nil else {
        throw BundleError.missingVerificationMaterial
    }
}

func parseEnvelope(_ input: Io_Intoto_Envelope) throws -> Envelope {
    guard !input.payload.isEmpty else { throw BundleError.missingEnvelope }
    return Envelope(
        DSSEEnvelope(
            payloadType: input.payloadType,
            payload: input.payload,
            signatures: input.signatures.map { DSSEEnvelope.Signature(keyID: $0.keyid, sig: $0.sig) }
        ))
}

func parseIntermediateCertificates(_ raw: [Dev_Sigstore_Common_V1_X509Certificate]) throws -> [X509.Certificate] {
    var out: [X509.Certificate] = []
    for cert in raw {
        guard !cert.rawBytes.isEmpty else { throw BundleError.missingVerificationMaterial }
        let parsed: X509.Certificate
        do {
            parsed = try X509.Certificate(derEncoded: Array(cert.rawBytes))
        } catch {
            throw BundleError.validation("\(error)")
        }
        if parsed.issuer == parsed.subject && parsed.publicKey.isValidSignature(parsed.signature, for: parsed) {
            throw BundleError.validation("self-signed certificate found in certificate chain")
        }
        guard case .isCertificateAuthority = try? parsed.extensions.basicConstraints else {
            throw BundleError.validation("non-CA certificate found in certificate chain")
        }
        out.append(parsed)
    }
    return out
}

/// protobuf-specs `HashAlgorithm` enum names (Go `HashAlgorithm_name`).
func hashAlgorithmName(_ alg: Dev_Sigstore_Common_V1_HashAlgorithm) -> String {
    switch alg {
    case .unspecified: return "HASH_ALGORITHM_UNSPECIFIED"
    case .sha2256: return "SHA2_256"
    case .sha2384: return "SHA2_384"
    case .sha2512: return "SHA2_512"
    case .sha3256: return "SHA3_256"
    case .sha3384: return "SHA3_384"
    case .UNRECOGNIZED: return ""
    }
}

// MARK: - Minimal golang.org/x/mod/semver (vMAJOR[.MINOR[.PATCH]] only).

func semverParse(_ v: String) -> [Int]? {
    guard v.hasPrefix("v") else { return nil }
    let parts = v.dropFirst().split(separator: ".", omittingEmptySubsequences: false)
    guard (1...3).contains(parts.count) else { return nil }
    var nums: [Int] = []
    for p in parts {
        guard !p.isEmpty, p.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        if p.count > 1 && p.first == "0" { return nil }
        guard let n = Int(p) else { return nil }
        nums.append(n)
    }
    while nums.count < 3 { nums.append(0) }
    return nums
}

func semverIsValid(_ v: String) -> Bool { semverParse(v) != nil }

/// Invalid versions sort before all valid ones, and are equal to each other.
func semverCompare(_ a: String, _ b: String) -> Int {
    switch (semverParse(a), semverParse(b)) {
    case (nil, nil): return 0
    case (nil, _): return -1
    case (_, nil): return 1
    case (let x?, let y?):
        for (p, q) in zip(x, y) where p != q { return p < q ? -1 : 1 }
        return 0
    }
}
