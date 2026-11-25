// Port of sigstore-go pkg/root/trusted_root.go (TUF-backed constructors and
// LiveTrustedRoot are pending SigstoreTUF).

import _CryptoExtras
import Foundation
import SigstoreCommon
import SigstoreProtobufSpecs
import SwiftProtobuf
import X509

public let trustedRootMediaType01 = "application/vnd.dev.sigstore.trustedroot+json;version=0.1"

/// Mirrors `root.TransparencyLog` (used for both Rekor and CT logs).
public struct TransparencyLog: Sendable {
    public var baseURL: String
    public var id: Data
    public var validityPeriodStart: Date?
    public var validityPeriodEnd: Date?
    /// Hash used by the log's Merkle tree.
    public var hashFunc: HashFunc
    public var publicKey: Certificate.PublicKey
    /// Hash used when verifying signatures made by `publicKey`.
    public var signatureHashFunc: HashFunc

    public init(
        baseURL: String,
        id: Data,
        validityPeriodStart: Date?,
        validityPeriodEnd: Date?,
        hashFunc: HashFunc,
        publicKey: Certificate.PublicKey,
        signatureHashFunc: HashFunc
    ) {
        self.baseURL = baseURL
        self.id = id
        self.validityPeriodStart = validityPeriodStart
        self.validityPeriodEnd = validityPeriodEnd
        self.hashFunc = hashFunc
        self.publicKey = publicKey
        self.signatureHashFunc = signatureHashFunc
    }
}

/// Mirrors `root.TrustedRoot`.
public struct TrustedRoot: TrustedMaterial {
    public let protobuf: Dev_Sigstore_Trustroot_V1_TrustedRoot?
    public let rekorLogs: [String: TransparencyLog]
    public let fulcioCertificateAuthorities: [any CertificateAuthority]
    public let ctLogs: [String: TransparencyLog]
    public let timestampingAuthorities: [any TimestampingAuthority]

    /// Mirrors `NewTrustedRootFromProtobuf`.
    public init(protobuf: Dev_Sigstore_Trustroot_V1_TrustedRoot) throws {
        guard protobuf.mediaType == trustedRootMediaType01 else {
            throw SigstoreError("unsupported TrustedRoot media type: \(protobuf.mediaType)")
        }
        self.protobuf = protobuf
        self.rekorLogs = try parseTransparencyLogs(protobuf.tlogs)
        self.fulcioCertificateAuthorities = try parseCertificateAuthorities(protobuf.certificateAuthorities)
        self.timestampingAuthorities = try parseTimestampingAuthorities(protobuf.timestampAuthorities)
        self.ctLogs = try parseTransparencyLogs(protobuf.ctlogs)
    }

    /// Mirrors `NewTrustedRootFromJSON`.
    public init(json: Data) throws {
        try self.init(protobuf: newTrustedRootProtobuf(json))
    }

    /// Mirrors `NewTrustedRootFromPath`.
    public init(path: String) throws {
        let data: Data
        do {
            data = try Data(contentsOf: URL(fileURLWithPath: path))
        } catch {
            throw SigstoreError("failed to read trusted root", underlying: error)
        }
        try self.init(json: data)
    }

    /// Mirrors `NewTrustedRoot`.
    public init(
        mediaType: String,
        certificateAuthorities: [any CertificateAuthority],
        certificateTransparencyLogs: [String: TransparencyLog],
        timestampAuthorities: [any TimestampingAuthority],
        transparencyLogs: [String: TransparencyLog]
    ) throws {
        guard mediaType == trustedRootMediaType01 else {
            throw SigstoreError(
                "unsupported TrustedRoot media type: \(mediaType), must be \(trustedRootMediaType01)"
            )
        }
        self.protobuf = nil
        self.fulcioCertificateAuthorities = certificateAuthorities
        self.ctLogs = certificateTransparencyLogs
        self.timestampingAuthorities = timestampAuthorities
        self.rekorLogs = transparencyLogs
    }

    /// The Sigstore public-good `trusted_root.json` embedded in this package
    /// (no Go equivalent; sigstore-go fetches it via TUF). Until SigstoreTUF
    /// exists, callers must update the package to pick up key rotations.
    public static func embeddedPublicGood() throws -> TrustedRoot {
        guard let url = Bundle.module.url(forResource: "trusted_root", withExtension: "json") else {
            throw SigstoreError("embedded trusted_root.json not found")
        }
        return try TrustedRoot(json: Data(contentsOf: url))
    }
}

/// Mirrors `NewTrustedRootProtobuf`.
public func newTrustedRootProtobuf(_ rootJSON: Data) throws -> Dev_Sigstore_Trustroot_V1_TrustedRoot {
    do {
        return try Dev_Sigstore_Trustroot_V1_TrustedRoot(jsonUTF8Data: ProtoJSON.normalizeBytesFields(rootJSON))
    } catch {
        throw SigstoreError("failed to proto-json unmarshal trusted root", underlying: error)
    }
}

/// Mirrors `ParseTransparencyLogs`.
public func parseTransparencyLogs(
    _ tlogs: [Dev_Sigstore_Trustroot_V1_TransparencyLogInstance]
) throws -> [String: TransparencyLog] {
    var out: [String: TransparencyLog] = [:]
    for tlog in tlogs {
        guard tlog.hashAlgorithm == .sha2256 else {
            throw SigstoreError("unsupported tlog hash algorithm: \(tlog.hashAlgorithm)")
        }
        guard tlog.hasLogID else { throw SigstoreError("tlog missing log ID") }
        guard !tlog.logID.keyID.isEmpty else { throw SigstoreError("tlog missing log ID key ID") }
        let encodedKeyID = Hex.encode(tlog.logID.keyID)
        guard tlog.hasPublicKey else { throw SigstoreError("tlog missing public key") }
        guard tlog.publicKey.hasRawBytes else { throw SigstoreError("tlog missing public key raw bytes") }

        let raw = Array(tlog.publicKey.rawBytes)
        let parse = { () throws -> Certificate.PublicKey in
            do {
                return try Certificate.PublicKey(derEncoded: raw)
            } catch {
                throw SigstoreError("failed to parse public key for tlog: \(tlog.baseURL)", underlying: error)
            }
        }
        let key: Certificate.PublicKey
        switch tlog.publicKey.keyDetails {
        case .pkixEcdsaP256Sha256, .pkixEcdsaP384Sha384, .pkixEcdsaP521Sha512:
            key = try parse()
            let v = try SignatureVerifier(publicKey: key)
            switch v.key {
            case .ecdsaP256, .ecdsaP384, .ecdsaP521: break
            default: throw SigstoreError("tlog public key is not ECDSA: \(tlog.publicKey.keyDetails)")
            }
        case .pkixRsaPkcs1V152048Sha256, .pkixRsaPkcs1V153072Sha256, .pkixRsaPkcs1V154096Sha256:
            key = try parse()
            guard case .rsaPKCS1v15 = try SignatureVerifier(publicKey: key).key else {
                throw SigstoreError("tlog public key is not RSA: \(tlog.publicKey.keyDetails)")
            }
        case .pkixEd25519:
            key = try parse()
            guard try SignatureVerifier(publicKey: key).isEd25519 else {
                throw SigstoreError("tlog public key is not Ed25519: \(tlog.publicKey.keyDetails)")
            }
        case .pkcs1RsaPkcs1V5:
            // Deprecated raw PKCS#1 RSAPublicKey (Go x509.ParsePKCS1PublicKey).
            do {
                key = Certificate.PublicKey(try _RSA.Signing.PublicKey(derRepresentation: raw))
            } catch {
                throw SigstoreError("failed to parse public key for tlog: \(tlog.baseURL)", underlying: error)
            }
        default:
            // TODO: ML_DSA_44 as in sigstore-go.
            throw SigstoreError("unsupported tlog public key type: \(tlog.publicKey.keyDetails)")
        }

        guard tlog.publicKey.hasValidFor else {
            throw SigstoreError("tlog missing public key validity period")
        }
        let validFor = tlog.publicKey.validFor
        guard validFor.hasStart else {
            throw SigstoreError("tlog missing public key validity period start time")
        }

        out[encodedKeyID] = TransparencyLog(
            baseURL: tlog.baseURL,
            id: tlog.logID.keyID,
            validityPeriodStart: validFor.start.date,
            validityPeriodEnd: validFor.hasEnd ? validFor.end.date : nil,
            hashFunc: .sha256,
            publicKey: key,
            signatureHashFunc: SignatureVerifier.defaultHashFunc(for: key)
        )
    }
    return out
}

/// Mirrors `ParseCertificateAuthorities`.
public func parseCertificateAuthorities(
    _ cas: [Dev_Sigstore_Trustroot_V1_CertificateAuthority]
) throws -> [any CertificateAuthority] {
    try cas.map { try parseCertificateAuthority($0) }
}

/// Mirrors `ParseCertificateAuthority`. The last certificate of the chain is
/// the root; the others are intermediates.
public func parseCertificateAuthority(
    _ ca: Dev_Sigstore_Trustroot_V1_CertificateAuthority
) throws -> FulcioCertificateAuthority {
    guard ca.hasCertChain else { throw SigstoreError("CertificateAuthority missing cert chain") }
    let certs = ca.certChain.certificates
    guard !certs.isEmpty else { throw SigstoreError("CertificateAuthority cert chain is empty") }
    var parsed: [Certificate] = []
    for cert in certs {
        do {
            parsed.append(try Certificate(derEncoded: Array(cert.rawBytes)))
        } catch {
            throw SigstoreError("failed to parse certificate for \(ca.uri)", underlying: error)
        }
    }
    return FulcioCertificateAuthority(
        root: parsed[parsed.count - 1],
        intermediates: Array(parsed.dropLast()),
        validityPeriodStart: ca.hasValidFor && ca.validFor.hasStart ? ca.validFor.start.date : nil,
        validityPeriodEnd: ca.hasValidFor && ca.validFor.hasEnd ? ca.validFor.end.date : nil,
        uri: ca.uri
    )
}

/// Mirrors `ParseTimestampingAuthorities`.
public func parseTimestampingAuthorities(
    _ cas: [Dev_Sigstore_Trustroot_V1_CertificateAuthority]
) throws -> [any TimestampingAuthority] {
    try cas.map { try parseTimestampingAuthority($0) }
}

/// Mirrors `ParseTimestampingAuthority`.
public func parseTimestampingAuthority(
    _ ca: Dev_Sigstore_Trustroot_V1_CertificateAuthority
) throws -> SigstoreTimestampingAuthority {
    guard ca.hasCertChain else { throw SigstoreError("CertificateAuthority missing cert chain") }
    let certs = ca.certChain.certificates
    guard !certs.isEmpty else { throw SigstoreError("CertificateAuthority cert chain is empty") }
    var tsa = SigstoreTimestampingAuthority(uri: ca.uri)
    for (i, raw) in certs.enumerated() {
        let cert: Certificate
        do {
            cert = try Certificate(derEncoded: Array(raw.rawBytes))
        } catch {
            throw SigstoreError("failed to parse certificate for \(ca.uri)", underlying: error)
        }
        let isCA: Bool
        if case .isCertificateAuthority = try? cert.extensions.basicConstraints { isCA = true } else { isCA = false }
        if i == 0 && !isCA {
            tsa.leaf = cert
        } else if i < certs.count - 1 {
            tsa.intermediates.append(cert)
        } else if i == certs.count - 1 {
            tsa.root = cert
        }
    }
    if ca.hasValidFor {
        if ca.validFor.hasStart { tsa.validityPeriodStart = ca.validFor.start.date }
        if ca.validFor.hasEnd { tsa.validityPeriodEnd = ca.validFor.end.date }
    }
    return tsa
}
