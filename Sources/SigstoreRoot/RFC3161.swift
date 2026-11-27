// RFC 3161 timestamp response verification.
//
// Port of the code sigstore-go v1.4.1 relies on, at the versions it pins:
// - sigstore/timestamp-authority v2.2.0 pkg/verification/verify.go
//   (`VerifyTimestampResponse`), as `TSAVerification`;
// - github.com/digitorus/timestamp 220c5c2851b7 (`ParseResponse`, `Parse`),
//   as `RFC3161Timestamp.parseResponse`;
// - github.com/digitorus/pkcs7 05f79448fa77 (`Parse`, `Verify`,
//   `GetOnlySigner`), as `PKCS7SignedData`.
//
// Deviations (see PROGRESS.md → Decisions): signerInfo `sid` must be
// issuerAndSerialNumber (as in pkcs7),
// SHA-1 is rejected outright, and ML-DSA keys are unsupported.

import Crypto
import Foundation
import SigstoreCommon
import SwiftASN1
@_spi(FixedExpiryValidationTime) import X509

// MARK: - OIDs

enum TSAOID {
    static let signedData: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 2]
    static let attributeMessageDigest: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 9, 4]
    static let attributeSigningTime: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 9, 5]

    static let sha1: ASN1ObjectIdentifier = [1, 3, 14, 3, 2, 26]
    static let sha256: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    static let sha384: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 2]
    static let sha512: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 3]

    static let dsa: ASN1ObjectIdentifier = [1, 2, 840, 10040, 4, 1]
    static let dsaSHA1: ASN1ObjectIdentifier = [1, 2, 840, 10040, 4, 3]
    static let ecdsaSHA1: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 1]
    static let ecdsaSHA256: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 2]
    static let ecdsaSHA384: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 3]
    static let ecdsaSHA512: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 4]
    static let ecPublicKey: ASN1ObjectIdentifier = [1, 2, 840, 10045, 2, 1]
    static let ecP256: ASN1ObjectIdentifier = [1, 2, 840, 10045, 3, 1, 7]
    static let ecP384: ASN1ObjectIdentifier = [1, 3, 132, 0, 34]
    static let ecP521: ASN1ObjectIdentifier = [1, 3, 132, 0, 35]
    static let rsa: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 1]
    static let rsaSHA1: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 5]
    static let rsaSHA256: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 11]
    static let rsaSHA384: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 12]
    static let rsaSHA512: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 13]
    static let ed25519: ASN1ObjectIdentifier = [1, 3, 101, 112]

    /// timestamp-authority pkg/x509 `PolicyOID` / `PolicyOIDPQC`.
    static let sigstorePolicy: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 2]
    static let sigstorePolicyPQC: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 2, 1]
}

// MARK: - Parsed timestamp (digitorus/timestamp)

/// Hash algorithm of a TSTInfo message imprint.
public enum TSAHashAlgorithm: Sendable, Hashable {
    case sha1, sha256, sha384, sha512

    init?(oid: ASN1ObjectIdentifier) {
        switch oid {
        case TSAOID.sha1: self = .sha1
        case TSAOID.sha256: self = .sha256
        case TSAOID.sha384: self = .sha384
        case TSAOID.sha512: self = .sha512
        default: return nil
        }
    }
}

/// Mirrors digitorus `timestamp.Timestamp` (the fields sigstore uses).
public struct RFC3161Timestamp: Sendable {
    public var rawToken: [UInt8]
    public var hashAlgorithm: TSAHashAlgorithm
    public var hashedMessage: [UInt8]
    public var time: Date
    public var policy: ASN1ObjectIdentifier
    /// DER INTEGER content bytes, if present.
    public var nonce: ArraySlice<UInt8>?
    public var certificates: [Certificate]

    /// Mirrors `timestamp.ParseResponse`: `bytes` is a DER TimeStampResp
    /// (RFC 3161 §2.4.2), as carried in a bundle's `signedTimestamp`.
    ///
    /// As in Go (`asn1.Unmarshal` into a struct with a `RawValue` token), the
    /// response and its status are DER, while the TimeStampToken is taken as
    /// a raw TLV without decoding its contents; `parse(token:)` then accepts
    /// BER there (pkcs7 `ber2der`). Stricter than Go: elements after the
    /// token are rejected (Go ignores them).
    public static func parseResponse(_ bytes: [UInt8]) throws -> RFC3161Timestamp {
        let (response, trailing) = try DERHeader.read(bytes[...])
        guard trailing.isEmpty else { throw SigstoreError("trailing data in Time-Stamp response") }
        guard response.identifier.elementsEqual([0x30]) else {
            throw SigstoreError("asn1: structure error: Time-Stamp response is not a SEQUENCE")
        }
        let (statusTLV, afterStatus) = try DERHeader.read(response.content)
        let statusNode = try asn1 { try DER.parse(statusTLV.full) }
        let (status, statusStrings) = try asn1 {
            try DER.sequence(statusNode, identifier: .sequence) { s in
                let status = try Int(derEncoded: &s)
                var strings: [String] = []
                if let free = optionalNode(&s, .sequence) {
                    strings = try DER.sequence(of: ASN1UTF8String.self, identifier: .sequence, rootNode: free)
                        .map(String.init)
                }
                _ = optionalNode(&s, .bitString)  // failInfo
                return (status, strings)
            }
        }
        // digitorus rejects grantedWithMods (1) too.
        if status > 0 {
            throw SigstoreError("timestamp response status \(status): \(statusStrings.joined(separator: ","))")
        }
        guard !afterStatus.isEmpty else { throw SigstoreError("no pkcs7 data in Time-Stamp response") }
        let (token, afterToken) = try DERHeader.read(afterStatus)
        guard !token.content.isEmpty else { throw SigstoreError("no pkcs7 data in Time-Stamp response") }
        guard afterToken.isEmpty else {
            throw SigstoreError("asn1: structure error: unexpected data after the TimeStampToken")
        }
        return try parse(token: Array(token.full))
    }

    /// Mirrors `timestamp.Parse`: parses a TimeStampToken (CMS ContentInfo).
    /// When the token embeds certificates the CMS signature is checked
    /// against them (no chain validation), as digitorus does.
    public static func parse(token bytes: [UInt8]) throws -> RFC3161Timestamp {
        let p7 = try PKCS7SignedData.parse(bytes)
        if !p7.certificates.isEmpty {
            try p7.verify()
        }
        let info = try TSTInfo(derEncoded: p7.content)
        guard !info.hashedMessage.isEmpty else {
            throw SigstoreError("Time-Stamp response contains no hashed message")
        }
        guard let alg = TSAHashAlgorithm(oid: info.hashAlgorithm) else {
            throw SigstoreError("Time-Stamp response uses unknown hash function")
        }
        return RFC3161Timestamp(
            rawToken: bytes, hashAlgorithm: alg, hashedMessage: info.hashedMessage, time: info.genTime,
            policy: info.policy, nonce: info.nonce, certificates: p7.certificates)
    }
}

/// RFC 3161 §2.4.2 TSTInfo (the fields digitorus decodes).
struct TSTInfo {
    var policy: ASN1ObjectIdentifier
    var hashAlgorithm: ASN1ObjectIdentifier
    var hashedMessage: [UInt8]
    var genTime: Date
    var nonce: ArraySlice<UInt8>?

    init(derEncoded bytes: [UInt8]) throws {
        let root = try asn1 { try DER.parse(bytes) }
        self = try asn1 {
            try DER.sequence(root, identifier: .sequence) { n in
                _ = try Int(derEncoded: &n)  // version
                let policy = try ASN1ObjectIdentifier(derEncoded: &n)
                let (alg, hashed) = try DER.sequence(n.nextOrThrow(), identifier: .sequence) { m in
                    let alg = try AlgorithmIdentifierNode(&m)
                    return (alg.oid, try ASN1OctetString(derEncoded: &m).bytes)
                }
                _ = try rawInteger(n.nextOrThrow())  // serialNumber
                let genTime = try GeneralizedTime(derEncoded: &n)
                _ = optionalNode(&n, .sequence)  // accuracy
                if let ordering = optionalNode(&n, .boolean) { _ = try Bool(derEncoded: ordering) }
                let nonce = try optionalNode(&n, .integer).map(rawInteger)
                _ = optionalNode(&n, ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific))  // tsa
                _ = optionalNode(&n, ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific))  // extensions
                return TSTInfo(
                    policy: policy, hashAlgorithm: alg, hashedMessage: Array(hashed),
                    genTime: Date(generalizedTime: genTime), nonce: nonce)
            }
        }
    }

    init(
        policy: ASN1ObjectIdentifier, hashAlgorithm: ASN1ObjectIdentifier, hashedMessage: [UInt8], genTime: Date,
        nonce: ArraySlice<UInt8>?
    ) {
        self.policy = policy
        self.hashAlgorithm = hashAlgorithm
        self.hashedMessage = hashedMessage
        self.genTime = genTime
        self.nonce = nonce
    }
}

// MARK: - CMS SignedData (digitorus/pkcs7)

struct AlgorithmIdentifierNode {
    var oid: ASN1ObjectIdentifier
    var parameters: ASN1Node?

    init(_ nodes: inout ASN1NodeCollection.Iterator) throws {
        self = try DER.sequence(nodes.nextOrThrow(), identifier: .sequence) { a in
            let oid = try ASN1ObjectIdentifier(derEncoded: &a)
            return AlgorithmIdentifierNode(oid: oid, parameters: a.next())
        }
    }

    init(oid: ASN1ObjectIdentifier, parameters: ASN1Node?) {
        self.oid = oid
        self.parameters = parameters
    }

    /// pkcs7 `algorithmIdentifierParametersAbsentOrNull`.
    var parametersAbsentOrNull: Bool {
        guard let parameters else { return true }
        return parameters.identifier == .null && parameters.encodedBytes.count == 2
    }
}

struct CMSAttributeNode {
    var type: ASN1ObjectIdentifier
    var values: [ASN1Node]
}

struct CMSSignerInfo {
    /// DER encoding of the sid issuer Name.
    var issuer: ArraySlice<UInt8>
    /// DER INTEGER content bytes of the sid serial number.
    var serialNumber: ArraySlice<UInt8>
    var digestAlgorithm: AlgorithmIdentifierNode
    var authenticatedAttributes: [CMSAttributeNode]
    /// The signed attributes as the DER SET OF the signature covers
    /// (RFC 5652 §5.4), built as pkcs7 `marshalAttributes` does.
    var authenticatedAttributesDER: [UInt8]
    var digestEncryptionAlgorithm: AlgorithmIdentifierNode
    var encryptedDigest: [UInt8]

    init(_ node: ASN1Node) throws {
        self = try DER.sequence(node, identifier: .sequence) { n in
            _ = try Int(derEncoded: &n)  // version
            // pkcs7 only supports issuerAndSerialNumber, not subjectKeyIdentifier.
            let (issuer, serial) = try DER.sequence(n.nextOrThrow(), identifier: .sequence) { s in
                let issuer = try s.nextOrThrow()
                guard issuer.identifier == .sequence else { throw ASN1Error.unexpectedFieldType(issuer.identifier) }
                return (issuer.encodedBytes, try rawInteger(s.nextOrThrow()))
            }
            let digestAlgorithm = try AlgorithmIdentifierNode(&n)
            var attributes: [CMSAttributeNode] = []
            var attributesDER: [UInt8] = []
            if let signed = optionalNode(&n, ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)) {
                guard case .constructed(let children) = signed.content else {
                    throw ASN1Error.invalidASN1Object(reason: "signed attributes are not constructed")
                }
                for child in children {
                    attributes.append(
                        try DER.sequence(child, identifier: .sequence) { a in
                            let type = try ASN1ObjectIdentifier(derEncoded: &a)
                            let set = try a.nextOrThrow()
                            guard set.identifier == .set, case .constructed(let values) = set.content else {
                                throw ASN1Error.unexpectedFieldType(set.identifier)
                            }
                            return CMSAttributeNode(type: type, values: Array(values))
                        })
                }
                attributesDER = derSetOf(children.map { Array($0.encodedBytes) })
            }
            let digestEncryptionAlgorithm = try AlgorithmIdentifierNode(&n)
            let encryptedDigest = try ASN1OctetString(derEncoded: &n).bytes
            _ = optionalNode(&n, ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific))  // unsigned attrs
            return CMSSignerInfo(
                issuer: issuer, serialNumber: serial, digestAlgorithm: digestAlgorithm,
                authenticatedAttributes: attributes, authenticatedAttributesDER: attributesDER,
                digestEncryptionAlgorithm: digestEncryptionAlgorithm, encryptedDigest: Array(encryptedDigest))
        }
    }

    init(
        issuer: ArraySlice<UInt8>, serialNumber: ArraySlice<UInt8>, digestAlgorithm: AlgorithmIdentifierNode,
        authenticatedAttributes: [CMSAttributeNode], authenticatedAttributesDER: [UInt8],
        digestEncryptionAlgorithm: AlgorithmIdentifierNode, encryptedDigest: [UInt8]
    ) {
        self.issuer = issuer
        self.serialNumber = serialNumber
        self.digestAlgorithm = digestAlgorithm
        self.authenticatedAttributes = authenticatedAttributes
        self.authenticatedAttributesDER = authenticatedAttributesDER
        self.digestEncryptionAlgorithm = digestEncryptionAlgorithm
        self.encryptedDigest = encryptedDigest
    }

    /// pkcs7 `unmarshalAttribute`: first value of the first matching attribute.
    func attribute(_ type: ASN1ObjectIdentifier) -> ASN1Node? {
        authenticatedAttributes.first { $0.type == type }?.values.first
    }

    /// pkcs7 `isCertMatchForIssuerAndSerial`.
    func matches(_ cert: Certificate) -> Bool {
        guard let raw = try? RawIssuerAndSerial(cert) else { return false }
        return raw.serialNumber == serialNumber && raw.issuer == issuer
    }
}

/// The raw issuer Name and serial INTEGER of a certificate (Go's
/// `RawIssuer` / `SerialNumber`), read from its TBSCertificate.
struct RawIssuerAndSerial {
    var issuer: ArraySlice<UInt8>
    var serialNumber: ArraySlice<UInt8>

    init(_ cert: Certificate) throws {
        let tbs = try DER.parse(cert.tbsCertificateBytes)
        self = try DER.sequence(tbs, identifier: .sequence) { n in
            var node = try n.nextOrThrow()
            if node.identifier == ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific) {
                node = try n.nextOrThrow()  // version
            }
            let serial = try rawInteger(node)
            _ = try n.nextOrThrow()  // signature
            let issuer = try n.nextOrThrow().encodedBytes
            while n.next() != nil {}
            return RawIssuerAndSerial(issuer: issuer, serialNumber: serial)
        }
    }

    init(issuer: ArraySlice<UInt8>, serialNumber: ArraySlice<UInt8>) {
        self.issuer = issuer
        self.serialNumber = serialNumber
    }
}

/// Mirrors pkcs7 `PKCS7` for SignedData content.
struct PKCS7SignedData {
    var content: [UInt8]
    var certificates: [Certificate]
    var signers: [CMSSignerInfo]

    /// Mirrors `pkcs7.Parse` (SignedData only): BER input is transcoded to
    /// DER first (`ber2der`), then parsed as DER.
    static func parse(_ bytes: [UInt8]) throws -> PKCS7SignedData {
        guard !bytes.isEmpty else { throw SigstoreError("pkcs7: input data is empty") }
        let der = try ber2der(bytes)
        let root = try asn1 { try DER.parse(der) }
        return try asn1 {
            try DER.sequence(root, identifier: .sequence) { n in
                let contentType = try ASN1ObjectIdentifier(derEncoded: &n)
                guard contentType == TSAOID.signedData else {
                    throw SigstoreError("pkcs7: cannot parse data: unimplemented content type")
                }
                guard
                    let signedData = try DER.optionalExplicitlyTagged(&n, tagNumber: 0, tagClass: .contextSpecific, {
                        $0
                    })
                else {
                    throw ASN1Error.invalidASN1Object(reason: "missing SignedData content")
                }
                return try parseSignedData(signedData)
            }
        }
    }

    private static func parseSignedData(_ node: ASN1Node) throws -> PKCS7SignedData {
        try DER.sequence(node, identifier: .sequence) { n in
            _ = try Int(derEncoded: &n)  // version
            let digestAlgorithms = try n.nextOrThrow()
            guard digestAlgorithms.identifier == .set else {
                throw ASN1Error.unexpectedFieldType(digestAlgorithms.identifier)
            }
            let content: [UInt8] = try DER.sequence(n.nextOrThrow(), identifier: .sequence) { e in
                _ = try ASN1ObjectIdentifier(derEncoded: &e)  // eContentType
                let eContent = try DER.optionalExplicitlyTagged(&e, tagNumber: 0, tagClass: .contextSpecific) {
                    try ASN1OctetString(derEncoded: $0).bytes
                }
                return eContent.map(Array.init) ?? []
            }
            var certificates: [Certificate] = []
            if let certs = optionalNode(&n, ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)) {
                guard case .constructed(let children) = certs.content else {
                    throw ASN1Error.invalidASN1Object(reason: "certificates are not constructed")
                }
                certificates = try children.map { try Certificate(derEncoded: $0) }
            }
            _ = optionalNode(&n, ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific))  // crls
            let signerInfos = try n.nextOrThrow()
            guard signerInfos.identifier == .set, case .constructed(let infos) = signerInfos.content else {
                throw ASN1Error.unexpectedFieldType(signerInfos.identifier)
            }
            return PKCS7SignedData(
                content: content, certificates: certificates, signers: try infos.map { try CMSSignerInfo($0) })
        }
    }

    /// Mirrors `PKCS7.Verify()`: checks every signer's signature against the
    /// embedded certificates, without chain validation.
    func verify() throws {
        guard !signers.isEmpty else { throw SigstoreError("pkcs7: Message has no signers") }
        for signer in signers {
            try verifySignature(signer)
        }
    }

    /// Mirrors pkcs7 `verifySignature` with no trust store.
    private func verifySignature(_ signer: CMSSignerInfo) throws {
        guard let ee = certificates.first(where: signer.matches) else {
            throw SigstoreError("pkcs7: No certificate for signer")
        }
        var signedData = content
        if !signer.authenticatedAttributes.isEmpty {
            guard let digestNode = signer.attribute(TSAOID.attributeMessageDigest) else {
                throw SigstoreError("pkcs7: attribute type not in attributes")
            }
            let digest = try asn1 { try ASN1OctetString(derEncoded: digestNode).bytes }
            let computed = try digestForOID(signer.digestAlgorithm.oid, content)
            guard constantTimeEqual(Array(digest), computed) else {
                throw SigstoreError("pkcs7: Message digest mismatch")
            }
            signedData = signer.authenticatedAttributesDER
            if let timeNode = signer.attribute(TSAOID.attributeSigningTime), let signingTime = parseTime(timeNode) {
                if signingTime > ee.notValidAfter || signingTime < ee.notValidBefore {
                    throw SigstoreError("pkcs7: signing time \(signingTime) is outside of certificate validity")
                }
            }
        }
        let algorithm = try signatureAlgorithm(signer.digestEncryptionAlgorithm, signer.digestAlgorithm)
        guard ee.publicKey.isValidSignature(signer.encryptedDigest, for: signedData, signatureAlgorithm: algorithm)
        else {
            throw SigstoreError("pkcs7: signature verification failed")
        }
    }

    /// Mirrors `PKCS7.GetOnlySigner`.
    var onlySigner: Certificate? {
        guard signers.count == 1 else { return nil }
        return certificates.first(where: signers[0].matches)
    }
}

/// pkcs7 `getHashForOID`, then hashes `data`. SHA-1 (which Go maps but
/// x509 then rejects as insecure) is rejected here.
private func digestForOID(_ oid: ASN1ObjectIdentifier, _ data: [UInt8]) throws -> [UInt8] {
    switch oid {
    case TSAOID.sha256, TSAOID.ecdsaSHA256: return Array(SHA256.hash(data: data))
    case TSAOID.sha384, TSAOID.ecdsaSHA384: return Array(SHA384.hash(data: data))
    case TSAOID.sha512, TSAOID.ecdsaSHA512: return Array(SHA512.hash(data: data))
    case TSAOID.sha1, TSAOID.ecdsaSHA1, TSAOID.dsa, TSAOID.dsaSHA1, TSAOID.rsa:
        throw SigstoreError("pkcs7: SHA-1 digests are insecure and not supported")
    default:
        throw SigstoreError("pkcs7: cannot decrypt data: unsupported algorithm")
    }
}

/// pkcs7 `getSignatureAlgorithm` (without ML-DSA); SHA-1 variants are
/// rejected as Go's `x509.CheckSignature` does.
private func signatureAlgorithm(
    _ encryption: AlgorithmIdentifierNode, _ digest: AlgorithmIdentifierNode
) throws -> Certificate.SignatureAlgorithm {
    func ecdsa() throws -> Certificate.SignatureAlgorithm {
        switch digest.oid {
        case TSAOID.sha256: return .ecdsaWithSHA256
        case TSAOID.sha384: return .ecdsaWithSHA384
        case TSAOID.sha512: return .ecdsaWithSHA512
        case TSAOID.sha1: throw SigstoreError("x509: insecure algorithm ECDSA-SHA1")
        default: throw SigstoreError("pkcs7: unsupported digest \(digest.oid) for signature algorithm \(encryption.oid)")
        }
    }
    switch encryption.oid {
    case TSAOID.ecdsaSHA1: throw SigstoreError("x509: insecure algorithm ECDSA-SHA1")
    case TSAOID.ecdsaSHA256: return .ecdsaWithSHA256
    case TSAOID.ecdsaSHA384: return .ecdsaWithSHA384
    case TSAOID.ecdsaSHA512: return .ecdsaWithSHA512
    case TSAOID.ecPublicKey:
        guard encryption.parametersAbsentOrNull else {
            throw SigstoreError("pkcs7: id-ecPublicKey AlgorithmIdentifier parameters must be absent or NULL")
        }
        return try ecdsa()
    case TSAOID.rsa, TSAOID.rsaSHA1, TSAOID.rsaSHA256, TSAOID.rsaSHA384, TSAOID.rsaSHA512:
        switch digest.oid {
        case TSAOID.sha256: return .sha256WithRSAEncryption
        case TSAOID.sha384: return .sha384WithRSAEncryption
        case TSAOID.sha512: return .sha512WithRSAEncryption
        case TSAOID.sha1: throw SigstoreError("x509: insecure algorithm SHA1-RSA")
        default:
            throw SigstoreError("pkcs7: unsupported digest \(digest.oid) for encryption algorithm \(encryption.oid)")
        }
    case TSAOID.dsa, TSAOID.dsaSHA1:
        throw SigstoreError("pkcs7: DSA signature verification is not supported")
    case TSAOID.ecP256, TSAOID.ecP384, TSAOID.ecP521:
        return try ecdsa()
    case TSAOID.ed25519:
        return .ed25519
    default:
        throw SigstoreError("pkcs7: unsupported algorithm \(encryption.oid)")
    }
}

// MARK: - Verification (timestamp-authority pkg/verification)

/// Mirrors timestamp-authority `pkg/verification`.
public enum TSAVerification {
    /// Mirrors `verification.VerifyOpts` (without `OID`, `Nonce` and
    /// `CommonName`, which sigstore-go does not set).
    public struct VerifyOpts: Sendable {
        public var tsaCertificate: Certificate?
        public var intermediates: [Certificate]
        public var roots: [Certificate]
        /// Chain validation time; defaults to the timestamp's own time.
        public var currentTime: Date?

        public init(
            tsaCertificate: Certificate? = nil, intermediates: [Certificate] = [], roots: [Certificate],
            currentTime: Date? = nil
        ) {
            self.tsaCertificate = tsaCertificate
            self.intermediates = intermediates
            self.roots = roots
            self.currentTime = currentTime
        }
    }

    /// Mirrors `VerifyTimestampResponse`: parses `tsrBytes` (a DER
    /// TimeStampResp), verifies its CMS signature and the signer's chain to
    /// `opts.roots` at the timestamp's time, the RFC 3161 §2.3 leaf rules,
    /// and that the message imprint is the hash of `artifact`.
    /// Revocation is not checked.
    public static func verifyTimestampResponse(
        _ tsrBytes: [UInt8], artifact: [UInt8], opts: VerifyOpts
    ) async throws -> RFC3161Timestamp {
        let ts: RFC3161Timestamp
        do {
            ts = try RFC3161Timestamp.parseResponse(tsrBytes)
        } catch {
            throw SigstoreError("error parsing response into Timestamp", underlying: error)
        }

        switch ts.hashAlgorithm {
        case .sha1: throw SigstoreError("weak hash algorithm: must be SHA-256, SHA-384, or SHA-512")
        case .sha256, .sha384, .sha512: break
        }

        var opts = opts
        if opts.currentTime == nil { opts.currentTime = ts.time }

        let (signerCert, chains) = try await verifyTSRWithChain(ts, opts: opts)
        try verifyPolicyOIDMatchesSignerKeyType(ts.policy)
        try verifyLeafCert(signerCert, chains: chains, opts: opts)
        try verifyHashedMessages(ts.hashAlgorithm, ts.hashedMessage, artifact)
        return ts
    }

    /// Mirrors `verifyTSRWithChain`.
    static func verifyTSRWithChain(
        _ ts: RFC3161Timestamp, opts: VerifyOpts
    ) async throws -> (Certificate, [[Certificate]]) {
        var p7: PKCS7SignedData
        do {
            p7 = try PKCS7SignedData.parse(ts.rawToken)
        } catch {
            throw SigstoreError("error parsing hashed message", underlying: error)
        }
        guard !opts.roots.isEmpty else {
            throw SigstoreError("no root certificates provided for verifying the certificate chain")
        }
        if p7.certificates.isEmpty && opts.tsaCertificate == nil {
            throw SigstoreError("leaf certificate must be present in the TSR or as a verify option")
        }
        let intermediates = opts.intermediates + p7.certificates
        if p7.certificates.isEmpty, let tsaCertificate = opts.tsaCertificate {
            p7.certificates = [tsaCertificate]
        }
        do {
            try p7.verify()
        } catch {
            throw SigstoreError("error while verifying signature", underlying: error)
        }
        guard let signerCert = p7.onlySigner else {
            throw SigstoreError("signer certificate was not found")
        }
        if let tsaCertificate = opts.tsaCertificate, tsaCertificate != signerCert {
            throw SigstoreError("certificate embedded in the TSR does not match the provided TSA certificate")
        }

        let currentTime = opts.currentTime ?? ts.time
        var verifier = Verifier(rootCertificates: CertificateStore(opts.roots)) {
            RFC5280Policy(fixedExpiryValidationTime: currentTime)
            TimestampingPolicy()
        }
        let result = await verifier.validate(leaf: signerCert, intermediates: CertificateStore(intermediates))
        switch result {
        case .validCertificate(let chain):
            return (signerCert, [Array(chain)])
        case .couldNotValidate(let failures):
            let reasons = failures.map { $0.policyFailureReason.description }
            throw SigstoreError(
                "error while verifying signer certificate chain"
                    + (reasons.isEmpty ? "" : ": " + reasons.joined(separator: "; ")))
        }
    }

    /// Mirrors `verifyPolicyOIDMatchesSignerKeyType`. ML-DSA keys cannot be
    /// parsed, so a chain is never ML-DSA and the PQC policy always fails.
    static func verifyPolicyOIDMatchesSignerKeyType(_ policy: ASN1ObjectIdentifier) throws {
        if policy == TSAOID.sigstorePolicyPQC {
            throw SigstoreError(
                "failed to verify policy OID on leaf certificate: policy OID \(policy) requires an ML-DSA certificate chain"
            )
        }
    }

    /// Mirrors `verifyLeafCert`.
    static func verifyLeafCert(_ leaf: Certificate, chains: [[Certificate]], opts: VerifyOpts) throws {
        let errMsg = "failed to verify TSA certificate"
        let basicConstraints = try leaf.extensions.basicConstraints
        if case .isCertificateAuthority = basicConstraints {
            throw SigstoreError("\(errMsg): TSA certificate must be an end-entity certificate, not a CA")
        }
        // RFC 3161 §2.3: the EKU extension must be critical.
        guard leaf.extensions[oid: .X509ExtensionID.extendedKeyUsage]?.critical == true else {
            throw SigstoreError("\(errMsg): certificate must set EKU to critical")
        }
        if let tsaCertificate = opts.tsaCertificate {
            let expected = try RawIssuerAndSerial(tsaCertificate)
            let actual = try RawIssuerAndSerial(leaf)
            guard expected.issuer == actual.issuer else {
                throw SigstoreError("\(errMsg): TSR cert issuer does not match provided TSA cert issuer")
            }
            guard expected.serialNumber == actual.serialNumber else {
                throw SigstoreError("\(errMsg): TSR cert serial number does not match provided TSA cert serial number")
            }
        }
        try verifyLeafAndIntermediatesTimestampingEKU(leaf, chains: chains)
    }

    /// Mirrors `verifyLeafAndIntermediatesTimestampingEKU`: the leaf has
    /// exactly one EKU, timeStamping; intermediates have none or include
    /// timeStamping or anyExtendedKeyUsage.
    static func verifyLeafAndIntermediatesTimestampingEKU(_ leaf: Certificate, chains: [[Certificate]]) throws {
        let prefix = "failed to verify EKU on leaf certificate"
        let eku = try leaf.extensions.extendedKeyUsage
        let count = eku?.count ?? 0
        guard count == 1 else {
            throw SigstoreError("\(prefix): certificate has \(count) extended key usages, expected only one")
        }
        guard eku?.contains(.timeStamping) == true else {
            throw SigstoreError("\(prefix): leaf certificate EKU is not set to TimeStamping as required")
        }
        var lastError: String?
        for chain in chains {
            var chainOK = true
            for cert in chain.dropFirst().dropLast() {
                if let eku = try cert.extensions.extendedKeyUsage, eku.count > 0,
                    !(eku.contains(.timeStamping) || eku.contains(.any))
                {
                    chainOK = false
                    lastError = "intermediate certificate does not allow Timestamping usage"
                    break
                }
            }
            if chainOK { return }
        }
        if let lastError {
            throw SigstoreError("\(prefix): no verified certificate chain met EKU requirements: \(lastError)")
        }
    }

    /// Mirrors `verifyHashedMessages`.
    static func verifyHashedMessages(_ alg: TSAHashAlgorithm, _ hashedMessage: [UInt8], _ artifact: [UInt8]) throws {
        let local: [UInt8]
        switch alg {
        case .sha256: local = Array(SHA256.hash(data: artifact))
        case .sha384: local = Array(SHA384.hash(data: artifact))
        case .sha512: local = Array(SHA512.hash(data: artifact))
        case .sha1: throw SigstoreError("weak hash algorithm: must be SHA-256, SHA-384, or SHA-512")
        }
        guard local == hashedMessage else { throw SigstoreError("hashed messages don't match") }
    }
}

/// Requires the timeStamping EKU along the whole chain, as Go's
/// `x509.Certificate.Verify` with `KeyUsages: [ExtKeyUsageTimeStamping]`
/// (`checkChainForKeyUsage` walks every certificate, root included):
/// a certificate with an EKU extension must list timeStamping or
/// anyExtendedKeyUsage. Declares SAN and EKU as handled critical extensions.
struct TimestampingPolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.subjectAlternativeName,
        .X509ExtensionID.extendedKeyUsage,
    ]

    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        for (index, cert) in chain.enumerated() {
            let eku: ExtendedKeyUsage?
            do {
                eku = try cert.extensions.extendedKeyUsage
            } catch {
                return .failsToMeetPolicy(reason: "invalid extended key usage extension: \(error)")
            }
            guard let eku, eku.count > 0 else { continue }
            if !(eku.contains(.timeStamping) || eku.contains(.any)) {
                return .failsToMeetPolicy(
                    reason: "certificate at chain position \(index) does not permit time stamping")
            }
        }
        return .meetsPolicy
    }
}

// MARK: - Helpers

/// Wraps ASN.1 decoding errors so callers see a SigstoreError.
private func asn1<T>(_ body: () throws -> T) throws -> T {
    do {
        return try body()
    } catch let error as SigstoreError {
        throw error
    } catch {
        throw SigstoreError("asn1: \(error)")
    }
}

/// The content bytes of a DER INTEGER of any sign (Go's `big.Int`
/// decoding), rejecting non-minimal encodings as encoding/asn1 does.
/// Mirrors pkcs7 `marshalAttributes`, which re-marshals the parsed signed
/// attributes with Go's `asn1.Marshal` (`asn1:"set"`): a SET OF whose
/// elements are sorted by their encodings with `bytes.Compare` (Go's
/// `setEncoder`, X.690 §11.6). Each element is an attribute's TLV; Go
/// re-encodes the attribute from its parsed OID (canonical, so the same
/// bytes) and its value's raw bytes, so the TLV is what Go writes.
func derSetOf(_ elements: [[UInt8]]) -> [UInt8] {
    let body = elements.sorted { $0.lexicographicallyPrecedes($1) }.flatMap { $0 }
    var out: [UInt8] = [0x31]
    if body.count < 0x80 {
        out.append(UInt8(body.count))
    } else {
        var lengthBytes: [UInt8] = []
        var n = body.count
        while n > 0 {
            lengthBytes.insert(UInt8(truncatingIfNeeded: n), at: 0)
            n >>= 8
        }
        out.append(0x80 | UInt8(lengthBytes.count))
        out += lengthBytes
    }
    return out + body
}

func rawInteger(_ node: ASN1Node) throws -> ArraySlice<UInt8> {
    guard node.identifier == .integer, case .primitive(let bytes) = node.content else {
        throw ASN1Error.unexpectedFieldType(node.identifier)
    }
    guard let first = bytes.first else { throw ASN1Error.invalidASN1IntegerEncoding(reason: "empty integer") }
    if bytes.count > 1 {
        let second = bytes[bytes.startIndex + 1]
        if (first == 0x00 && second < 0x80) || (first == 0xFF && second >= 0x80) {
            throw ASN1Error.invalidASN1IntegerEncoding(reason: "integer not minimally-encoded")
        }
    }
    return bytes
}

/// Returns the next node if it has `identifier`, without consuming otherwise.
private func optionalNode(_ nodes: inout ASN1NodeCollection.Iterator, _ identifier: ASN1Identifier) -> ASN1Node? {
    var copy = nodes
    guard let node = copy.next(), node.identifier == identifier else { return nil }
    nodes = copy
    return node
}

extension ASN1NodeCollection.Iterator {
    fileprivate mutating func nextOrThrow() throws -> ASN1Node {
        guard let node = next() else { throw ASN1Error.invalidASN1Object(reason: "missing field") }
        return node
    }
}

/// A UTCTime or GeneralizedTime attribute value, as Go's `time.Time`
/// unmarshalling accepts; nil when it is neither.
private func parseTime(_ node: ASN1Node) -> Date? {
    if let t = try? GeneralizedTime(derEncoded: node) { return Date(generalizedTime: t) }
    if let t = try? UTCTime(derEncoded: node) {
        return Date(utc: t.year, t.month, t.day, t.hours, t.minutes, t.seconds, 0)
    }
    return nil
}

private func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in a.indices { diff |= a[i] ^ b[i] }
    return diff == 0
}

extension Date {
    init(generalizedTime t: GeneralizedTime) {
        self.init(utc: t.year, t.month, t.day, t.hours, t.minutes, t.seconds, t.fractionalSeconds)
    }

    /// Proleptic Gregorian UTC components to a Date (days-from-civil).
    init(utc year: Int, _ month: Int, _ day: Int, _ hour: Int, _ minute: Int, _ second: Int, _ fraction: Double) {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let mp = (month + 9) % 12
        let doy = (153 * mp + 2) / 5 + day - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        let days = era * 146097 + doe - 719468
        let seconds = days * 86400 + hour * 3600 + minute * 60 + second
        self.init(timeIntervalSince1970: TimeInterval(seconds) + fraction)
    }
}
