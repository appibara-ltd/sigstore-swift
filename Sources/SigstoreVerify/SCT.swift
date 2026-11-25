// Port of sigstore-go pkg/verify/sct.go, plus the parts of
// certificate-transparency-go it relies on (x509util.ParseSCTsFromCertificate,
// ct.MerkleTreeLeafForEmbeddedSCT, ctutil.VerifySCT) per RFC 6962 §3.2/§3.3.

import Crypto
import Foundation
import SigstoreCommon
import SigstoreRoot
import SwiftASN1
import X509

/// OID 1.3.6.1.4.1.11129.2.4.2 (embedded SCT list, RFC 6962 §3.3).
let sctListOID: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 11129, 2, 4, 2]

/// Mirrors `VerifySignedCertificateTimestamp`: at least `threshold` distinct
/// trusted CT logs must have a valid embedded SCT for the leaf.
public func verifySignedCertificateTimestamp(
    chains: [[Certificate]], threshold: Int, trustedMaterial: any TrustedMaterial
) throws {
    guard let leaf = chains.first?.first else {
        throw SigstoreError("no chains provided")
    }
    let ctlogs = trustedMaterial.ctLogs
    let scts = try parseSCTsFromCertificate(leaf)
    let precertTBS = try tbsWithoutSCTList(leaf)

    var verifiedLogs = Set<String>()
    for sct in scts {
        let encodedKeyID = Hex.encode(sct.logID)
        if verifiedLogs.contains(encodedKeyID) { continue }
        guard let key = ctlogs[encodedKeyID] else { continue }

        let sctTime = Date(timeIntervalSince1970: TimeInterval(sct.timestamp) / 1000)
        if let start = key.validityPeriodStart, sctTime < start { continue }
        if let end = key.validityPeriodEnd, sctTime > end { continue }

        for chain in chains {
            guard chain.count >= 2 else { continue }
            let issuerKeyHash = Array(SHA256.hash(data: chain[1].publicKey.pkixBytes))
            if verifySCT(sct, logKey: key, issuerKeyHash: issuerKeyHash, precertTBS: precertTBS) {
                verifiedLogs.insert(encodedKeyID)
                break
            }
        }
    }

    if verifiedLogs.count < threshold {
        throw SigstoreError(
            "only able to verify \(verifiedLogs.count) SCT entries; unable to meet threshold of \(threshold)")
    }
}

struct SignedCertificateTimestamp {
    var version: UInt8
    var logID: [UInt8]
    var timestamp: UInt64
    var extensions: [UInt8]
    var hashAlgorithm: UInt8
    var signatureAlgorithm: UInt8
    var signature: [UInt8]
}

/// Minimal TLS presentation-language reader.
struct TLSReader {
    var bytes: ArraySlice<UInt8>

    mutating func u8() throws -> UInt8 {
        guard let b = bytes.first else { throw SigstoreError("truncated SCT data") }
        bytes = bytes.dropFirst()
        return b
    }

    mutating func uint(_ n: Int) throws -> UInt64 {
        var v: UInt64 = 0
        for _ in 0..<n { v = v << 8 | UInt64(try u8()) }
        return v
    }

    mutating func take(_ n: Int) throws -> ArraySlice<UInt8> {
        guard bytes.count >= n else { throw SigstoreError("truncated SCT data") }
        let out = bytes.prefix(n)
        bytes = bytes.dropFirst(n)
        return out
    }

    mutating func vector(lengthBytes: Int) throws -> ArraySlice<UInt8> {
        try take(Int(try uint(lengthBytes)))
    }
}

/// Mirrors `x509util.ParseSCTsFromCertificate`.
func parseSCTsFromCertificate(_ cert: Certificate) throws -> [SignedCertificateTimestamp] {
    guard let ext = cert.extensions[oid: sctListOID] else { return [] }
    let octets: ASN1OctetString
    do {
        octets = try ASN1OctetString(derEncoded: ext.value)
    } catch {
        throw SigstoreError("failed to parse SCT list extension", underlying: error)
    }
    var outer = TLSReader(bytes: octets.bytes)
    var list = TLSReader(bytes: try outer.vector(lengthBytes: 2))
    guard outer.bytes.isEmpty else { throw SigstoreError("trailing data after SCT list") }
    var out: [SignedCertificateTimestamp] = []
    while !list.bytes.isEmpty {
        var r = TLSReader(bytes: try list.vector(lengthBytes: 2))
        let version = try r.u8()
        guard version == 0 else { throw SigstoreError("unsupported SCT version \(version)") }
        let sct = SignedCertificateTimestamp(
            version: version,
            logID: Array(try r.take(32)),
            timestamp: try r.uint(8),
            extensions: Array(try r.vector(lengthBytes: 2)),
            hashAlgorithm: try r.u8(),
            signatureAlgorithm: try r.u8(),
            signature: Array(try r.vector(lengthBytes: 2))
        )
        guard r.bytes.isEmpty else { throw SigstoreError("trailing data in SCT") }
        out.append(sct)
    }
    return out
}

/// Mirrors ctutil.VerifySCT for an embedded SCT (precert_entry).
func verifySCT(
    _ sct: SignedCertificateTimestamp, logKey: TransparencyLog, issuerKeyHash: [UInt8], precertTBS: [UInt8]
) -> Bool {
    let hash: HashFunc
    switch sct.hashAlgorithm {
    case 4: hash = .sha256
    case 5: hash = .sha384
    case 6: hash = .sha512
    default: return false
    }
    guard let verifier = try? SignatureVerifier(publicKey: logKey.publicKey, hashFunction: hash) else {
        return false
    }
    // RFC 6962 digitally-signed struct for a precert entry.
    var signed: [UInt8] = []
    signed.append(sct.version)
    signed.append(0)  // signature_type = certificate_timestamp
    signed += bigEndian(sct.timestamp, bytes: 8)
    signed += [0, 1]  // entry_type = precert_entry
    signed += issuerKeyHash
    guard precertTBS.count < 1 << 24, sct.extensions.count < 1 << 16 else { return false }
    signed += bigEndian(UInt64(precertTBS.count), bytes: 3)
    signed += precertTBS
    signed += bigEndian(UInt64(sct.extensions.count), bytes: 2)
    signed += sct.extensions
    return verifier.verify(signature: sct.signature, message: signed)
}

private func bigEndian(_ v: UInt64, bytes n: Int) -> [UInt8] {
    (0..<n).reversed().map { UInt8(truncatingIfNeeded: v >> (UInt64($0) * 8)) }
}

/// TBSCertificate DER with the SCT list extension removed
/// (certificate-transparency-go `x509.RemoveSCTList`).
func tbsWithoutSCTList(_ cert: Certificate) throws -> [UInt8] {
    let tbs = try DER.parse(cert.tbsCertificateBytes)
    guard case .constructed(let fields) = tbs.content else {
        throw SigstoreError("malformed TBSCertificate")
    }
    var content: [UInt8] = []
    for field in fields {
        // extensions [3] EXPLICIT Extensions
        if field.identifier == ASN1Identifier(tagWithNumber: 3, tagClass: .contextSpecific) {
            guard case .constructed(let wrapped) = field.content,
                let extSeq = Array(wrapped).first,
                case .constructed(let exts) = extSeq.content
            else { throw SigstoreError("malformed extensions in TBSCertificate") }
            var kept: [UInt8] = []
            for ext in exts {
                guard case .constructed(let parts) = ext.content, let oidNode = Array(parts).first else {
                    throw SigstoreError("malformed extension")
                }
                let oid = try ASN1ObjectIdentifier(derEncoded: oidNode)
                if oid == sctListOID { continue }
                kept += ext.encodedBytes
            }
            if kept.isEmpty { continue }
            content += derTLV(tag: 0xA3, derTLV(tag: 0x30, kept))
        } else {
            content += field.encodedBytes
        }
    }
    return derTLV(tag: 0x30, content)
}

func derTLV(tag: UInt8, _ content: [UInt8]) -> [UInt8] {
    var out: [UInt8] = [tag]
    let n = content.count
    if n < 0x80 {
        out.append(UInt8(n))
    } else {
        var len: [UInt8] = []
        var v = n
        while v > 0 {
            len.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        }
        out.append(0x80 | UInt8(len.count))
        out += len
    }
    return out + content
}
