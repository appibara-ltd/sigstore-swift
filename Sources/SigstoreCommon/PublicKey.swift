// A public key as sigstore-go handles it (`crypto.PublicKey`): the
// classical keys swift-certificates models, or ML-DSA keys, which it does
// not (Go: `crypto/mldsa`, parsed by `x509.ParsePKIXPublicKey`).

import Foundation
import SigstoreMLDSA
import SwiftASN1
import X509

/// A classical (`Certificate.PublicKey`) or ML-DSA public key.
public enum SigstorePublicKey: Sendable, Hashable {
    case x509(Certificate.PublicKey)
    case mlDSA(MLDSAPublicKey)

    /// ML-DSA SPKI algorithm OIDs (NIST CSOR; RFC 9881 §2), parameters absent.
    static let mlDSAOIDs: [(ASN1ObjectIdentifier, MLDSAParameterSet)] = [
        ([2, 16, 840, 1, 101, 3, 4, 3, 17], .mlDSA44),
        ([2, 16, 840, 1, 101, 3, 4, 3, 18], .mlDSA65),
        ([2, 16, 840, 1, 101, 3, 4, 3, 19], .mlDSA87),
    ]

    /// Parses a DER SubjectPublicKeyInfo (Go `x509.ParsePKIXPublicKey`).
    public init<D: DataProtocol>(spki: D) throws {
        let bytes = Array(spki)
        if let key = try? Certificate.PublicKey(derEncoded: bytes) {
            self = .x509(key)
            return
        }
        guard let mldsa = try? Self.parseMLDSA(bytes) else {
            throw SigstoreError("failed to parse public key: unsupported or malformed SubjectPublicKeyInfo")
        }
        self = .mlDSA(mldsa)
    }

    /// RFC 9881: SEQUENCE { SEQUENCE { id-ml-dsa-* } , BIT STRING pk }.
    private static func parseMLDSA(_ der: [UInt8]) throws -> MLDSAPublicKey {
        let root = try DER.parse(der)
        return try DER.sequence(root, identifier: .sequence) { nodes in
            let oid = try DER.sequence(of: ASN1ObjectIdentifier.self, identifier: .sequence, nodes: &nodes)
            guard oid.count == 1, let set = mlDSAOIDs.first(where: { $0.0 == oid[0] })?.1 else {
                throw SigstoreError("not an ML-DSA key")
            }
            let bits = try ASN1BitString(derEncoded: &nodes)
            guard bits.paddingBits == 0 else { throw SigstoreError("ML-DSA key has padding bits") }
            return try MLDSAPublicKey(rawRepresentation: bits.bytes, parameterSet: set)
        }
    }

    /// DER SubjectPublicKeyInfo.
    public var pkixBytes: [UInt8] {
        switch self {
        case .x509(let k): return k.pkixBytes
        case .mlDSA(let k):
            // mlDSAOIDs lists every MLDSAParameterSet case.
            // swiftlint:disable:next force_unwrapping
            let oid = Self.mlDSAOIDs.first { $0.1 == k.parameterSet }!.0
            var s = DER.Serializer()
            // Serializing fixed OIDs and a byte string cannot fail.
            // swiftlint:disable:next force_try
            try! s.appendConstructedNode(identifier: .sequence) { s in
                try s.appendConstructedNode(identifier: .sequence) { s in try s.serialize(oid) }
                try s.serialize(ASN1BitString(bytes: ArraySlice(k.rawRepresentation)))
            }
            return s.serializedBytes
        }
    }

    /// The classical key, if this is one.
    public var x509: Certificate.PublicKey? {
        if case .x509(let k) = self { return k }
        return nil
    }
}
