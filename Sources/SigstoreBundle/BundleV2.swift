// Port of sigstore-go v1.4.1 pkg/bundle/bundle_v2.go: the v2 bundle
// (`dev.sigstore.bundle.v2`) as a `VerifiableEntity`. sigstore-go has no
// verifier for it yet (see `IdentityVerifier`).

import Foundation
import SigstoreCommon
import SigstoreProtobufSpecs
import SigstoreVerify
import SwiftProtobuf
import X509

/// Mirrors `bundle.BundleV2`.
public struct BundleV2: VerifiableEntity {
    public let protobuf: Dev_Sigstore_Bundle_V2_Bundle

    /// Mirrors `NewBundleV2`.
    public init(_ pb: Dev_Sigstore_Bundle_V2_Bundle) throws {
        protobuf = pb
        try validate()
    }

    /// Mirrors `BundleV2.UnmarshalJSON` (protojson, then validation).
    public init(json: Data) throws {
        try self.init(Dev_Sigstore_Bundle_V2_Bundle(jsonUTF8Data: ProtoJSON.normalizeBytesFields(json)))
    }

    /// Mirrors `LoadJSONFromPathV2`.
    public static func loadJSONFromPath(_ path: String) throws -> BundleV2 {
        try BundleV2(json: Data(contentsOf: URL(fileURLWithPath: path)))
    }

    /// Mirrors `BundleV2.MarshalJSON`.
    public func jsonData() throws -> Data { try protobuf.jsonUTF8Data() }

    private func validate() throws {
        do {
            _ = try version()
        } catch {
            throw error.wrapped("error getting bundle version")
        }
        if protobuf.hasPayload && (protobuf.payload.payload.isEmpty || protobuf.payload.payloadType.isEmpty) {
            throw BundleError.missingEnvelope
        }
        guard protobuf.hasVerificationMaterial else { throw BundleError.missingVerificationMaterial }
        let vm = protobuf.verificationMaterial
        switch vm.content {
        case .transparencyLogProof(let p):
            if p.proof.isEmpty { throw BundleError.missingVerificationMaterial }
            if p.hasSignature && p.signature.signature.isEmpty { throw BundleError.missingVerificationMaterial }
        case .publicKey(let k):
            if k.signature.signature.isEmpty { throw BundleError.missingVerificationMaterial }
        case .certificate(let c):
            if c.certificate.rawBytes.isEmpty || c.timestamps.rfc3161Timestamps.isEmpty
                || c.signature.signature.isEmpty
            {
                throw BundleError.missingVerificationMaterial
            }
        case nil:
            throw BundleError.missingVerificationMaterial
        }
    }

    public var hasTransparencyLogProof: Bool {
        if case .transparencyLogProof = protobuf.verificationMaterial.content { return true }
        return false
    }

    public var hasCertificate: Bool {
        if case .certificate = protobuf.verificationMaterial.content { return true }
        return false
    }

    public var hasPublicKey: Bool {
        if case .publicKey = protobuf.verificationMaterial.content { return true }
        return false
    }

    public var hasEnvelope: Bool { protobuf.hasPayload }

    /// Mirrors `BundleV2.Version`: only `v2.0` is accepted.
    public func version() throws -> String {
        let version = try getBundleVersion(protobuf.mediaType)
        guard version == "v2.0" else {
            throw BundleError.unsupportedMediaType("bundle version \(version) is not a supported v2 bundle")
        }
        return version
    }

    /// Mirrors `BundleV2.Signature`.
    public func signature() throws -> Data {
        switch protobuf.verificationMaterial.content {
        case .transparencyLogProof(let p): return p.signature.signature
        case .certificate(let c): return c.signature.signature
        case .publicKey(let k): return k.signature.signature
        case nil: throw BundleError.missingVerificationMaterial
        }
    }

    /// Mirrors `BundleV2.Envelope`: the payload as a DSSE envelope carrying
    /// the bundle's signature (if any).
    public func envelope() throws -> any EnvelopeContent {
        guard hasEnvelope else { throw BundleError.missingEnvelope }
        let payload = protobuf.payload
        guard !payload.payload.isEmpty, !payload.payloadType.isEmpty else { throw BundleError.missingEnvelope }
        var signatures: [DSSEEnvelope.Signature] = []
        if let sig = try? signature(), !sig.isEmpty {
            signatures = [DSSEEnvelope.Signature(keyID: "", sig: sig)]
        }
        return Envelope(DSSEEnvelope(payloadType: payload.payloadType, payload: payload.payload, signatures: signatures))
    }

    /// Mirrors `BundleV2.Timestamps`.
    public func timestamps() throws -> [Data] {
        guard protobuf.hasVerificationMaterial else { throw BundleError.missingVerificationMaterial }
        switch protobuf.verificationMaterial.content {
        case .certificate(let c): return c.timestamps.rfc3161Timestamps.map(\.signedTimestamp)
        case .publicKey(let k): return k.timestamps.rfc3161Timestamps.map(\.signedTimestamp)
        default: return []
        }
    }

    /// Mirrors `BundleV2.Certificate`.
    public func certificate() throws -> (X509.Certificate, [X509.Certificate]) {
        guard case .certificate(let c) = protobuf.verificationMaterial.content, !c.certificate.rawBytes.isEmpty else {
            throw BundleError.missingVerificationMaterial
        }
        let leaf: X509.Certificate
        do {
            leaf = try X509.Certificate(derEncoded: Array(c.certificate.rawBytes))
        } catch {
            throw BundleError.validation("\(error)")
        }
        return (leaf, try parseIntermediateCertificates(c.intermediates.certificates))
    }

    /// Mirrors `BundleV2.TransparencyLogProof`.
    public func transparencyLogProof() throws -> Dev_Sigstore_Bundle_V2_TransparencyLogProof {
        guard case .transparencyLogProof(let p) = protobuf.verificationMaterial.content else {
            throw BundleError.missingVerificationMaterial
        }
        return p
    }
}
