// Port of sigstore-go v1.4.1 pkg/sign/content.go.

import Foundation
import SigstoreProtobufSpecs

/// Mirrors `sign.Content`: what is signed, and how its signature is stored
/// in a bundle.
public protocol Content: Sendable {
    /// The bytes to sign.
    var preAuthEncoding: Data { get }
    /// Sets the bundle's content (a message signature or a DSSE envelope).
    func bundle(
        _ bundle: inout Dev_Sigstore_Bundle_V1_Bundle, signature: Data, digest: Data,
        hashAlgorithm: Dev_Sigstore_Common_V1_HashAlgorithm)
}

/// Mirrors `sign.PlainData`: an artifact signed directly, stored as a
/// message signature.
public struct PlainData: Content {
    /// The artifact.
    public var data: Data

    /// Creates plain content for `data`.
    public init(data: Data) {
        self.data = data
    }

    /// The artifact itself.
    public var preAuthEncoding: Data { data }

    /// Stores a message signature with the artifact's digest.
    public func bundle(
        _ bundle: inout Dev_Sigstore_Bundle_V1_Bundle, signature: Data, digest: Data,
        hashAlgorithm: Dev_Sigstore_Common_V1_HashAlgorithm
    ) {
        var messageSignature = Dev_Sigstore_Common_V1_MessageSignature()
        messageSignature.messageDigest.algorithm = hashAlgorithm
        messageSignature.messageDigest.digest = digest
        messageSignature.signature = signature
        bundle.messageSignature = messageSignature
    }
}

/// Mirrors `sign.DSSEData`: a payload signed in a DSSE envelope.
public struct DSSEData: Content {
    /// The payload, such as an in-toto statement.
    public var data: Data
    /// The payload type, such as "application/vnd.in-toto+json".
    public var payloadType: String

    /// Creates DSSE content for `data` of type `payloadType`.
    public init(data: Data, payloadType: String) {
        self.data = data
        self.payloadType = payloadType
    }

    /// The DSSE pre-authentication encoding:
    /// `DSSEv1 <len(type)> <type> <len(payload)> <payload>`, lengths in bytes.
    public var preAuthEncoding: Data {
        let type = Data(payloadType.utf8)
        var pae = Data("DSSEv1 \(type.count) ".utf8)
        pae.append(type)
        pae.append(Data(" \(data.count) ".utf8))
        pae.append(data)
        return pae
    }

    /// Stores a DSSE envelope with one signature.
    public func bundle(
        _ bundle: inout Dev_Sigstore_Bundle_V1_Bundle, signature: Data, digest _: Data,
        hashAlgorithm _: Dev_Sigstore_Common_V1_HashAlgorithm
    ) {
        var sig = Io_Intoto_Signature()
        sig.sig = signature
        var envelope = Io_Intoto_Envelope()
        envelope.payload = data
        envelope.payloadType = payloadType
        envelope.signatures = [sig]
        bundle.dsseEnvelope = envelope
    }
}
