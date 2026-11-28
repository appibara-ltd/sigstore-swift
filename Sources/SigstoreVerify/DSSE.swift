// DSSE envelope and pre-authentication encoding.
// Spec: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
// (sigstore-go uses github.com/secure-systems-lab/go-securesystemslib/dsse).

import Foundation

/// A DSSE envelope with the payload and signatures already base64-decoded.
public struct DSSEEnvelope: Sendable, Hashable {
    /// One envelope signature.
    public struct Signature: Sendable, Hashable {
        /// The optional key identifier (`keyid`).
        public var keyID: String
        /// The raw signature bytes over the PAE of the payload.
        public var sig: Data

        /// Creates a signature from a key ID and raw signature bytes.
        public init(keyID: String, sig: Data) {
            self.keyID = keyID
            self.sig = sig
        }
    }

    /// The payload media type, such as ``intotoMediaType``.
    public var payloadType: String
    /// The raw (decoded) payload bytes.
    public var payload: Data
    /// The envelope's signatures.
    public var signatures: [Signature]

    /// Creates an envelope from a payload type, decoded payload and signatures.
    public init(payloadType: String, payload: Data, signatures: [Signature]) {
        self.payloadType = payloadType
        self.payload = payload
        self.signatures = signatures
    }

    /// PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
    public static func pae(payloadType: String, payload: Data) -> Data {
        let type = Data(payloadType.utf8)
        var out = Data("DSSEv1 \(type.count) ".utf8)
        out.append(type)
        out.append(contentsOf: Data(" \(payload.count) ".utf8))
        out.append(payload)
        return out
    }
}
