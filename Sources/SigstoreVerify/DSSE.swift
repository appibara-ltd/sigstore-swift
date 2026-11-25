// DSSE envelope and pre-authentication encoding.
// Spec: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md
// (sigstore-go uses github.com/secure-systems-lab/go-securesystemslib/dsse).

import Foundation

/// A DSSE envelope with the payload and signatures already base64-decoded.
public struct DSSEEnvelope: Sendable, Hashable {
    public struct Signature: Sendable, Hashable {
        public var keyID: String
        public var sig: Data

        public init(keyID: String, sig: Data) {
            self.keyID = keyID
            self.sig = sig
        }
    }

    public var payloadType: String
    public var payload: Data
    public var signatures: [Signature]

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
