// Decoding of Rekor v1 canonicalized entry bodies.
//
// sigstore-go uses rekor's go-openapi models (`models.UnmarshalProposedEntry`,
// `types.UnmarshalEntry`) and validates required fields with the OpenAPI
// schema. Here we decode only the kinds sigstore-go's `ValidateEntry`
// accepts and enforce the fields its verification path reads.

import Foundation
import SigstoreCommon

/// `dsse` v0.0.1 (rekor pkg/types/dsse/v0.0.1).
public struct DSSEV001: Sendable {
    public struct Signature: Sendable {
        /// Base64 signature string.
        public var signature: String
        /// PEM bytes (the JSON value is base64 of the PEM).
        public var verifierPEM: Data
    }
    public var signatures: [Signature]
    public var payloadHashAlgorithm: String?
    public var payloadHashValue: String?
    public var envelopeHashAlgorithm: String?
    public var envelopeHashValue: String?
}

/// `hashedrekord` v0.0.1.
public struct HashedRekordV001: Sendable {
    public var signatureContent: Data
    public var publicKeyPEM: Data
    public var dataHashAlgorithm: String
    public var dataHashValue: String
}

/// `intoto` v0.0.2.
public struct IntotoV002: Sendable {
    public struct Signature: Sendable {
        /// Base64 signature (the JSON value is base64 of this string).
        public var sig: String
        public var publicKeyPEM: Data
    }
    public var signatures: [Signature]
    public var payloadHashAlgorithm: String?
    public var payloadHashValue: String?
}

struct RekorV1Body {
    var apiVersion: String
    var kind: String
    var entry: RekorV1Entry

    struct Malformed: Error, CustomStringConvertible {
        var description: String
    }

    static func parse(_ body: Data) throws -> RekorV1Body {
        guard let obj = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            throw Malformed(description: "entry body is not a JSON object")
        }
        guard let kind = obj["kind"] as? String, let apiVersion = obj["apiVersion"] as? String else {
            throw Malformed(description: "entry body missing kind or apiVersion")
        }
        guard let spec = obj["spec"] as? [String: Any] else {
            throw Malformed(description: "entry body missing spec")
        }
        switch (kind, apiVersion) {
        case ("dsse", "0.0.1"):
            return RekorV1Body(apiVersion: apiVersion, kind: kind, entry: .dsseV001(try parseDSSE(spec)))
        case ("hashedrekord", "0.0.1"):
            return RekorV1Body(
                apiVersion: apiVersion, kind: kind, entry: .hashedRekordV001(try parseHashedRekord(spec)))
        case ("intoto", "0.0.2"):
            return RekorV1Body(apiVersion: apiVersion, kind: kind, entry: .intotoV002(try parseIntoto(spec)))
        default:
            throw Malformed(description: "unsupported entry type: \(kind)/\(apiVersion)")
        }
    }

    private static func hash(_ obj: Any?, allowed: Set<String>) throws -> (String, String)? {
        guard let obj else { return nil }
        guard let h = obj as? [String: Any], let alg = h["algorithm"] as? String, let value = h["value"] as? String
        else { throw Malformed(description: "malformed hash") }
        guard allowed.contains(alg) else { throw Malformed(description: "unsupported hash algorithm \(alg)") }
        guard Hex.decode(value)?.count == (try HashFunc(algorithmString: alg)).size else {
            throw Malformed(description: "malformed hash value")
        }
        return (alg, value)
    }

    private static func base64Field(_ obj: Any?, _ name: String) throws -> Data {
        guard let s = obj as? String, let d = Base64.decode(s) else {
            throw Malformed(description: "\(name) missing or not base64")
        }
        return d
    }

    static func parseDSSE(_ spec: [String: Any]) throws -> DSSEV001 {
        guard let sigs = spec["signatures"] as? [[String: Any]], !sigs.isEmpty else {
            throw Malformed(description: "dsse entry requires at least one signature")
        }
        let signatures = try sigs.map { s -> DSSEV001.Signature in
            guard let sig = s["signature"] as? String else {
                throw Malformed(description: "dsse signature missing")
            }
            return DSSEV001.Signature(signature: sig, verifierPEM: try base64Field(s["verifier"], "dsse verifier"))
        }
        let payloadHash = try hash(spec["payloadHash"], allowed: ["sha256"])
        let envelopeHash = try hash(spec["envelopeHash"], allowed: ["sha256"])
        return DSSEV001(
            signatures: signatures,
            payloadHashAlgorithm: payloadHash?.0,
            payloadHashValue: payloadHash?.1,
            envelopeHashAlgorithm: envelopeHash?.0,
            envelopeHashValue: envelopeHash?.1
        )
    }

    static func parseHashedRekord(_ spec: [String: Any]) throws -> HashedRekordV001 {
        guard let sig = spec["signature"] as? [String: Any],
            let pk = sig["publicKey"] as? [String: Any],
            let data = spec["data"] as? [String: Any]
        else { throw Malformed(description: "hashedrekord entry missing signature or data") }
        guard let h = try hash(data["hash"], allowed: ["sha256", "sha384", "sha512"]) else {
            throw Malformed(description: "hashedrekord entry missing data hash")
        }
        return HashedRekordV001(
            signatureContent: try base64Field(sig["content"], "hashedrekord signature content"),
            publicKeyPEM: try base64Field(pk["content"], "hashedrekord public key"),
            dataHashAlgorithm: h.0,
            dataHashValue: h.1
        )
    }

    static func parseIntoto(_ spec: [String: Any]) throws -> IntotoV002 {
        guard let content = spec["content"] as? [String: Any],
            let env = content["envelope"] as? [String: Any],
            let sigs = env["signatures"] as? [[String: Any]], !sigs.isEmpty
        else { throw Malformed(description: "intoto entry requires an envelope with signatures") }
        let signatures = try sigs.map { s -> IntotoV002.Signature in
            let sigB64 = try base64Field(s["sig"], "intoto sig")
            guard let sig = String(data: sigB64, encoding: .utf8) else {
                throw Malformed(description: "intoto sig is not text")
            }
            return IntotoV002.Signature(sig: sig, publicKeyPEM: try base64Field(s["publicKey"], "intoto publicKey"))
        }
        let payloadHash = try hash(content["payloadHash"], allowed: ["sha256"])
        return IntotoV002(
            signatures: signatures,
            payloadHashAlgorithm: payloadHash?.0,
            payloadHashValue: payloadHash?.1
        )
    }
}
