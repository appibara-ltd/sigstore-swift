// Port of sigstore-go pkg/fulcio/certificate/summarize.go.

import SwiftASN1
import X509

/// The identity a Fulcio certificate attests to. Mirrors sigstore-go
/// `certificate.Summary`.
public struct Summary: Sendable, Hashable, Codable {
    /// The certificate's issuer distinguished name, as a string.
    public var certificateIssuer: String
    /// The identity SAN: the first URI, else the first email, else the Fulcio
    /// OtherName value.
    public var subjectAlternativeName: String
    /// The Fulcio extensions parsed from the certificate.
    public var extensions: Extensions

    /// Creates a summary from its parts.
    public init(certificateIssuer: String, subjectAlternativeName: String, extensions: Extensions) {
        self.certificateIssuer = certificateIssuer
        self.subjectAlternativeName = subjectAlternativeName
        self.extensions = extensions
    }
}

/// Mirrors `ErrCompareExtensions`.
public struct CompareExtensionsError: Error, CustomStringConvertible, Sendable {
    /// The Go field name of the mismatched extension (e.g. `Issuer`).
    public let field: String
    /// The expected value.
    public let expected: String
    /// The value found in the certificate.
    public let actual: String

    /// The error message, in Go's `ErrCompareExtensions` format.
    public var description: String {
        "expected \(field) to be \"\(expected)\", got \"\(actual)\""
    }
}

/// Thrown by ``summarizeCertificate(_:)`` when the certificate has no usable
/// Subject Alternative Name.
public struct SummarizeCertificateError: Error, CustomStringConvertible, Sendable {
    /// A message describing the failure.
    public let description: String
}

/// Mirrors `SummarizeCertificate`. The SAN is the first URI, else the first
/// email, else the Fulcio OtherName (OID 1.3.6.1.4.1.57264.1.7) UTF8String.
public func summarizeCertificate(_ cert: Certificate) throws -> Summary {
    let extensions = try parseExtensions(cert.extensions)

    var uris: [String] = []
    var emails: [String] = []
    var otherName: String?
    if let sanExt = cert.extensions[oid: .X509ExtensionID.subjectAlternativeName] {
        let sans = try SubjectAlternativeNames(sanExt)
        for name in sans {
            switch name {
            case .uniformResourceIdentifier(let u): uris.append(u)
            case .rfc822Name(let e): emails.append(e)
            case .otherName(let on) where on.typeID == FulcioOID.otherName && otherName == nil:
                otherName = decodeOtherNameValue(on.value)
            default: break
            }
        }
    }

    var san = ""
    if let u = uris.first {
        san = u
    } else if let e = emails.first {
        san = e
    }
    if san.isEmpty, let o = otherName {
        san = o
    }
    if san.isEmpty {
        throw SummarizeCertificateError(description: "no Subject Alternative Name found")
    }

    return Summary(
        certificateIssuer: cert.issuer.description,
        subjectAlternativeName: san,
        extensions: extensions
    )
}

/// OtherName value is `[0] EXPLICIT UTF8String` (cryptoutils.UnmarshalOtherNameSAN).
private func decodeOtherNameValue(_ value: ASN1Any?) -> String? {
    guard let value else { return nil }
    var serializer = DER.Serializer()
    guard (try? serializer.serialize(value)) != nil,
        let node = try? DER.parse(serializer.serializedBytes)
    else { return nil }
    guard case .constructed(let children) = node.content else { return nil }
    var it = children.makeIterator()
    guard let inner = it.next(), it.next() == nil else { return nil }
    return (try? ASN1UTF8String(derEncoded: inner)).map { String($0) }
}

/// Mirrors `CompareExtensions`: every non-empty expected field must equal the
/// actual value.
public func compareExtensions(expected: Extensions, actual: Extensions) throws {
    for ((name, exp), (_, act)) in zip(expected.fields, actual.fields) where !exp.isEmpty {
        if exp != act {
            throw CompareExtensionsError(field: name, expected: exp, actual: act)
        }
    }
}
