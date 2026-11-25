// Port of sigstore-go pkg/verify/certificate_identity.go.
//
// Regular expressions: Go uses RE2; this port uses NSRegularExpression (ICU).
// Common patterns behave the same, but RE2-only or ICU-only syntax differs.
// Matching is unanchored, as with Go's `Regexp.MatchString`.

import Foundation
import SigstoreCommon
import SigstoreFulcio

/// A compiled regular expression that remembers its source (Go `regexp.Regexp`).
public struct Pattern: Sendable, Hashable, CustomStringConvertible {
    public let source: String

    public init(_ source: String) throws {
        if !source.isEmpty {
            do {
                _ = try NSRegularExpression(pattern: source)
            } catch {
                throw SigstoreError("invalid regular expression \"\(source)\"", underlying: error)
            }
        }
        self.source = source
    }

    public var description: String { source }

    public func matches(_ value: String) -> Bool {
        guard let re = try? NSRegularExpression(pattern: source) else { return false }
        return re.firstMatch(in: value, range: NSRange(value.startIndex..., in: value)) != nil
    }
}

/// Mirrors `ErrValueMismatch`.
public struct ValueMismatchError: Error, CustomStringConvertible, Sendable {
    public let object: String
    public let expected: String
    public let actual: String
    public var description: String { "expected \(object) value \"\(expected)\", got \"\(actual)\"" }
}

/// Mirrors `ErrValueRegexMismatch`.
public struct ValueRegexMismatchError: Error, CustomStringConvertible, Sendable {
    public let object: String
    public let regex: String
    public let value: String
    public var description: String { "expected \(object) value to match regex \"\(regex)\", got \"\(value)\"" }
}

/// Mirrors `ErrNoMatchingCertificateIdentity`.
public struct NoMatchingCertificateIdentityError: Error, CustomStringConvertible, Sendable {
    public let errors: [any Error]
    public var description: String {
        if let last = errors.last {
            return "no matching CertificateIdentity found, last error: \(last)"
        }
        return "no matching CertificateIdentity found"
    }
}

/// Mirrors `SubjectAlternativeNameMatcher`.
public struct SubjectAlternativeNameMatcher: Sendable, Hashable {
    public var subjectAlternativeName: String
    public var regexp: Pattern

    /// Mirrors `NewSANMatcher`.
    public init(_ sanValue: String = "", regexp: String = "") throws {
        self.subjectAlternativeName = sanValue
        self.regexp = try Pattern(regexp)
    }

    public func verify(_ actualCert: Summary) throws {
        if subjectAlternativeName.isEmpty && regexp.source.isEmpty {
            throw SigstoreError(
                "when verifying a certificate identity, there must be subject alternative name criteria")
        }
        if !subjectAlternativeName.isEmpty && actualCert.subjectAlternativeName != subjectAlternativeName {
            throw ValueMismatchError(
                object: "SAN", expected: subjectAlternativeName, actual: actualCert.subjectAlternativeName)
        }
        if !regexp.source.isEmpty && !regexp.matches(actualCert.subjectAlternativeName) {
            throw ValueRegexMismatchError(
                object: "SAN", regex: regexp.source, value: actualCert.subjectAlternativeName)
        }
    }
}

/// Mirrors `IssuerMatcher`.
public struct IssuerMatcher: Sendable, Hashable {
    public var issuer: String
    public var regexp: Pattern

    /// Mirrors `NewIssuerMatcher`.
    public init(_ issuerValue: String = "", regexp: String = "") throws {
        self.issuer = issuerValue
        self.regexp = try Pattern(regexp)
    }

    public func verify(_ actualCert: Summary) throws {
        if issuer.isEmpty && regexp.source.isEmpty {
            throw SigstoreError("when verifying a certificate identity, must specify Issuer criteria")
        }
        if !issuer.isEmpty && actualCert.extensions.issuer != issuer {
            throw ValueMismatchError(object: "issuer", expected: issuer, actual: actualCert.extensions.issuer)
        }
        if !regexp.source.isEmpty && !regexp.matches(actualCert.extensions.issuer) {
            throw ValueRegexMismatchError(object: "issuer", regex: regexp.source, value: actualCert.extensions.issuer)
        }
    }
}

/// Mirrors `CertificateIdentity`.
public struct CertificateIdentity: Sendable, Hashable {
    public var subjectAlternativeName: SubjectAlternativeNameMatcher
    public var issuer: IssuerMatcher
    public var extensions: Extensions

    /// Without `NewCertificateIdentity`'s checks (Go struct literal / JSON decoding).
    init(unchecked san: SubjectAlternativeNameMatcher, issuer: IssuerMatcher, extensions: Extensions) {
        self.subjectAlternativeName = san
        self.issuer = issuer
        self.extensions = extensions
    }

    /// Mirrors `NewCertificateIdentity`.
    public init(
        subjectAlternativeName: SubjectAlternativeNameMatcher,
        issuer: IssuerMatcher,
        extensions: Extensions = Extensions()
    ) throws {
        if subjectAlternativeName.subjectAlternativeName.isEmpty && subjectAlternativeName.regexp.source.isEmpty {
            throw SigstoreError(
                "when verifying a certificate identity, there must be subject alternative name criteria")
        }
        if issuer.issuer.isEmpty && issuer.regexp.source.isEmpty {
            throw SigstoreError("when verifying a certificate identity, must specify Issuer criteria")
        }
        if !extensions.issuer.isEmpty {
            throw SigstoreError("please specify issuer in IssuerMatcher, not Extensions")
        }
        self.subjectAlternativeName = subjectAlternativeName
        self.issuer = issuer
        self.extensions = extensions
    }

    /// Mirrors `NewShortCertificateIdentity`.
    public init(issuer: String, issuerRegex: String = "", sanValue: String, sanRegex: String = "") throws {
        try self.init(
            subjectAlternativeName: SubjectAlternativeNameMatcher(sanValue, regexp: sanRegex),
            issuer: IssuerMatcher(issuer, regexp: issuerRegex)
        )
    }

    public func verify(_ actualCert: Summary) throws {
        try subjectAlternativeName.verify(actualCert)
        try issuer.verify(actualCert)
        try compareExtensions(expected: extensions, actual: actualCert.extensions)
    }
}

/// Mirrors `CertificateIdentities.Verify`: returns the first matching identity.
extension Array where Element == CertificateIdentity {
    public func verify(_ cert: Summary) throws -> CertificateIdentity {
        var errors: [any Error] = []
        for ci in self {
            do {
                try ci.verify(cert)
                return ci
            } catch {
                errors.append(error)
            }
        }
        throw NoMatchingCertificateIdentityError(errors: errors)
    }
}

public typealias CertificateIdentities = [CertificateIdentity]
