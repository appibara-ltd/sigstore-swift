// Port of sigstore-go pkg/fulcio/certificate/extensions.go (itself a copy of
// fulcio pkg/certificate/extensions.go).

import SwiftASN1
import X509

public enum FulcioOID {
    // Deprecated (raw string values).
    public static let issuer: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 1]
    public static let gitHubWorkflowTrigger: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 2]
    public static let gitHubWorkflowSHA: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 3]
    public static let gitHubWorkflowName: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 4]
    public static let gitHubWorkflowRepository: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 5]
    public static let gitHubWorkflowRef: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 6]

    public static let otherName: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 7]
    public static let issuerV2: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 8]

    // CI extensions (DER-encoded string values).
    public static let buildSignerURI: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 9]
    public static let buildSignerDigest: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 10]
    public static let runnerEnvironment: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 11]
    public static let sourceRepositoryURI: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 12]
    public static let sourceRepositoryDigest: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 13]
    public static let sourceRepositoryRef: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 14]
    public static let sourceRepositoryIdentifier: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 15]
    public static let sourceRepositoryOwnerURI: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 16]
    public static let sourceRepositoryOwnerIdentifier: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 17]
    public static let buildConfigURI: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 18]
    public static let buildConfigDigest: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 19]
    public static let buildTrigger: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 20]
    public static let runInvocationURI: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 21]
    public static let sourceRepositoryVisibilityAtSigning: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 22]
}

/// All custom X.509 extensions defined by Fulcio. Empty string means unset,
/// as in Go.
public struct Extensions: Sendable, Hashable, Codable {
    public var issuer = ""
    public var githubWorkflowTrigger = ""
    public var githubWorkflowSHA = ""
    public var githubWorkflowName = ""
    public var githubWorkflowRepository = ""
    public var githubWorkflowRef = ""
    public var buildSignerURI = ""
    public var buildSignerDigest = ""
    public var runnerEnvironment = ""
    public var sourceRepositoryURI = ""
    public var sourceRepositoryDigest = ""
    public var sourceRepositoryRef = ""
    public var sourceRepositoryIdentifier = ""
    public var sourceRepositoryOwnerURI = ""
    public var sourceRepositoryOwnerIdentifier = ""
    public var buildConfigURI = ""
    public var buildConfigDigest = ""
    public var buildTrigger = ""
    public var runInvocationURI = ""
    public var sourceRepositoryVisibilityAtSigning = ""

    public init() {}

    /// Field name / value pairs in declaration order (for `compareExtensions`).
    var fields: [(String, String)] {
        [
            ("Issuer", issuer),
            ("GithubWorkflowTrigger", githubWorkflowTrigger),
            ("GithubWorkflowSHA", githubWorkflowSHA),
            ("GithubWorkflowName", githubWorkflowName),
            ("GithubWorkflowRepository", githubWorkflowRepository),
            ("GithubWorkflowRef", githubWorkflowRef),
            ("BuildSignerURI", buildSignerURI),
            ("BuildSignerDigest", buildSignerDigest),
            ("RunnerEnvironment", runnerEnvironment),
            ("SourceRepositoryURI", sourceRepositoryURI),
            ("SourceRepositoryDigest", sourceRepositoryDigest),
            ("SourceRepositoryRef", sourceRepositoryRef),
            ("SourceRepositoryIdentifier", sourceRepositoryIdentifier),
            ("SourceRepositoryOwnerURI", sourceRepositoryOwnerURI),
            ("SourceRepositoryOwnerIdentifier", sourceRepositoryOwnerIdentifier),
            ("BuildConfigURI", buildConfigURI),
            ("BuildConfigDigest", buildConfigDigest),
            ("BuildTrigger", buildTrigger),
            ("RunInvocationURI", runInvocationURI),
            ("SourceRepositoryVisibilityAtSigning", sourceRepositoryVisibilityAtSigning),
        ]
    }
}

/// Mirrors `ParseExtensions`.
public func parseExtensions(_ extensions: Certificate.Extensions) throws -> Extensions {
    var out = Extensions()
    for e in extensions {
        let raw = String(decoding: e.value, as: UTF8.self)
        switch e.oid {
        // BEGIN: Deprecated
        case FulcioOID.issuer: out.issuer = raw
        case FulcioOID.gitHubWorkflowTrigger: out.githubWorkflowTrigger = raw
        case FulcioOID.gitHubWorkflowSHA: out.githubWorkflowSHA = raw
        case FulcioOID.gitHubWorkflowName: out.githubWorkflowName = raw
        case FulcioOID.gitHubWorkflowRepository: out.githubWorkflowRepository = raw
        case FulcioOID.gitHubWorkflowRef: out.githubWorkflowRef = raw
        // END: Deprecated
        case FulcioOID.issuerV2: out.issuer = try parseDERString(e.value)
        case FulcioOID.buildSignerURI: out.buildSignerURI = try parseDERString(e.value)
        case FulcioOID.buildSignerDigest: out.buildSignerDigest = try parseDERString(e.value)
        case FulcioOID.runnerEnvironment: out.runnerEnvironment = try parseDERString(e.value)
        case FulcioOID.sourceRepositoryURI: out.sourceRepositoryURI = try parseDERString(e.value)
        case FulcioOID.sourceRepositoryDigest: out.sourceRepositoryDigest = try parseDERString(e.value)
        case FulcioOID.sourceRepositoryRef: out.sourceRepositoryRef = try parseDERString(e.value)
        case FulcioOID.sourceRepositoryIdentifier: out.sourceRepositoryIdentifier = try parseDERString(e.value)
        case FulcioOID.sourceRepositoryOwnerURI: out.sourceRepositoryOwnerURI = try parseDERString(e.value)
        case FulcioOID.sourceRepositoryOwnerIdentifier:
            out.sourceRepositoryOwnerIdentifier = try parseDERString(e.value)
        case FulcioOID.buildConfigURI: out.buildConfigURI = try parseDERString(e.value)
        case FulcioOID.buildConfigDigest: out.buildConfigDigest = try parseDERString(e.value)
        case FulcioOID.buildTrigger: out.buildTrigger = try parseDERString(e.value)
        case FulcioOID.runInvocationURI: out.runInvocationURI = try parseDERString(e.value)
        case FulcioOID.sourceRepositoryVisibilityAtSigning:
            out.sourceRepositoryVisibilityAtSigning = try parseDERString(e.value)
        default: break
        }
    }
    return out
}

public struct ExtensionParseError: Error, CustomStringConvertible, Sendable {
    public let description: String
}

/// Mirrors `ParseDERString`: decodes a DER string (Go's `asn1.Unmarshal` into
/// a `string` accepts UTF8String, PrintableString and IA5String), rejecting
/// trailing bytes.
public func parseDERString(_ bytes: ArraySlice<UInt8>) throws -> String {
    let node: ASN1Node
    do {
        // DER.parse rejects trailing bytes.
        node = try DER.parse(bytes)
    } catch {
        throw ExtensionParseError(description: "unexpected error unmarshalling DER-encoded string: \(error)")
    }
    do {
        switch node.identifier {
        case .utf8String:
            return String(try ASN1UTF8String(derEncoded: node))
        case .printableString:
            return String(try ASN1PrintableString(derEncoded: node))
        case .ia5String:
            return String(try ASN1IA5String(derEncoded: node))
        default:
            throw ExtensionParseError(description: "unexpected ASN.1 tag for string: \(node.identifier)")
        }
    } catch let e as ExtensionParseError {
        throw e
    } catch {
        throw ExtensionParseError(description: "unexpected error unmarshalling DER-encoded string: \(error)")
    }
}
