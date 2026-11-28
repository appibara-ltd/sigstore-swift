// Port of sigstore-go pkg/fulcio/certificate/extensions.go (itself a copy of
// fulcio pkg/certificate/extensions.go).

import SwiftASN1
import X509

/// Object identifiers of Fulcio's custom X.509 extensions (arc
/// 1.3.6.1.4.1.57264.1). Mirrors the `OID*` variables of sigstore-go
/// `certificate`.
public enum FulcioOID {
    // Deprecated (raw string values).
    /// The OIDC issuer as a raw string (1.3.6.1.4.1.57264.1.1). Deprecated: use
    /// ``issuerV2``.
    public static let issuer: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 1]
    /// The GitHub workflow trigger (1.3.6.1.4.1.57264.1.2). Deprecated: use
    /// ``buildTrigger``.
    public static let gitHubWorkflowTrigger: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 2]
    /// The GitHub workflow commit SHA (1.3.6.1.4.1.57264.1.3). Deprecated: use
    /// ``sourceRepositoryDigest``.
    public static let gitHubWorkflowSHA: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 3]
    /// The GitHub workflow name (1.3.6.1.4.1.57264.1.4). Deprecated: use
    /// ``buildConfigURI`` or ``buildConfigDigest``.
    public static let gitHubWorkflowName: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 4]
    /// The GitHub workflow repository (1.3.6.1.4.1.57264.1.5). Deprecated: use
    /// ``sourceRepositoryURI``.
    public static let gitHubWorkflowRepository: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 5]
    /// The GitHub workflow git ref (1.3.6.1.4.1.57264.1.6). Deprecated: use
    /// ``sourceRepositoryRef``.
    public static let gitHubWorkflowRef: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 6]

    /// The type ID of Fulcio's OtherName SAN (1.3.6.1.4.1.57264.1.7).
    public static let otherName: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 7]
    /// The OIDC issuer as a DER string (1.3.6.1.4.1.57264.1.8).
    public static let issuerV2: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 8]

    // CI extensions (DER-encoded string values).
    /// The build signer URI (1.3.6.1.4.1.57264.1.9).
    public static let buildSignerURI: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 9]
    /// The build signer digest (1.3.6.1.4.1.57264.1.10).
    public static let buildSignerDigest: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 10]
    /// The runner environment (1.3.6.1.4.1.57264.1.11).
    public static let runnerEnvironment: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 11]
    /// The source repository URI (1.3.6.1.4.1.57264.1.12).
    public static let sourceRepositoryURI: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 12]
    /// The source repository digest (1.3.6.1.4.1.57264.1.13).
    public static let sourceRepositoryDigest: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 13]
    /// The source repository ref (1.3.6.1.4.1.57264.1.14).
    public static let sourceRepositoryRef: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 14]
    /// The source repository identifier (1.3.6.1.4.1.57264.1.15).
    public static let sourceRepositoryIdentifier: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 15]
    /// The source repository owner URI (1.3.6.1.4.1.57264.1.16).
    public static let sourceRepositoryOwnerURI: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 16]
    /// The source repository owner identifier (1.3.6.1.4.1.57264.1.17).
    public static let sourceRepositoryOwnerIdentifier: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 17]
    /// The build config URI (1.3.6.1.4.1.57264.1.18).
    public static let buildConfigURI: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 18]
    /// The build config digest (1.3.6.1.4.1.57264.1.19).
    public static let buildConfigDigest: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 19]
    /// The build trigger (1.3.6.1.4.1.57264.1.20).
    public static let buildTrigger: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 20]
    /// The run invocation URI (1.3.6.1.4.1.57264.1.21).
    public static let runInvocationURI: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 21]
    /// The source repository visibility at signing (1.3.6.1.4.1.57264.1.22).
    public static let sourceRepositoryVisibilityAtSigning: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 57264, 1, 22]
}

/// All custom X.509 extensions defined by Fulcio. Empty string means unset,
/// as in Go.
public struct Extensions: Sendable, Hashable, Codable {
    /// The OIDC issuer (Fulcio extension 1.3.6.1.4.1.57264.1.8, or the
    /// deprecated 1.3.6.1.4.1.57264.1.1).
    public var issuer = ""
    /// Deprecated: the GitHub workflow trigger (1.3.6.1.4.1.57264.1.2).
    public var githubWorkflowTrigger = ""
    /// Deprecated: the GitHub workflow commit SHA (1.3.6.1.4.1.57264.1.3).
    public var githubWorkflowSHA = ""
    /// Deprecated: the GitHub workflow name (1.3.6.1.4.1.57264.1.4).
    public var githubWorkflowName = ""
    /// Deprecated: the GitHub workflow repository (1.3.6.1.4.1.57264.1.5).
    public var githubWorkflowRepository = ""
    /// Deprecated: the GitHub workflow git ref (1.3.6.1.4.1.57264.1.6).
    public var githubWorkflowRef = ""
    /// Reference to the build instructions responsible for signing (Fulcio
    /// extension 1.3.6.1.4.1.57264.1.9).
    public var buildSignerURI = ""
    /// Immutable reference to the version of the build instructions responsible
    /// for signing (Fulcio extension 1.3.6.1.4.1.57264.1.10).
    public var buildSignerDigest = ""
    /// Whether the build ran on platform-hosted or self-hosted infrastructure
    /// (Fulcio extension 1.3.6.1.4.1.57264.1.11).
    public var runnerEnvironment = ""
    /// The source repository URL the build was based on (Fulcio extension
    /// 1.3.6.1.4.1.57264.1.12).
    public var sourceRepositoryURI = ""
    /// Immutable reference to the source code version the build was based on
    /// (Fulcio extension 1.3.6.1.4.1.57264.1.13).
    public var sourceRepositoryDigest = ""
    /// The source repository ref the build was based on (Fulcio extension
    /// 1.3.6.1.4.1.57264.1.14).
    public var sourceRepositoryRef = ""
    /// Immutable identifier of the source repository (Fulcio extension
    /// 1.3.6.1.4.1.57264.1.15).
    public var sourceRepositoryIdentifier = ""
    /// URL of the source repository's owner (Fulcio extension
    /// 1.3.6.1.4.1.57264.1.16).
    public var sourceRepositoryOwnerURI = ""
    /// Immutable identifier of the source repository's owner (Fulcio extension
    /// 1.3.6.1.4.1.57264.1.17).
    public var sourceRepositoryOwnerIdentifier = ""
    /// URL of the top-level build instructions (Fulcio extension
    /// 1.3.6.1.4.1.57264.1.18).
    public var buildConfigURI = ""
    /// Immutable reference to the version of the top-level build instructions
    /// (Fulcio extension 1.3.6.1.4.1.57264.1.19).
    public var buildConfigDigest = ""
    /// The event or action that initiated the build (Fulcio extension
    /// 1.3.6.1.4.1.57264.1.20).
    public var buildTrigger = ""
    /// URL that uniquely identifies the build run (Fulcio extension
    /// 1.3.6.1.4.1.57264.1.21).
    public var runInvocationURI = ""
    /// The source repository's visibility when the certificate was issued
    /// (Fulcio extension 1.3.6.1.4.1.57264.1.22).
    public var sourceRepositoryVisibilityAtSigning = ""

    /// Creates a value with every field unset (empty).
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
        // Go compares string(ext.Value); Go's regexp also reads invalid UTF-8 as U+FFFD.
        // swiftlint:disable:next optional_data_string_conversion
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

/// Thrown when a Fulcio extension value is not a valid DER string.
public struct ExtensionParseError: Error, CustomStringConvertible, Sendable {
    /// A message describing the parse failure.
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
