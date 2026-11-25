// Placeholder for a port of sigstore-go pkg/tuf (a TUF client that fetches
// and refreshes `trusted_root.json` from tuf-repo-cdn.sigstore.dev).
//
// Until it exists, use `TrustedRoot.embeddedPublicGood()` or load a trusted
// root from disk with `TrustedRoot(path:)`.

/// Mirrors `tuf.DefaultMirror`.
public let defaultMirror = "https://tuf-repo-cdn.sigstore.dev"

/// Mirrors `tuf.Options` (fields only; no client yet).
public struct Options: Sendable {
    public var repositoryBaseURL: String = defaultMirror
    public var cachePath: String?
    public var forceCache: Bool = false

    public init() {}
}
