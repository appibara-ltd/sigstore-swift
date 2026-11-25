// Port of sigstore-go pkg/root/trusted_root.go TUF helpers
// (`FetchTrustedRoot`, `FetchTrustedRootWithOptions`, `GetTrustedRoot`).

import Foundation
import SigstoreCommon
import SigstoreTUF

/// The TUF target holding the trusted root (sigstore-go `defaultTrustedRoot`).
public let defaultTrustedRootTarget = "trusted_root.json"

/// Mirrors `root.FetchTrustedRoot`: the public-good trusted root via TUF.
public func fetchTrustedRoot() async throws -> TrustedRoot {
    try await fetchTrustedRootWithOptions(SigstoreTUF.Options())
}

/// Mirrors `root.FetchTrustedRootWithOptions`.
public func fetchTrustedRootWithOptions(_ opts: SigstoreTUF.Options) async throws -> TrustedRoot {
    let client: Client
    do {
        client = try await Client(options: opts)
    } catch {
        throw SigstoreError("failed to create TUF client", underlying: error)
    }
    return try await getTrustedRoot(client)
}

/// Mirrors `root.GetTrustedRoot`.
public func getTrustedRoot(_ client: Client) async throws -> TrustedRoot {
    let json: Data
    do {
        json = try await client.getTarget(defaultTrustedRootTarget)
    } catch {
        throw SigstoreError("failed to get trusted root from TUF client", underlying: error)
    }
    return try TrustedRoot(json: json)
}
