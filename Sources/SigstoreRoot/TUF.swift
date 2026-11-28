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

/// Mirrors `root.FetchSigningConfig`: the public-good signing config via TUF.
public func fetchSigningConfig() async throws -> SigningConfig {
    try await fetchSigningConfigWithOptions(SigstoreTUF.Options())
}

/// Mirrors `root.FetchSigningConfigWithOptions`.
public func fetchSigningConfigWithOptions(_ opts: SigstoreTUF.Options) async throws -> SigningConfig {
    let client: Client
    do {
        client = try await Client(options: opts)
    } catch {
        throw SigstoreError("failed to create TUF client", underlying: error)
    }
    return try await getSigningConfig(client)
}

/// Mirrors `root.GetSigningConfig`.
public func getSigningConfig(_ client: Client) async throws -> SigningConfig {
    let json: Data
    do {
        json = try await client.getTarget(defaultSigningConfigTarget)
    } catch {
        throw SigstoreError("failed to get signing config from TUF client", underlying: error)
    }
    return try SigningConfig(json: json)
}

/// Mirrors `root.LiveTrustedRoot`: a trusted root fetched over TUF and
/// refreshed in the background every `refreshPeriod` (default 24 h). Reads
/// always see a complete trusted root; a failed refresh keeps the previous
/// one (Go logs and retries at the next tick).
///
/// Go stops the refresh loop when `tuf.Options.Context` is cancelled; here
/// call `stop()` or release the object (Swift structured concurrency has no
/// ambient context to hang it on).
public final class LiveTrustedRoot: TrustedMaterial, @unchecked Sendable {
    private let lock = NSLock()
    private var current: TrustedRoot
    private var refreshTask: Task<Void, Never>?

    /// Called after each background refresh attempt (Go logs instead).
    public typealias RefreshObserver = @Sendable (Result<TrustedRoot, any Error>) -> Void

    /// Mirrors `NewLiveTrustedRoot` / `NewLiveTrustedRootFromTarget` /
    /// `NewLiveTrustedRootFromTargetWithPeriod`.
    public init(
        options: SigstoreTUF.Options = SigstoreTUF.Options(),
        target: String = defaultTrustedRootTarget,
        refreshPeriod: Duration = .seconds(24 * 60 * 60),
        onRefresh: RefreshObserver? = nil
    ) async throws {
        current = try await Self.fetch(options, target)
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: refreshPeriod)
                } catch {
                    return  // cancelled
                }
                do {
                    let root = try await Self.fetch(options, target)
                    guard let self else { return }
                    self.lock.withLock { self.current = root }
                    onRefresh?(.success(root))
                } catch {
                    guard self != nil else { return }
                    onRefresh?(.failure(error))
                }
            }
        }
    }

    deinit { refreshTask?.cancel() }

    /// Stops background refreshes (Go: cancelling `Options.Context`).
    public func stop() { lock.withLock { refreshTask?.cancel() } }

    private static func fetch(_ options: SigstoreTUF.Options, _ target: String) async throws -> TrustedRoot {
        let client: Client
        do {
            client = try await Client(options: options)
        } catch {
            throw SigstoreError("failed to create TUF client", underlying: error)
        }
        let json: Data
        do {
            json = try await client.getTarget(target)
        } catch {
            throw SigstoreError("failed to get target from TUF client", underlying: error)
        }
        return try TrustedRoot(json: json)
    }

    /// The trusted root currently in use.
    public var trustedRoot: TrustedRoot { lock.withLock { current } }

    /// The current trusted root's timestamping authorities.
    public var timestampingAuthorities: [any TimestampingAuthority] { trustedRoot.timestampingAuthorities }
    /// The current trusted root's certificate authorities.
    public var fulcioCertificateAuthorities: [any CertificateAuthority] { trustedRoot.fulcioCertificateAuthorities }
    /// The current trusted root's Rekor logs, keyed by hex-encoded log ID.
    public var rekorLogs: [String: TransparencyLog] { trustedRoot.rekorLogs }
    /// The current trusted root's CT logs, keyed by hex-encoded log ID.
    public var ctLogs: [String: TransparencyLog] { trustedRoot.ctLogs }
    /// Forwards to the current trusted root's `publicKeyVerifier(_:)`.
    public func publicKeyVerifier(_ keyID: String) throws -> any TimeConstrainedVerifier {
        try trustedRoot.publicKeyVerifier(keyID)
    }
    /// The current trusted root's public key verifiers.
    public var publicKeyVerifiers: [any TimeConstrainedVerifier] { trustedRoot.publicKeyVerifiers }
}
