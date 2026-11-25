// Port of sigstore-go v1.4.1 pkg/tuf (client.go, config.go, options.go):
// a TUF client for Sigstore trust material with an on-disk cache.

import Foundation
import SigstoreCommon

/// Mirrors `tuf.DefaultMirror`.
public let defaultMirror = "https://tuf-repo-cdn.sigstore.dev"
/// Mirrors `tuf.StagingMirror`.
public let stagingMirror = "https://tuf-repo-cdn.sigstage.dev"
/// Mirrors `tuf.NoCache`.
public let noCache = 0
/// Mirrors `tuf.MaxCache`.
public let maxCache = Int.max

/// Mirrors `tuf.DefaultRoot`: the embedded public-good `root.json`.
public func defaultRoot() -> Data { decodeEmbedded(EmbeddedRoots.root) }

/// Mirrors `tuf.StagingRoot`: the embedded staging `root.json`.
public func stagingRoot() -> Data { decodeEmbedded(EmbeddedRoots.stagingRoot) }

private func decodeEmbedded(_ chunks: [String]) -> Data {
    guard let data = Data(base64Encoded: chunks.joined()) else {
        // As in Go: the binary is not assembled as it should be.
        fatalError("embedded TUF root is corrupt")
    }
    return data
}

/// Mirrors `tuf.Options`. `with...` methods return a modified copy.
public struct Options: Sendable {
    /// Days the cached metadata is used without contacting the repository.
    public var cacheValidity = 0
    /// Use the cache whenever it verifies, regardless of age.
    public var forceCache = false
    /// The initial trusted `root.json`.
    public var root: Data
    public var cachePath: String
    public var repositoryBaseURL: String
    public var disableLocalCache = false
    public var disableConsistentSnapshot = false
    public var fetcher: (any Fetcher)?

    /// Mirrors `tuf.DefaultOptions`: public-good root and mirror, cache in
    /// `~/.sigstore/root`.
    public init() {
        root = defaultRoot()
        cachePath = joinPath(joinPath(homeDirectory(), ".sigstore"), "root")
        repositoryBaseURL = defaultMirror
        fetcher = DefaultFetcher()
    }

    public static func defaultOptions() -> Options { Options() }

    public func withCacheValidity(_ days: Int) -> Options { var o = self; o.cacheValidity = days; return o }
    public func withForceCache() -> Options { var o = self; o.forceCache = true; return o }
    public func withRoot(_ root: Data) -> Options { var o = self; o.root = root; return o }
    public func withCachePath(_ path: String) -> Options { var o = self; o.cachePath = path; return o }
    public func withRepositoryBaseURL(_ url: String) -> Options {
        var o = self
        o.repositoryBaseURL = url
        return o
    }
    public func withDisableLocalCache() -> Options { var o = self; o.disableLocalCache = true; return o }
    public func withDisableConsistentSnapshot() -> Options {
        var o = self
        o.disableConsistentSnapshot = true
        return o
    }
    public func withFetcher(_ f: any Fetcher) -> Options { var o = self; o.fetcher = f; return o }
}

private func homeDirectory() -> String {
    let home = NSHomeDirectory()
    return home.isEmpty ? NSTemporaryDirectory() : home
}

/// Mirrors `tuf.Config` (persisted next to the cache).
struct ClientConfig: Codable {
    var lastTimestamp: Date

    static func load(_ path: String) -> ClientConfig? {
        guard let data = FileManager.default.contents(atPath: path),
            let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let s = obj["lastTimestamp"] as? String, let d = parseRFC3339(s)
        else { return nil }
        return ClientConfig(lastTimestamp: d)
    }

    func persist(_ path: String) throws {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let json = "{\"lastTimestamp\":\"\(f.string(from: lastTimestamp))\"}"
        try Data(json.utf8).write(to: URL(fileURLWithPath: path), options: .atomic)
        if let attrs = posixAttributes(0o600) { try? FileManager.default.setAttributes(attrs, ofItemAtPath: path) }
    }
}

/// Mirrors `tuf.Client`.
public actor Client {
    private var cfg: UpdaterConfig
    private var up: Updater
    private var opts: Options

    /// Mirrors `tuf.New`: loads cached metadata (refreshing from the
    /// repository when the cache is missing, invalid or older than
    /// `cacheValidity` days).
    public init(options: Options) async throws {
        var opts = options
        let dir = joinPath(opts.cachePath, urlToPath(opts.repositoryBaseURL))
        var cfg = UpdaterConfig(remoteURL: opts.repositoryBaseURL, rootBytes: opts.root)
        cfg.localMetadataDir = dir
        cfg.localTargetsDir = joinPath(dir, "targets")
        cfg.disableLocalCache = opts.disableLocalCache
        cfg.prefixTargetsWithHash = !opts.disableConsistentSnapshot
        if cfg.disableLocalCache {
            opts.cachePath = ""
            opts.cacheValidity = 0
            opts.forceCache = false
        }
        cfg.fetcher = opts.fetcher ?? DefaultFetcher()

        var tmp = cfg
        tmp.unsafeLocalMode = true
        let up: Updater
        do {
            up = try Updater(config: tmp)
        } catch {
            throw SigstoreError("failed to create initial TUF updater", underlying: error)
        }
        self.cfg = cfg
        self.up = up
        self.opts = opts
        do {
            try await loadMetadata()
        } catch {
            throw SigstoreError("failed to load metadata", underlying: error)
        }
    }

    /// Mirrors `tuf.DefaultClient`.
    public static func defaultClient() async throws -> Client { try await Client(options: Options()) }

    private func loadMetadata() async throws {
        do {
            var u = up
            defer { up = u }
            try await u.refresh()  // cached metadata only
        } catch {
            return try await refresh()
        }
        if opts.forceCache { return }
        if opts.cacheValidity > 0 {
            let last = ClientConfig.load(configPath)?.lastTimestamp ?? .distantPast
            let validUntil = Calendar(identifier: .gregorian).date(
                byAdding: .day, value: opts.cacheValidity, to: last) ?? .distantFuture
            if Date() < validUntil { return }
        }
        try await refresh()
    }

    private var configPath: String { joinPath(opts.cachePath, "\(urlToPath(opts.repositoryBaseURL)).json") }

    /// Mirrors `Client.Refresh`: a full online TUF update.
    public func refresh() async throws {
        do {
            up = try Updater(config: cfg)
        } catch {
            throw SigstoreError("failed to create tuf updater", underlying: error)
        }
        do {
            var u = up
            defer { up = u }
            try await u.refresh()
        } catch {
            throw SigstoreError("tuf refresh failed", underlying: error)
        }
        if cfg.disableLocalCache { return }
        var config = ClientConfig.load(configPath) ?? ClientConfig(lastTimestamp: .distantPast)
        config.lastTimestamp = Date()
        try? config.persist(configPath)
    }

    /// Mirrors `Client.GetTarget`: the target's bytes, from the cache when
    /// they match the trusted targets metadata, else downloaded.
    public func getTarget(_ target: String) async throws -> Data {
        let info: TargetFiles
        do {
            var u = up
            defer { up = u }
            info = try await u.getTargetInfo(target)
        } catch {
            throw SigstoreError("getting info for target \"\(target)\"", underlying: error)
        }
        if let (_, data) = try up.findCachedTarget(info) { return data }
        do {
            return try await up.downloadTarget(info).1
        } catch {
            throw SigstoreError("failed to download target file \(target)", underlying: error)
        }
    }

    /// The trusted metadata (for inspection and tests).
    public var trustedMetadata: TrustedMetadata { up.trusted }
}

/// Mirrors `tuf.URLToPath`.
public func urlToPath(_ url: String) -> String {
    var fn = url
    if fn.hasPrefix("https://") { fn.removeFirst("https://".count) }
    if fn.hasPrefix("http://") { fn.removeFirst("http://".count) }
    fn = fn.replacingOccurrences(of: "/", with: "-").replacingOccurrences(of: ":", with: "-")
    return fn.lowercased()
}
