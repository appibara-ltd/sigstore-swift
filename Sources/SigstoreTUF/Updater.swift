// Port of go-tuf v2.4.2 metadata/config, metadata/fetcher and
// metadata/updater: the TUF client workflow (detailed client workflow of
// the TUF specification) with a local metadata/target cache.

import Crypto
import Foundation
import SigstoreCommon

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Fetcher

/// Mirrors `fetcher.Fetcher`.
public protocol Fetcher: Sendable {
    /// Downloads `url`, failing with `TUFError.downloadHTTP` on a non-200
    /// status and `TUFError.downloadLengthMismatch` above `maxLength` bytes.
    func downloadFile(_ url: String, maxLength: Int64) async throws -> Data
}

/// Mirrors `fetcher.DefaultFetcher` as configured by sigstore-go
/// (`newDefaultFetcher`: retrying HTTP client, sigstore user agent).
///
/// Like go-tuf, a response whose `Content-Length` exceeds `maxLength` is
/// rejected before its body is read, and the body is streamed and
/// abandoned as soon as it exceeds `maxLength`, whatever the header says.
public struct DefaultFetcher: Fetcher {
    /// The `User-Agent` header sent with each request.
    public var userAgent: String
    /// Attempts for transport errors, 429 and 5xx responses.
    public var maxAttempts: Int
    /// Builds the session configuration for each download (tests inject
    /// `protocolClasses`).
    public var sessionConfiguration: @Sendable () -> URLSessionConfiguration

    /// Creates a fetcher.
    ///
    /// - Parameters:
    ///   - userAgent: The `User-Agent` header value.
    ///   - maxAttempts: Attempts for transport errors, 429 and 5xx responses.
    ///   - sessionConfiguration: Builds the session configuration for each
    ///     download.
    public init(
        userAgent: String = "sigstore-swift", maxAttempts: Int = 3,
        sessionConfiguration: @escaping @Sendable () -> URLSessionConfiguration = { .ephemeral }
    ) {
        self.userAgent = userAgent
        self.maxAttempts = maxAttempts
        self.sessionConfiguration = sessionConfiguration
    }

    /// Downloads `url`, retrying with backoff on transport errors, 429 and
    /// 5xx responses up to ``maxAttempts`` times.
    ///
    /// - Throws: ``TUFError/downloadHTTP(statusCode:url:)`` on a non-200
    ///   status, ``TUFError/downloadLengthMismatch(_:)`` above `maxLength`
    ///   bytes, ``TUFError/download(_:)`` on an invalid URL or transport error.
    public func downloadFile(_ url: String, maxLength: Int64) async throws -> Data {
        guard let u = URL(string: url) else { throw TUFError.download("invalid URL \(url)") }
        var request = URLRequest(url: u)
        request.setValue(userAgent, forHTTPHeaderField: "User-Agent")
        var attempt = 0
        while true {
            attempt += 1
            do {
                return try await LimitedDownload(url: url, maxLength: maxLength).run(
                    request, configuration: sessionConfiguration())
            } catch TUFError.downloadHTTP(let status, _) where (status == 429 || status >= 500) && attempt < maxAttempts {
                try await backoff(attempt)
            } catch let error as TUFError {
                throw error
            } catch {
                guard attempt < maxAttempts else { throw TUFError.download("\(url): \(error)") }
                try await backoff(attempt)
            }
        }
    }

    private func backoff(_ attempt: Int) async throws {
        try await Task.sleep(nanoseconds: UInt64(attempt) * 500_000_000)
    }
}

/// One size-limited download (the `io.LimitReader(res.Body, maxLength+1)`
/// of go-tuf's fetcher, as a URLSession delegate).
final class LimitedDownload: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let url: String
    private let maxLength: Int64
    private let lock = NSLock()
    private var received = Data()
    private var failure: (any Error)?
    private var continuation: CheckedContinuation<Data, any Error>?

    init(url: String, maxLength: Int64) {
        self.url = url
        self.maxLength = maxLength
    }

    func run(_ request: URLRequest, configuration: URLSessionConfiguration) async throws -> Data {
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        return try await withCheckedThrowingContinuation { continuation in
            lock.lock()
            self.continuation = continuation
            lock.unlock()
            session.dataTask(with: request).resume()
        }
    }

    private func fail(_ error: any Error) {
        lock.lock()
        if failure == nil { failure = error }
        lock.unlock()
    }

    private func tooLarge(_ length: Int64) -> TUFError {
        .downloadLengthMismatch("download failed for \(url), length \(length) is larger than expected \(maxLength)")
    }

    func urlSession(
        _ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {
        guard let http = response as? HTTPURLResponse else {
            fail(TUFError.download("not an HTTP response"))
            return completionHandler(.cancel)
        }
        guard http.statusCode == 200 else {
            fail(TUFError.downloadHTTP(statusCode: http.statusCode, url: url))
            return completionHandler(.cancel)
        }
        if http.expectedContentLength > maxLength {
            fail(tooLarge(http.expectedContentLength))
            return completionHandler(.cancel)
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        received.append(data)
        let count = Int64(received.count)
        lock.unlock()
        if count > maxLength {
            fail(tooLarge(count))
            dataTask.cancel()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        let result: Result<Data, any Error>
        if let failure {
            result = .failure(failure)
        } else if let error {
            result = .failure(error)
        } else {
            result = .success(received)
        }
        received = Data()
        lock.unlock()
        continuation?.resume(with: result)
    }
}

// MARK: - Config

/// Mirrors `config.UpdaterConfig`.
public struct UpdaterConfig: Sendable {
    /// Maximum number of root versions fetched in one update.
    public var maxRootRotations: Int64 = 256
    /// Maximum number of delegated roles visited when searching a target.
    public var maxDelegations = 32
    /// Maximum size in bytes of a downloaded `root.json`.
    public var rootMaxLength: Int64 = 512_000
    /// Maximum size in bytes of a downloaded `timestamp.json`.
    public var timestampMaxLength: Int64 = 16_384
    /// Maximum size in bytes of a downloaded `snapshot.json` when the
    /// timestamp gives no length.
    public var snapshotMaxLength: Int64 = 2_000_000
    /// Maximum size in bytes of a downloaded targets metadata file when the
    /// snapshot gives no length.
    public var targetsMaxLength: Int64 = 5_000_000
    /// Downloads metadata and targets.
    public var fetcher: any Fetcher = DefaultFetcher()
    /// The initial trusted `root.json` bytes.
    public var localTrustedRoot: Data
    /// Directory where trusted metadata is cached.
    public var localMetadataDir = ""
    /// Directory where downloaded targets are cached.
    public var localTargetsDir = ""
    /// Base URL of the repository's metadata.
    public var remoteMetadataURL: String
    /// Base URL of the repository's target files.
    public var remoteTargetsURL: String
    /// Keep metadata and targets in memory only; nothing is written to or
    /// read from disk.
    public var disableLocalCache = false
    /// Download targets by hash-prefixed name when the root enables
    /// consistent snapshots.
    public var prefixTargetsWithHash = true
    /// Use only the metadata cached on disk; ``Updater/refresh()`` fails if
    /// it is incomplete.
    public var unsafeLocalMode = false

    /// Mirrors `config.New`: targets default to `<remoteURL>/targets`.
    public init(remoteURL: String, rootBytes: Data) {
        localTrustedRoot = rootBytes
        remoteMetadataURL = remoteURL
        var base = remoteURL
        while base.hasSuffix("/") { base.removeLast() }
        remoteTargetsURL = base + "/targets"
    }

    /// Mirrors `EnsurePathsExist` (directories created 0700).
    public func ensurePathsExist() throws {
        if disableLocalCache { return }
        for path in [localMetadataDir, localTargetsDir] {
            try FileManager.default.createDirectory(
                atPath: path, withIntermediateDirectories: true, attributes: posixAttributes(0o700))
        }
    }
}

func posixAttributes(_ mode: Int) -> [FileAttributeKey: Any]? {
    #if os(Windows)
    return nil
    #else
    return [.posixPermissions: mode]
    #endif
}

// MARK: - Updater

/// Mirrors `updater.Updater`.
public struct Updater: Sendable {
    /// The metadata trusted so far.
    public private(set) var trusted: TrustedMetadata
    /// The configuration the updater was created with.
    public let config: UpdaterConfig

    /// Mirrors `updater.New`: loads the trusted root and persists it.
    public init(config: UpdaterConfig) throws {
        guard !config.localTrustedRoot.isEmpty, !config.remoteMetadataURL.isEmpty else {
            throw TUFError.value("no initial trusted root metadata or remote URL provided")
        }
        trusted = try TrustedMetadata(rootData: config.localTrustedRoot)
        self.config = config
        try config.ensurePathsExist()
        try persistMetadata(TUFRole.root, config.localTrustedRoot)
    }

    /// Mirrors `UnsafeSetRefTime` (tests).
    public mutating func unsafeSetRefTime(_ t: Date) { trusted.refTime = t }

    /// Mirrors `Refresh`.
    public mutating func refresh() async throws {
        if config.unsafeLocalMode {
            try unsafeLocalRefresh()
        } else {
            try await onlineRefresh()
        }
    }

    private mutating func onlineRefresh() async throws {
        try await loadRoot()
        try await loadTimestamp()
        try await loadSnapshot()
        _ = try await loadTargets(TUFRole.targets, parent: TUFRole.root)
    }

    /// Loads timestamp, snapshot and targets from the local cache only.
    private mutating func unsafeLocalRefresh() throws {
        try trusted.updateTimestamp(try loadLocalMetadata(TUFRole.timestamp))
        try trusted.updateSnapshot(try loadLocalMetadata(TUFRole.snapshot), isTrusted: false)
        try trusted.updateDelegatedTargets(
            try loadLocalMetadata(TUFRole.targets), roleName: TUFRole.targets, delegatorName: TUFRole.root)
    }

    /// Mirrors `GetTargetInfo`.
    public mutating func getTargetInfo(_ targetPath: String) async throws -> TargetFiles {
        if trusted.targets[TUFRole.targets] == nil { try await refresh() }
        return try await preOrderDepthFirstWalk(targetPath)
    }

    /// Mirrors `DownloadTarget` (with an empty `targetBaseURL`).
    public func downloadTarget(_ targetFile: TargetFiles, filePath: String? = nil) async throws -> (String, Data) {
        let path = try filePath ?? generateTargetFilePath(targetFile)
        var remotePath = targetFile.path
        if trusted.root.signed.consistentSnapshot && config.prefixTargetsWithHash {
            // Go takes an arbitrary (map-order) hash; prefer sha256. Parsed
            // targets always have one, but `hashes` is a public var: throw
            // (as Go's VerifyLengthHashes later would) rather than trap.
            let alg = targetFile.hashes["sha256"] != nil ? "sha256" : targetFile.hashes.keys.sorted().first
            guard let alg, let digest = targetFile.hashes[alg] else {
                throw TUFError.lengthOrHashMismatch("hashes must not be empty for target files")
            }
            let prefix = Hex.encode(digest)
            if let slash = remotePath.lastIndex(of: "/") {
                remotePath = "\(remotePath[..<slash])/\(prefix).\(remotePath[remotePath.index(after: slash)...])"
            } else {
                remotePath = "\(prefix).\(remotePath)"
            }
        }
        let data = try await config.fetcher.downloadFile(
            ensureTrailingSlash(config.remoteTargetsURL) + remotePath, maxLength: targetFile.length)
        try targetFile.verifyLengthHashes(data)
        if !config.disableLocalCache {
            try data.write(to: URL(fileURLWithPath: path))
        }
        return (path, data)
    }

    /// Mirrors `FindCachedTarget`: a cached target is used only if its
    /// length and hashes match.
    public func findCachedTarget(_ targetFile: TargetFiles, filePath: String? = nil) throws -> (String, Data)? {
        if config.disableLocalCache { return nil }
        let path = try filePath ?? generateTargetFilePath(targetFile)
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        guard (try? targetFile.verifyLengthHashes(data)) != nil else { return nil }
        return (path, data)
    }

    private mutating func loadTimestamp() async throws {
        if let data = try? loadLocalMetadata(TUFRole.timestamp) {
            do {
                try trusted.updateTimestamp(data)
            } catch let error as TUFError where error.isRepository {
                // Cached timestamp is unusable; fall through to download.
            }
        }
        let data = try await downloadMetadata(TUFRole.timestamp, length: config.timestampMaxLength, version: nil)
        do {
            try trusted.updateTimestamp(data)
        } catch TUFError.equalVersionNumber {
            return  // the cached one is current
        }
        try persistMetadata(TUFRole.timestamp, data)
    }

    private mutating func loadSnapshot() async throws {
        if let data = try? loadLocalMetadata(TUFRole.snapshot) {
            do {
                try trusted.updateSnapshot(data, isTrusted: true)
                return
            } catch let error as TUFError where error.isRepository {
                // fall through to download
            }
        }
        guard let timestamp = trusted.timestamp else { throw TUFError.runtime("trusted timestamp not set") }
        let meta = timestamp.signed.meta["snapshot.json"]
        var length = meta?.length ?? 0
        if length == 0 { length = config.snapshotMaxLength }
        let version = trusted.root.signed.consistentSnapshot ? String(meta?.version ?? 0) : nil
        let data = try await downloadMetadata(TUFRole.snapshot, length: length, version: version)
        try trusted.updateSnapshot(data, isTrusted: false)
        try persistMetadata(TUFRole.snapshot, data)
    }

    private mutating func loadTargets(_ role: String, parent: String) async throws -> Metadata<TargetsType> {
        if let loaded = trusted.targets[role] { return loaded }
        if let data = try? loadLocalMetadata(role) {
            do {
                return try trusted.updateDelegatedTargets(data, roleName: role, delegatorName: parent)
            } catch let error as TUFError where error.isRepository {
                // fall through to download
            }
        }
        guard let snapshot = trusted.snapshot else { throw TUFError.runtime("trusted snapshot not set") }
        guard let meta = snapshot.signed.meta["\(role).json"] else {
            throw TUFError.runtime("role \(role) not found in snapshot")
        }
        let length = meta.length == 0 ? config.targetsMaxLength : meta.length
        let version = trusted.root.signed.consistentSnapshot ? String(meta.version) : nil
        let data = try await downloadMetadata(role, length: length, version: version)
        let delegated = try trusted.updateDelegatedTargets(data, roleName: role, delegatorName: parent)
        try persistMetadata(role, data)
        return delegated
    }

    /// Mirrors `loadRoot`: walks root versions N+1, N+2, ... (at most
    /// `maxRootRotations`) until the repository returns 404.
    private mutating func loadRoot() async throws {
        let lower = trusted.root.signed.version + 1
        let upper = lower + config.maxRootRotations
        var next = lower
        while next < upper {
            let data: Data
            do {
                data = try await downloadMetadata(TUFRole.root, length: config.rootMaxLength, version: String(next))
            } catch TUFError.downloadHTTP(let status, _) where status == 404 {
                break
            }
            try trusted.updateRoot(data)
            try persistMetadata(TUFRole.root, data)
            next += 1
        }
    }

    /// Mirrors `preOrderDepthFirstWalk`: searches the delegation graph in
    /// pre-order, honouring terminating delegations and `maxDelegations`.
    private mutating func preOrderDepthFirstWalk(_ targetPath: String) async throws -> TargetFiles {
        var toVisit: [(role: String, parent: String)] = [(TUFRole.targets, TUFRole.root)]
        var visited = Set<String>()
        while visited.count <= config.maxDelegations, let delegation = toVisit.popLast() {
            if visited.contains(delegation.role) { continue }
            let targets = try await loadTargets(delegation.role, parent: delegation.parent)
            if let target = targets.signed.targets[targetPath] { return target }
            visited.insert(delegation.role)
            if let delegations = targets.signed.delegations {
                var children: [(role: String, parent: String)] = []
                for r in delegations.rolesForTarget(targetPath) {
                    children.append((r.name, delegation.role))
                    if r.terminating {
                        toVisit = []
                        break
                    }
                }
                toVisit += children.reversed()
            }
        }
        throw TUFError.value("target \(targetPath) not found")
    }

    /// Mirrors `persistMetadata`: atomic write, then read back and compare.
    private func persistMetadata(_ role: String, _ data: Data) throws {
        if config.disableLocalCache { return }
        let path = joinPath(config.localMetadataDir, "\(pathEscape(role)).json")
        let url = URL(fileURLWithPath: path)
        try data.write(to: url, options: .atomic)
        if let attrs = posixAttributes(0o644) { try? FileManager.default.setAttributes(attrs, ofItemAtPath: path) }
        guard FileManager.default.contents(atPath: path) == data else {
            throw TUFError.runtime("failed to persist metadata")
        }
    }

    private func downloadMetadata(_ role: String, length: Int64, version: String?) async throws -> Data {
        let base = ensureTrailingSlash(config.remoteMetadataURL)
        let url = version.map { "\(base)\($0).\(pathEscape(role)).json" } ?? "\(base)\(pathEscape(role)).json"
        return try await config.fetcher.downloadFile(url, maxLength: length)
    }

    private func generateTargetFilePath(_ tf: TargetFiles) throws -> String {
        if config.localTargetsDir.isEmpty && !config.disableLocalCache {
            throw TUFError.value("LocalTargetsDir must be set if filepath is not given")
        }
        return joinPath(config.localTargetsDir, pathEscape(tf.path))
    }

    private func loadLocalMetadata(_ role: String) throws -> Data {
        let path = joinPath(config.localMetadataDir, role) + ".json"
        guard let data = FileManager.default.contents(atPath: path) else {
            throw TUFError.runtime("no local metadata at \(path)")
        }
        return data
    }
}

/// Go `url.PathEscape`: escapes everything except unreserved characters
/// and `$&+:=@`.
func pathEscape(_ s: String) -> String {
    var allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~")
    allowed.insert(charactersIn: "$&+:=@")
    return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
}

func ensureTrailingSlash(_ url: String) -> String { url.hasSuffix("/") ? url : url + "/" }

/// `filepath.Join` for two components, using the platform separator.
func joinPath(_ dir: String, _ name: String) -> String {
    if dir.isEmpty { return name }
    return URL(fileURLWithPath: dir, isDirectory: true).appendingPathComponent(name).path
}
