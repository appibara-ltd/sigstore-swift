import Crypto
import Foundation
import Sigstore
import Testing

// MARK: - Test repository

/// Serves files from memory like a TUF HTTP mirror (404 for missing files,
/// `maxLength` enforced as go-tuf's DefaultFetcher does).
actor MemoryFetcher: Fetcher {
    var files: [String: Data]
    private(set) var requests: [String] = []
    var offline = false

    init(_ files: [String: Data]) { self.files = files }

    func set(_ path: String, _ data: Data?) { files[path] = data }
    func goOffline() { offline = true }

    func downloadFile(_ url: String, maxLength: Int64) async throws -> Data {
        requests.append(url)
        if offline { throw TUFError.download("offline: \(url)") }
        let path = url.replacingOccurrences(of: TestTUFRepo.baseURL + "/", with: "")
        guard let data = files[path] else { throw TUFError.downloadHTTP(statusCode: 404, url: url) }
        guard Int64(data.count) <= maxLength else {
            throw TUFError.downloadLengthMismatch("length \(data.count) is larger than expected \(maxLength)")
        }
        return data
    }
}

/// A signing key for test metadata.
struct TestKey {
    enum Kind { case ed25519(Curve25519.Signing.PrivateKey), p256(P256.Signing.PrivateKey) }
    let kind: Kind

    static func ed25519() -> TestKey { TestKey(kind: .ed25519(.init())) }
    static func p256() -> TestKey { TestKey(kind: .p256(.init())) }

    var json: JSONValue {
        switch kind {
        case .ed25519(let k):
            return .object([
                "keytype": .string("ed25519"), "scheme": .string("ed25519"),
                "keyval": .object(["public": .string(Hex.encode(k.publicKey.rawRepresentation))]),
            ])
        case .p256(let k):
            return .object([
                "keytype": .string("ecdsa"), "scheme": .string("ecdsa-sha2-nistp256"),
                "keyval": .object(["public": .string(k.publicKey.pemRepresentation)]),
            ])
        }
    }

    var id: String { Hex.encode(Array(SHA256.hash(data: try! json.canonicalBytes()))) }

    func sign(_ payload: [UInt8]) -> [UInt8] {
        switch kind {
        case .ed25519(let k): return Array(try! k.signature(for: payload))
        case .p256(let k): return Array(try! k.signature(for: payload).derRepresentation)
        }
    }
}

/// Builds and signs a small TUF repository (consistent snapshots).
struct TestTUFRepo {
    static let baseURL = "https://tuf.test"
    static let future = "2099-01-01T00:00:00Z"

    var files: [String: Data] = [:]
    var rootKeys = [TestKey.p256()]
    var timestampKey = TestKey.ed25519()
    var snapshotKey = TestKey.ed25519()
    var targetsKey = TestKey.p256()
    var rootVersion: Int64 = 1
    var timestampVersion: Int64 = 0

    static func metadata(_ signed: JSONValue, _ signers: [TestKey], extraSignatures: [JSONValue] = []) -> Data {
        let payload = try! signed.canonicalBytes()
        let sigs = signers.map {
            JSONValue.object(["keyid": .string($0.id), "sig": .string(Hex.encode($0.sign(payload)))])
        }
        let doc = JSONValue.object(["signed": signed, "signatures": .array(sigs + extraSignatures)])
        return Data(jsonText(doc).utf8)
    }

    func rootSigned(version: Int64, expires: String = future, threshold: Int = 1) -> JSONValue {
        var keys: [String: JSONValue] = [:]
        for k in rootKeys + [timestampKey, snapshotKey, targetsKey] { keys[k.id] = k.json }
        func role(_ ks: [TestKey], _ t: Int = 1) -> JSONValue {
            .object(["keyids": .array(ks.map { .string($0.id) }), "threshold": .number(String(t))])
        }
        return .object([
            "_type": .string("root"), "spec_version": .string("1.0.31"), "consistent_snapshot": .bool(true),
            "version": .number(String(version)), "expires": .string(expires), "keys": .object(keys),
            "roles": .object([
                "root": role(rootKeys, threshold), "timestamp": role([timestampKey]),
                "snapshot": role([snapshotKey]), "targets": role([targetsKey]),
            ]),
        ])
    }

    /// Publishes `version`.root.json signed by `signers` (default: current root keys).
    mutating func publishRoot(version: Int64, expires: String = future, signers: [TestKey]? = nil) -> Data {
        let data = Self.metadata(rootSigned(version: version, expires: expires), signers ?? rootKeys)
        files["\(version).root.json"] = data
        rootVersion = version
        return data
    }

    /// Publishes targets, snapshot and timestamp (all at `version`) for `targets`.
    mutating func publish(
        targets: [String: Data], version: Int64 = 1, delegations: JSONValue? = nil,
        expires: (timestamp: String, snapshot: String, targets: String) = (future, future, future)
    ) {
        var entries: [String: JSONValue] = [:]
        for (name, data) in targets {
            let hash = Hex.encode(Array(SHA256.hash(data: data)))
            entries[name] = .object([
                "length": .number(String(data.count)), "hashes": .object(["sha256": .string(hash)]),
            ])
            files["targets/\(hash).\(name)"] = data
        }
        var targetsObj: [String: JSONValue] = [
            "_type": .string("targets"), "spec_version": .string("1.0.31"), "version": .number(String(version)),
            "expires": .string(expires.targets), "targets": .object(entries),
        ]
        if let delegations { targetsObj["delegations"] = delegations }
        files["\(version).targets.json"] = Self.metadata(.object(targetsObj), [targetsKey])

        let snapshot = Self.metadata(
            .object([
                "_type": .string("snapshot"), "spec_version": .string("1.0.31"), "version": .number(String(version)),
                "expires": .string(expires.snapshot),
                "meta": .object(["targets.json": .object(["version": .number(String(version))])]),
            ]), [snapshotKey])
        files["\(version).snapshot.json"] = snapshot
        timestampVersion += 1
        files["timestamp.json"] = Self.metadata(
            .object([
                "_type": .string("timestamp"), "spec_version": .string("1.0.31"),
                "version": .number(String(timestampVersion)), "expires": .string(expires.timestamp),
                "meta": .object([
                    "snapshot.json": .object([
                        "version": .number(String(version)), "length": .number(String(snapshot.count)),
                        "hashes": .object(["sha256": .string(Hex.encode(Array(SHA256.hash(data: snapshot))))]),
                    ])
                ]),
            ]), [timestampKey])
    }

    static func standard() -> TestTUFRepo {
        var repo = TestTUFRepo()
        _ = repo.publishRoot(version: 1)
        repo.publish(targets: ["trusted_root.json": Data("{\"hello\":1}".utf8)])
        return repo
    }
}

/// Plain JSON serialization (escaped strings), as repositories serve metadata.
func jsonText(_ v: JSONValue) -> String {
    switch v {
    case .object(let o):
        return "{" + o.keys.sorted().map { "\(jsonText(.string($0))): \(jsonText(o[$0]!))" }.joined(separator: ", ") + "}"
    case .array(let a): return "[" + a.map(jsonText).joined(separator: ", ") + "]"
    case .number(let n): return n
    case .bool(let b): return b ? "true" : "false"
    case .null: return "null"
    case .string(let s):
        var out = "\""
        for u in s.unicodeScalars {
            switch u {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case _ where u.value < 0x20: out += String(format: "\\u%04x", u.value)
            default: out.unicodeScalars.append(u)
            }
        }
        return out + "\""
    }
}

private func tempDir() -> String {
    let dir = NSTemporaryDirectory() + "sigstore-swift-tuf-\(UUID().uuidString)"
    try! FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    return dir
}

private func options(_ root: Data, _ fetcher: MemoryFetcher, cache: String? = nil) -> SigstoreTUF.Options {
    var o = SigstoreTUF.Options().withRoot(root).withRepositoryBaseURL(TestTUFRepo.baseURL).withFetcher(fetcher)
    if let cache { o = o.withCachePath(cache) } else { o = o.withDisableLocalCache() }
    return o
}

private func expectTUFError(
    _ fragment: String, sourceLocation: SourceLocation = #_sourceLocation, _ body: () async throws -> Void
) async {
    do {
        try await body()
        Issue.record("expected an error containing \"\(fragment)\"", sourceLocation: sourceLocation)
    } catch {
        #expect("\(error)".contains(fragment), "unexpected error: \(error)", sourceLocation: sourceLocation)
    }
}

// MARK: - Tests

@Suite("TUF client")
struct TUFTests {
    /// GitHub's TUF repository (`tuf-repo.github.com`), captured 2026-11-25:
    /// starts from `gh`'s embedded root v3 and rotates to v9.
    private func githubFetcher() throws -> (Data, MemoryFetcher) {
        let dir = try #require(
            Foundation.Bundle.module.url(forResource: "tuf-repo.github.com", withExtension: nil, subdirectory: "Fixtures"))
        var files: [String: Data] = [:]
        for rel in try FileManager.default.subpathsOfDirectory(atPath: dir.path) {
            var isDir: ObjCBool = false
            let url = dir.appendingPathComponent(rel)
            guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir), !isDir.boolValue else { continue }
            files[rel.replacingOccurrences(of: "\\", with: "/")] = try Data(contentsOf: url)
        }
        return (files["3.root.json"]!, MemoryFetcher(files))
    }

    @Test func githubRepositoryRotatesRootAndServesTrustedRoot() async throws {
        let (root, fetcher) = try githubFetcher()
        var config = UpdaterConfig(remoteURL: TestTUFRepo.baseURL, rootBytes: root)
        config.disableLocalCache = true
        config.fetcher = fetcher
        var updater = try Updater(config: config)
        updater.unsafeSetRefTime(ISO8601DateFormatter().date(from: "2026-11-26T00:00:00Z")!)
        let info = try await updater.getTargetInfo("trusted_root.json")
        #expect(updater.trusted.root.signed.version == 9)
        let (_, data) = try await updater.downloadTarget(info)
        let trustedRoot = try TrustedRoot(json: data)
        #expect(trustedRoot.timestampingAuthorities.count == 6)
        // Same trust material as the fixture `gh attestation trusted-root` gave.
        let fixture = try Fixtures.githubTrustedRoot()
        #expect(trustedRoot.fulcioCertificateAuthorities.count == fixture.fulcioCertificateAuthorities.count)
    }

    @Test func githubRepositoryExpiresAtLaterReferenceTime() async throws {
        let (root, fetcher) = try githubFetcher()
        var config = UpdaterConfig(remoteURL: TestTUFRepo.baseURL, rootBytes: root)
        config.disableLocalCache = true
        config.fetcher = fetcher
        var updater = try Updater(config: config)
        updater.unsafeSetRefTime(ISO8601DateFormatter().date(from: "2026-12-03T00:00:00Z")!)
        await expectTUFError("timestamp.json is expired") { try await updater.refresh() }
    }

    @Test func clientDownloadsVerifiedTarget() async throws {
        let repo = TestTUFRepo.standard()
        let client = try await Client(options: options(repo.files["1.root.json"]!, MemoryFetcher(repo.files)))
        #expect(try await client.getTarget("trusted_root.json") == Data("{\"hello\":1}".utf8))
        await expectTUFError("target missing.json not found") { _ = try await client.getTarget("missing.json") }
    }

    @Test func rootRotationToNewKeys() async throws {
        var repo = TestTUFRepo.standard()
        let initial = repo.files["1.root.json"]!
        let oldKeys = repo.rootKeys
        repo.rootKeys = [.ed25519()]
        _ = repo.publishRoot(version: 2, signers: oldKeys + repo.rootKeys)
        let client = try await Client(options: options(initial, MemoryFetcher(repo.files)))
        #expect(await client.trustedMetadata.root.signed.version == 2)
    }

    @Test func rootNotSignedByPreviousRootFails() async throws {
        var repo = TestTUFRepo.standard()
        let initial = repo.files["1.root.json"]!
        repo.rootKeys = [.ed25519()]
        _ = repo.publishRoot(version: 2)  // only the new keys sign
        await expectTUFError("Verifying root failed, not enough signatures") {
            _ = try await Client(options: options(initial, MemoryFetcher(repo.files)))
        }
    }

    @Test func rootNotSignedByItsOwnKeysFails() async throws {
        var repo = TestTUFRepo.standard()
        let initial = repo.files["1.root.json"]!
        let oldKeys = repo.rootKeys
        repo.rootKeys = [.ed25519()]
        _ = repo.publishRoot(version: 2, signers: oldKeys)
        await expectTUFError("Verifying root failed, not enough signatures") {
            _ = try await Client(options: options(initial, MemoryFetcher(repo.files)))
        }
    }

    @Test func rootVersionMustIncrementByOne() async throws {
        var repo = TestTUFRepo.standard()
        let initial = repo.files["1.root.json"]!
        repo.files["2.root.json"] = TestTUFRepo.metadata(repo.rootSigned(version: 3), repo.rootKeys)
        await expectTUFError("bad version number, expected 2, got 3") {
            _ = try await Client(options: options(initial, MemoryFetcher(repo.files)))
        }
    }

    @Test(arguments: ["root", "timestamp", "snapshot", "targets"])
    func expiredMetadataFails(_ role: String) async throws {
        let past = "2020-01-01T00:00:00Z"
        var repo = TestTUFRepo()
        _ = repo.publishRoot(version: 1, expires: role == "root" ? past : TestTUFRepo.future)
        repo.publish(
            targets: ["t": Data("x".utf8)],
            expires: (
                role == "timestamp" ? past : TestTUFRepo.future, role == "snapshot" ? past : TestTUFRepo.future,
                role == "targets" ? past : TestTUFRepo.future
            ))
        let expected = role == "root" ? "final root.json is expired" : role == "targets" ? "new targets is expired" : "\(role).json is expired"
        await expectTUFError(expected) {
            _ = try await Client(options: options(repo.files["1.root.json"]!, MemoryFetcher(repo.files)))
        }
    }

    @Test func snapshotMustMatchTimestampHash() async throws {
        var repo = TestTUFRepo.standard()
        // Re-sign a different snapshot body without updating timestamp.
        repo.files["1.snapshot.json"] = TestTUFRepo.metadata(
            .object([
                "_type": .string("snapshot"), "spec_version": .string("1.0.31"), "version": .number("1"),
                // Same length as the published snapshot, different bytes.
                "expires": .string("2098-01-01T00:00:00Z"),
                "meta": .object(["targets.json": .object(["version": .number("1")])]),
            ]), [repo.snapshotKey])
        await expectTUFError("hash verification failed - mismatch for algorithm sha256") {
            _ = try await Client(options: options(repo.files["1.root.json"]!, MemoryFetcher(repo.files)))
        }
    }

    @Test func targetBytesMustMatchTargetsMetadata() async throws {
        var repo = TestTUFRepo.standard()
        let key = repo.files.keys.first { $0.hasPrefix("targets/") }!
        repo.files[key] = Data("{\"hello\":2}".utf8)  // same length, different hash
        let client = try await Client(options: options(repo.files["1.root.json"]!, MemoryFetcher(repo.files)))
        await expectTUFError("hash verification failed - mismatch for algorithm sha256") {
            _ = try await client.getTarget("trusted_root.json")
        }
    }

    @Test func targetsSignedByWrongKeyFails() async throws {
        var repo = TestTUFRepo.standard()
        let rogue = TestKey.p256()
        let good = repo.targetsKey
        repo.targetsKey = rogue
        repo.publish(targets: ["trusted_root.json": Data("{}".utf8)], version: 2)
        repo.targetsKey = good
        // Keep root v1 (which trusts `good`) as the initial root.
        await expectTUFError("Verifying targets failed, not enough signatures") {
            _ = try await Client(options: options(repo.files["1.root.json"]!, MemoryFetcher(repo.files)))
        }
    }

    @Test func thresholdCountsDistinctKeys() async throws {
        var repo = TestTUFRepo()
        let key = TestKey.p256()
        // Two key IDs for the same key, threshold 2: one key must not count twice.
        var signed = repo.rootSigned(version: 1, threshold: 2)
        if case .object(var o) = signed, case .object(var keys) = o["keys"]!, case .object(var roles) = o["roles"]! {
            keys = keys.filter { $0.key != repo.rootKeys[0].id }
            keys["alias-1"] = key.json
            keys["alias-2"] = key.json
            roles["root"] = .object(["keyids": .array([.string("alias-1"), .string("alias-2")]), "threshold": .number("2")])
            o["keys"] = .object(keys)
            o["roles"] = .object(roles)
            signed = .object(o)
        }
        let payload = try signed.canonicalBytes()
        let sig = JSONValue.string(Hex.encode(key.sign(payload)))
        let data = TestTUFRepo.metadata(
            signed, [],
            extraSignatures: [
                .object(["keyid": .string("alias-1"), "sig": sig]), .object(["keyid": .string("alias-2"), "sig": sig]),
            ])
        repo.files["1.root.json"] = data
        #expect { try TrustedMetadata(rootData: data) } throws: {
            "\($0)".contains("Verifying root failed, not enough signatures, got 1, want 2")
        }
    }

    @Test func duplicateSignatureKeyIDsAreRejected() throws {
        let repo = TestTUFRepo()
        let signed = repo.rootSigned(version: 1)
        let sig = JSONValue.object([
            "keyid": .string(repo.rootKeys[0].id),
            "sig": .string(Hex.encode(repo.rootKeys[0].sign(try signed.canonicalBytes()))),
        ])
        let data = TestTUFRepo.metadata(signed, [], extraSignatures: [sig, sig])
        #expect { try Metadata<RootType>(fromBytes: data) } throws: {
            "\($0)".contains("multiple signatures found for key ID")
        }
    }

    @Test func wrongMetadataTypeIsRejected() throws {
        let repo = TestTUFRepo.standard()
        #expect { try Metadata<RootType>(fromBytes: repo.files["timestamp.json"]!) } throws: {
            "\($0)".contains("expected metadata type root, got - timestamp")
        }
    }

    @Test func oversizedSnapshotIsRejected() async throws {
        var repo = TestTUFRepo.standard()
        // Serve a longer snapshot than timestamp's meta length allows.
        repo.files["1.snapshot.json"]! += Data(" ".utf8)
        await expectTUFError("larger than expected") {
            _ = try await Client(options: options(repo.files["1.root.json"]!, MemoryFetcher(repo.files)))
        }
    }

    @Test func timestampRollbackIsRejected() async throws {
        var repo = TestTUFRepo.standard()
        let oldTimestamp = repo.files["timestamp.json"]!
        repo.publish(targets: ["trusted_root.json": Data("{\"hello\":1}".utf8)], version: 2)
        let cache = tempDir()
        let fetcher = MemoryFetcher(repo.files)
        _ = try await Client(options: options(repo.files["1.root.json"]!, fetcher, cache: cache))
        await fetcher.set("timestamp.json", oldTimestamp)
        await expectTUFError("new timestamp version 1 must be >= 2") {
            _ = try await Client(options: options(repo.files["1.root.json"]!, fetcher, cache: cache))
        }
    }

    @Test func forceCacheWorksOffline() async throws {
        let repo = TestTUFRepo.standard()
        let cache = tempDir()
        let fetcher = MemoryFetcher(repo.files)
        let first = try await Client(options: options(repo.files["1.root.json"]!, fetcher, cache: cache))
        _ = try await first.getTarget("trusted_root.json")
        await fetcher.goOffline()
        let offline = try await Client(options: options(repo.files["1.root.json"]!, fetcher, cache: cache).withForceCache())
        #expect(try await offline.getTarget("trusted_root.json") == Data("{\"hello\":1}".utf8))
        // Without force/validity the client refreshes, which fails offline.
        await expectTUFError("tuf refresh failed") {
            _ = try await Client(options: options(repo.files["1.root.json"]!, fetcher, cache: cache))
        }
    }

    @Test func delegatedTargetsAreFound() async throws {
        var repo = TestTUFRepo()
        _ = repo.publishRoot(version: 1)
        let delegateKey = TestKey.ed25519()
        let delegations = JSONValue.object([
            "keys": .object([delegateKey.id: delegateKey.json]),
            "roles": .array([
                .object([
                    "name": .string("stop"), "keyids": .array([.string(delegateKey.id)]), "threshold": .number("1"),
                    "terminating": .bool(true), "paths": .array([.string("sub/z.json")]),
                ]),
                .object([
                    "name": .string("delegate"), "keyids": .array([.string(delegateKey.id)]), "threshold": .number("1"),
                    "terminating": .bool(false), "paths": .array([.string("sub/*.json")]),
                ]),
            ]),
        ])
        repo.publish(targets: [:], delegations: delegations)
        // Delegated role metadata, listed in snapshot.
        let data = Data("delegated".utf8)
        let hash = Hex.encode(Array(SHA256.hash(data: data)))
        repo.files["targets/sub/\(hash).x.json"] = data
        let entry = JSONValue.object(["length": .number(String(data.count)), "hashes": .object(["sha256": .string(hash)])])
        func role(_ targets: [String: JSONValue]) -> Data {
            TestTUFRepo.metadata(
                .object([
                    "_type": .string("targets"), "spec_version": .string("1.0.31"), "version": .number("1"),
                    "expires": .string(TestTUFRepo.future), "targets": .object(targets),
                ]), [delegateKey])
        }
        // "delegate" also lists sub/z.json, but the terminating "stop" role is
        // visited first for that path and has no such target.
        repo.files["1.delegate.json"] = role(["sub/x.json": entry, "sub/z.json": entry])
        repo.files["1.stop.json"] = role([:])
        // Rebuild snapshot + timestamp to include delegate.json.
        let snapshot = TestTUFRepo.metadata(
            .object([
                "_type": .string("snapshot"), "spec_version": .string("1.0.31"), "version": .number("1"),
                "expires": .string(TestTUFRepo.future),
                "meta": .object([
                    "targets.json": .object(["version": .number("1")]), "delegate.json": .object(["version": .number("1")]),
                    "stop.json": .object(["version": .number("1")]),
                ]),
            ]), [repo.snapshotKey])
        repo.files["1.snapshot.json"] = snapshot
        repo.files["timestamp.json"] = TestTUFRepo.metadata(
            .object([
                "_type": .string("timestamp"), "spec_version": .string("1.0.31"), "version": .number("9"),
                "expires": .string(TestTUFRepo.future),
                "meta": .object(["snapshot.json": .object(["version": .number("1")])]),
            ]), [repo.timestampKey])
        let client = try await Client(options: options(repo.files["1.root.json"]!, MemoryFetcher(repo.files)))
        #expect(try await client.getTarget("sub/x.json") == data)
        await expectTUFError("target sub/z.json not found") { _ = try await client.getTarget("sub/z.json") }
    }

    @Test func pathPatternsFollowFilepathMatch() {
        let cases: [(String, String, Bool)] = [
            ("a/b.json", "a/*.json", true), ("a/b/c.json", "a/*.json", false), ("ab", "a?", true),
            ("ab", "a[a-c]", true), ("ad", "a[^a-c]", true), ("ab", "a[^a-c]", false), ("a*", "a\\*", true),
            ("ab", "a\\*", false), ("x", "[", false),
        ]
        for (target, pattern, expected) in cases {
            let role = try! DelegatedRole(
                JSONValue.object([
                    "name": .string("r"), "keyids": .array([]), "threshold": .number("1"),
                    "paths": .array([.string(pattern)]),
                ]))
            #expect(role.isDelegatedPath(target) == expected, "\(target) ~ \(pattern)")
        }
    }

    @Test func succinctRoleBins() throws {
        let roles = try SuccinctRoles(
            JSONValue.object([
                "keyids": .array([]), "threshold": .number("1"), "bit_length": .number("8"),
                "name_prefix": .string("bin"),
            ]))
        let name = roles.rolesForTarget("trusted_root.json")[0].name
        let first = Array(SHA256.hash(data: Data("trusted_root.json".utf8)))[0]
        #expect(name == "bin-" + String(format: "%02x", first))
    }

    @Test func canonicalJSONMatchesSecuresystemslib() throws {
        let input = #"{"b":[1,true,null],"a":"q\"\\é<\u0001","A":{"z":-3,"y":"\/"}}"#
        let out = String(decoding: try JSONValue(parsing: Data(input.utf8)).canonicalBytes(), as: UTF8.self)
        #expect(out == "{\"A\":{\"y\":\"/\",\"z\":-3},\"a\":\"q\\\"\\\\é<\u{01}\",\"b\":[1,true,null]}")
        #expect(throws: (any Error).self) { try JSONValue(parsing: Data(#"{"a":1.5}"#.utf8)).canonicalBytes() }
    }

    @Test func embeddedRootsAreSelfSigned() throws {
        #expect(try TrustedMetadata(rootData: defaultRoot()).root.signed.version >= 1)
        #expect(try TrustedMetadata(rootData: stagingRoot()).root.signed.version >= 1)
    }

    @Test func urlToPathMatchesGo() {
        #expect(urlToPath("https://tuf-repo-cdn.sigstore.dev") == "tuf-repo-cdn.sigstore.dev")
        #expect(urlToPath("http://Example.com:8080/a/b") == "example.com-8080-a-b")
    }
}
