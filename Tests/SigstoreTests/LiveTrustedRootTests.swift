import Foundation
import Sigstore
import Synchronization
import Testing

/// Collects refresh results from LiveTrustedRoot's observer.
private final class RefreshLog: Sendable {
    private let results = Mutex<[Bool]>([])
    func record(_ r: Result<TrustedRoot, any Error>) {
        results.withLock { $0.append((try? r.get()) != nil) }
    }
    var values: [Bool] { results.withLock { $0 } }
}

private func fixture(_ name: String) throws -> Data {
    let url = try #require(Foundation.Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
    return try Data(contentsOf: url)
}

private func waitUntil(_ condition: () -> Bool) async throws {
    for _ in 0..<200 where !condition() { try await Task.sleep(for: .milliseconds(20)) }
}

@Suite("LiveTrustedRoot")
struct LiveTrustedRootTests {
    @Test func refreshesInTheBackgroundAndKeepsLastGoodRoot() async throws {
        var repo = TestTUFRepo()
        _ = repo.publishRoot(version: 1)
        repo.publish(targets: ["trusted_root.json": try fixture("trusted_root")])
        let fetcher = MemoryFetcher(repo.files)
        let options = SigstoreTUF.Options().withRoot(repo.files["1.root.json"]!)
            .withRepositoryBaseURL(TestTUFRepo.baseURL).withFetcher(fetcher).withDisableLocalCache()
        let log = RefreshLog()
        let live = try await LiveTrustedRoot(options: options, refreshPeriod: .milliseconds(50)) { log.record($0) }
        #expect(live.rekorLogs.count == 2)  // public-good snapshot

        // The repository publishes GitHub's trusted root (no Rekor logs).
        repo.publish(targets: ["trusted_root.json": try fixture("github_trusted_root")], version: 2)
        for (path, data) in repo.files { await fetcher.set(path, data) }
        try await waitUntil { live.rekorLogs.isEmpty }
        #expect(live.rekorLogs.isEmpty)
        #expect(live.timestampingAuthorities.count == 6)

        // A failing refresh keeps the last good root.
        await fetcher.goOffline()
        let before = log.values.count
        try await waitUntil { log.values.count > before }
        #expect(log.values.last == false)
        #expect(live.timestampingAuthorities.count == 6)

        live.stop()
        let afterStop = log.values.count
        try await Task.sleep(for: .milliseconds(200))
        #expect(log.values.count <= afterStop + 1)  // at most one in-flight attempt
    }

    @Test func initialFetchFailureThrows() async throws {
        let repo = TestTUFRepo.standard()  // trusted_root.json is not a trusted root
        let options = SigstoreTUF.Options().withRoot(repo.files["1.root.json"]!)
            .withRepositoryBaseURL(TestTUFRepo.baseURL).withFetcher(MemoryFetcher(repo.files)).withDisableLocalCache()
        await #expect(throws: (any Error).self) { _ = try await LiveTrustedRoot(options: options) }
    }
}
