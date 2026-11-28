// The HTTP plumbing of sigstore-go v1.4.1 pkg/sign (retry.go, useragent.go)
// and sigstore/sigstore v1.11.4 pkg/httpretry, over URLSession.

import Foundation
import SigstoreCommon

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Mirrors Go's `http.RoundTripper` as sigstore-go's clients use it: sends
/// one request and returns the response body and head.
public protocol HTTPTransport: Sendable {
    /// Sends `request`. Throws on transport errors, not on HTTP error
    /// statuses.
    func roundTrip(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

/// The default transport (Go `http.DefaultTransport`): one URLSession data
/// task per request, with the response body capped at
/// ``maxResponseLength`` bytes.
public struct URLSessionTransport: HTTPTransport {
    /// Responses with a longer body fail instead of being buffered.
    public var maxResponseLength: Int
    /// Builds the session configuration for each request (tests inject
    /// `protocolClasses`).
    public var sessionConfiguration: @Sendable () -> URLSessionConfiguration

    /// Creates a transport.
    public init(
        maxResponseLength: Int = 16 << 20,
        sessionConfiguration: @escaping @Sendable () -> URLSessionConfiguration = { .ephemeral }
    ) {
        self.maxResponseLength = maxResponseLength
        self.sessionConfiguration = sessionConfiguration
    }

    /// Sends `request` and buffers the response body.
    ///
    /// - Throws: Transport errors, a body over ``maxResponseLength`` bytes,
    ///   or `CancellationError` when the task is cancelled.
    public func roundTrip(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let task = BufferedTask(maxLength: maxResponseLength)
        return try await task.run(request, configuration: sessionConfiguration())
    }
}

/// One size-limited request, as a URLSession delegate.
final class BufferedTask: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let maxLength: Int
    private let lock = NSLock()
    private var received = Data()
    private var response: HTTPURLResponse?
    private var failure: (any Error)?
    private var continuation: CheckedContinuation<(Data, HTTPURLResponse), any Error>?
    private var task: URLSessionDataTask?

    init(maxLength: Int) {
        self.maxLength = maxLength
    }

    func run(_ request: URLRequest, configuration: URLSessionConfiguration) async throws -> (Data, HTTPURLResponse) {
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let task = session.dataTask(with: request)
                lock.lock()
                self.continuation = continuation
                self.task = task
                lock.unlock()
                task.resume()
            }
        } onCancel: {
            fail(CancellationError())
            lock.lock()
            let task = self.task
            lock.unlock()
            task?.cancel()
        }
    }

    private func fail(_ error: any Error) {
        lock.lock()
        if failure == nil { failure = error }
        lock.unlock()
    }

    func urlSession(
        _ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {
        guard let http = response as? HTTPURLResponse else {
            fail(SigstoreError("not an HTTP response"))
            return completionHandler(.cancel)
        }
        if http.expectedContentLength > Int64(maxLength) {
            fail(SigstoreError("response body larger than \(maxLength) bytes"))
            return completionHandler(.cancel)
        }
        lock.lock()
        self.response = http
        lock.unlock()
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        received.append(data)
        let count = received.count
        lock.unlock()
        if count > maxLength {
            fail(SigstoreError("response body larger than \(maxLength) bytes"))
            dataTask.cancel()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        let result: Result<(Data, HTTPURLResponse), any Error>
        if let failure {
            result = .failure(failure)
        } else if let error {
            result = .failure(error)
        } else if let response {
            result = .success((received, response))
        } else {
            result = .failure(SigstoreError("no HTTP response"))
        }
        received = Data()
        lock.unlock()
        continuation?.resume(with: result)
    }
}

/// Mirrors sigstore `httpretry.Transport`: retries transient failures
/// (transport errors, HTTP 429, and HTTP 5xx other than 501) with jittered
/// exponential backoff that honours `Retry-After`.
public struct HTTPRetryTransport: HTTPTransport {
    /// The wrapped transport.
    public var base: any HTTPTransport
    /// Retries after the first attempt; zero disables retrying.
    public var maxRetries: Int
    /// The first backoff delay, in seconds.
    public var waitMin: TimeInterval
    /// The largest backoff delay, in seconds.
    public var waitMax: TimeInterval

    /// Mirrors `httpretry.NewTransport` (4 retries, 1 s to 30 s); `base`
    /// defaults to ``URLSessionTransport``.
    public init(
        base: (any HTTPTransport)? = nil, maxRetries: Int = 4, waitMin: TimeInterval = 1, waitMax: TimeInterval = 30
    ) {
        self.base = base ?? URLSessionTransport()
        self.maxRetries = maxRetries
        self.waitMin = waitMin
        self.waitMax = waitMax
    }

    /// Sends `request`, retrying transient failures up to ``maxRetries``
    /// times; returns the last response or error.
    public func roundTrip(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var attempt = 0
        while true {
            let result: Result<(Data, HTTPURLResponse), any Error>
            do {
                result = .success(try await base.roundTrip(request))
            } catch {
                result = .failure(error)
            }
            guard attempt < max(maxRetries, 0), Self.shouldRetry(result) else {
                return try result.get()
            }
            let response = try? result.get().1
            let delay = Self.backoff(waitMin: waitMin, waitMax: waitMax, attempt: attempt, response: response)
            if delay > 0 {
                try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            } else {
                try Task.checkCancellation()
            }
            attempt += 1
        }
    }

    /// Mirrors `httpretry.DefaultRetryPolicy`.
    static func shouldRetry(_ result: Result<(Data, HTTPURLResponse), any Error>) -> Bool {
        if Task.isCancelled { return false }
        switch result {
        case .failure(let error): return retryableError(error)
        case .success(let (_, response)):
            let status = response.statusCode
            return status == 429 || status == 0 || (status >= 500 && status != 501)
        }
    }

    /// Mirrors `httpretry.retryableError`: not cancellation, bad URLs,
    /// redirect loops or certificate errors.
    static func retryableError(_ error: any Error) -> Bool {
        if error is CancellationError { return false }
        guard let urlError = error as? URLError else { return true }
        switch urlError.code {
        case .cancelled, .badURL, .unsupportedURL, .httpTooManyRedirects,
            .serverCertificateUntrusted, .serverCertificateHasBadDate, .serverCertificateNotYetValid,
            .serverCertificateHasUnknownRoot, .timedOut:
            return false
        default:
            return true
        }
    }

    /// Mirrors `httpretry.DefaultBackoff`, in seconds.
    static func backoff(waitMin: TimeInterval, waitMax: TimeInterval, attempt: Int, response: HTTPURLResponse?)
        -> TimeInterval
    {
        guard waitMin > 0, waitMax > 0 else { return 0 }
        guard waitMin <= waitMax else { return waitMax }
        if let retryAfter = retryAfterDelay(response), retryAfter > 0 {
            return min(retryAfter, waitMax)
        }
        var delay = waitMin
        for _ in 0..<attempt {
            if delay >= waitMax / 2 { return waitMax }
            delay *= 2
        }
        // Jitter only spreads out retry timing (httpretry uses math/rand/v2);
        // it protects nothing, so it needs no cryptographic randomness.
        // nosemgrep: insecure-random
        return delay > waitMin ? Double.random(in: waitMin..<delay) : waitMin
    }

    /// Mirrors `httpretry.retryAfterDelay`: `Retry-After` in seconds or as
    /// an HTTP date, on 429 and 503 only.
    static func retryAfterDelay(_ response: HTTPURLResponse?) -> TimeInterval? {
        guard let response, response.statusCode == 429 || response.statusCode == 503,
            let value = response.value(forHTTPHeaderField: "Retry-After"), !value.isEmpty
        else { return nil }
        if let seconds = Int(value) {
            return seconds > 0 ? TimeInterval(seconds) : nil
        }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        guard let date = formatter.date(from: value) else { return nil }
        let delay = date.timeIntervalSinceNow
        return delay > 0 ? delay : nil
    }
}

/// Mirrors sigstore-go `userAgent`: the library's user agent, prefixed with
/// `prefix` when set.
func userAgent(_ prefix: String) -> String {
    prefix.isEmpty ? libraryUserAgent : "\(prefix) \(libraryUserAgent)"
}

/// Mirrors `util.ConstructUserAgent` ("sigstore-go/<version>"). The
/// package has no version constant, so it is the bare name, as
/// `SigstoreTUF.DefaultFetcher` sends.
let libraryUserAgent = "sigstore-swift"

/// Runs `operation` with an overall deadline (Go `http.Client.Timeout`),
/// cancelling it when `seconds` elapse; `nil` means no deadline.
func withDeadline<T: Sendable>(
    _ seconds: TimeInterval?, _ operation: @escaping @Sendable () async throws -> T
) async throws -> T {
    guard let seconds else { return try await operation() }
    return try await withThrowingTaskGroup(of: T?.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            return nil
        }
        defer { group.cancelAll() }
        guard let first = try await group.next(), let value = first else {
            throw SigstoreError("request timed out after \(seconds) seconds")
        }
        return value
    }
}

/// Mirrors the `Timeout` option of sigstore-go's clients: zero means the
/// 30 s default, a negative value no timeout.
func effectiveTimeout(_ timeout: TimeInterval) -> TimeInterval? {
    if timeout < 0 { return nil }
    return timeout == 0 ? 30 : timeout
}
