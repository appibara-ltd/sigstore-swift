/// A generic error carrying a message and an optional wrapped cause.
///
/// sigstore-go mostly returns `fmt.Errorf("...: %w", err)` chains; this type
/// plays the same role. Where sigstore-go defines a named error type or
/// sentinel, the corresponding Swift module defines a named type instead.
public struct SigstoreError: Error, CustomStringConvertible, Sendable {
    public let message: String
    public let underlying: (any Error)?

    public init(_ message: String, underlying: (any Error)? = nil) {
        self.message = message
        self.underlying = underlying
    }

    public var description: String {
        if let underlying {
            return "\(message): \(underlying)"
        }
        return message
    }

    /// Walks the `underlying` chain (like Go's `errors.Is`/`errors.As`).
    public func contains<E: Error>(_ type: E.Type) -> Bool {
        var current: (any Error)? = self
        while let error = current {
            if error is E { return true }
            current = (error as? SigstoreError)?.underlying
        }
        return false
    }
}

extension Error {
    /// Wraps `self` with additional context, mirroring `fmt.Errorf("%s: %w")`.
    public func wrapped(_ message: String) -> SigstoreError {
        SigstoreError(message, underlying: self)
    }
}
