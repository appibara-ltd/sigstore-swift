import Foundation

/// Hex helpers and JSON vector loading for the generated vectors in
/// `Vectors/` (see scripts/cryptoextras-vectors).
enum Vectors {
    static func load<T: Decodable>(_ name: String, as type: T.Type) throws -> T {
        try JSONDecoder().decode(T.self, from: EmbeddedTestData.data("Vectors/\(name).json"))
    }
}

extension Array where Element == UInt8 {
    init(hex: String) {
        precondition(hex.count % 2 == 0, "odd-length hex")
        var out: [UInt8] = []
        out.reserveCapacity(hex.count / 2)
        var it = hex.makeIterator()
        while let a = it.next(), let b = it.next() {
            out.append(UInt8(String([a, b]), radix: 16)!)
        }
        self = out
    }

    var hex: String { map { String(format: "%02x", $0) }.joined() }
}

/// Deterministic xorshift generator for fuzz-style tests.
struct XorShift: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        return state
    }

    mutating func bytes(_ n: Int) -> [UInt8] { (0..<n).map { _ in UInt8.random(in: 0...255, using: &self) } }
}
