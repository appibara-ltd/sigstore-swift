// A strict reader for the handful of DER constructs RSAPublicKey needs
// (ITU-T X.690 §8.1, §8.3 and §10.1): definite, minimally encoded lengths;
// minimally encoded INTEGERs.

struct DERReader {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    var isAtEnd: Bool { offset == bytes.count }

    private typealias Error = RSAPublicKeyComponents.Error

    /// Reads one element with the given single-octet tag and returns a reader
    /// over its contents.
    mutating func read(tag: UInt8) throws -> DERReader {
        guard offset < bytes.count else { throw Error.malformedDER("unexpected end of data") }
        guard bytes[offset] == tag else { throw Error.malformedDER("unexpected tag") }
        offset += 1
        guard offset < bytes.count else { throw Error.malformedDER("missing length") }
        let first = bytes[offset]
        offset += 1
        var length: Int
        if first < 0x80 {
            length = Int(first)
        } else {
            // X.690 §10.1: definite form only (0x80 is indefinite); we accept
            // up to 4 length octets.
            let count = Int(first & 0x7f)
            guard count >= 1, count <= 4 else { throw Error.malformedDER("unsupported length form") }
            guard bytes.count - offset >= count else { throw Error.malformedDER("truncated length") }
            guard bytes[offset] != 0 else { throw Error.malformedDER("non-minimal length") }
            length = 0
            for _ in 0..<count {
                length = length << 8 | Int(bytes[offset])
                offset += 1
            }
            // X.690 §10.1: the short form must be used for lengths < 128.
            guard length >= 0x80 else { throw Error.malformedDER("non-minimal length") }
        }
        guard bytes.count - offset >= length else { throw Error.malformedDER("truncated contents") }
        let contents = DERReader(Array(bytes[offset..<(offset + length)]))
        offset += length
        return contents
    }

    /// Reads a non-negative INTEGER and returns its big-endian magnitude
    /// (with any single leading 0x00 sign octet removed).
    mutating func readUnsignedInteger() throws -> [UInt8] {
        let content = try read(tag: 0x02).bytes
        guard !content.isEmpty else { throw Error.malformedDER("empty INTEGER") }
        // X.690 §8.3.2: the first nine bits must not be all 0 or all 1.
        if content.count > 1 {
            if content[0] == 0x00 && content[1] & 0x80 == 0 { throw Error.malformedDER("non-minimal INTEGER") }
            if content[0] == 0xff && content[1] & 0x80 != 0 { throw Error.malformedDER("non-minimal INTEGER") }
        }
        guard content[0] & 0x80 == 0 else { throw Error.malformedDER("negative INTEGER") }
        return content.first == 0 ? Array(content.dropFirst()) : content
    }
}
