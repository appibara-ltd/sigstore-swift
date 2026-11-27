// BER → DER transcoding and a shallow DER TLV header reader for RFC 3161.
//
// `ber2der` is a port of github.com/digitorus/pkcs7 05f79448fa77 ber.go (the
// pkcs7 version sigstore-go v1.4.1 pins), which `pkcs7.Parse` runs on every
// TimeStampToken before decoding it. `DERHeader` follows Go's
// encoding/asn1 `parseTagAndLength`, which digitorus/timestamp uses for the
// outer TimeStampResp (DER only; the token is kept as a raw TLV).

import SigstoreCommon

/// Nesting limit (our addition; Go recurses without one). The transcoded
/// DER is parsed by SwiftASN1, which rejects nesting deeper than 50 anyway.
let ber2derMaximumDepth = 50

/// Mirrors pkcs7 `ber2der`: re-encodes the first BER object in `ber` with
/// definite, minimal lengths. Indefinite lengths must be constructed and
/// end with `00 00`; tags and primitive contents are copied unchanged
/// (constructed strings stay constructed). Bytes after the first object
/// are ignored, as in Go.
func ber2der(_ ber: [UInt8]) throws -> [UInt8] {
    guard !ber.isEmpty else { throw SigstoreError("ber2der: input ber is empty") }
    return try readBERObject(ber, 0, depth: 1).der
}

private func endOfData() -> SigstoreError {
    SigstoreError("ber2der: cannot move offset forward, end of ber data reached")
}

/// Mirrors pkcs7 `readObject`: returns the object's DER encoding and the
/// offset after it. For a definite-length constructed object that offset is
/// the declared end, even when its children ran past it (as in Go).
private func readBERObject(_ ber: [UInt8], _ start: Int, depth: Int) throws -> (der: [UInt8], next: Int) {
    guard depth <= ber2derMaximumDepth else { throw SigstoreError("ber2der: BER nesting too deep") }
    let berLen = ber.count
    var offset = start
    guard offset < berLen else { throw SigstoreError("ber2der: offset is after end of ber data") }
    let tagStart = offset
    let b = ber[offset]
    offset += 1
    guard offset < berLen else { throw endOfData() }
    if b & 0x1F == 0x1F {
        // High tag number form: base-128 continuation bytes, then the last.
        while ber[offset] >= 0x80 {
            offset += 1
            guard offset < berLen else { throw endOfData() }
        }
        offset += 1
        guard offset < berLen else { throw endOfData() }
    }
    let tagEnd = offset
    let constructed = b & 0x20 != 0

    var length = 0
    let l = ber[offset]
    offset += 1
    if l >= 0x80 && offset >= berLen {
        throw endOfData()
    }
    var indefinite = false
    if l > 0x80 {
        let numberOfBytes = Int(l & 0x7F)
        guard numberOfBytes <= 4 else { throw SigstoreError("ber2der: BER tag length too long") }
        if numberOfBytes == 4 && ber[offset] > 0x7F {
            throw SigstoreError("ber2der: BER tag length is negative")
        }
        guard offset + numberOfBytes <= berLen else { throw endOfData() }
        if ber[offset] == 0 && (numberOfBytes == 1 || ber[offset + 1] <= 0x7F) {
            throw SigstoreError("ber2der: BER tag length has leading zero")
        }
        for _ in 0..<numberOfBytes {
            length = length * 256 + Int(ber[offset])
            offset += 1
        }
    } else if l == 0x80 {
        indefinite = true
    } else {
        length = Int(l)
    }
    var contentEnd = offset + length
    guard contentEnd <= berLen else {
        throw SigstoreError("ber2der: BER tag length is more than available data")
    }
    if indefinite && !constructed {
        throw SigstoreError("ber2der: Indefinite form tag must have constructed encoding")
    }

    let content: ArraySlice<UInt8>
    if !constructed {
        content = ber[offset..<contentEnd]
    } else {
        var inner: [UInt8] = []
        while offset < contentEnd || indefinite {
            let child = try readBERObject(ber, offset, depth: depth + 1)
            inner += child.der
            offset = child.next
            if indefinite {
                // End-of-contents must start exactly at the current offset.
                guard berLen - offset >= 2 else { throw SigstoreError("ber2der: Invalid BER format") }
                if ber[offset] == 0 && ber[offset + 1] == 0 { break }
            }
        }
        content = inner[...]
    }
    if indefinite {
        contentEnd = offset + 2
    }

    var der = Array(ber[tagStart..<tagEnd])
    appendDERLength(&der, content.count)
    der += content
    return (der, contentEnd)
}

/// Mirrors pkcs7 `encodeLength`: short form below 128, else minimal long form.
private func appendDERLength(_ out: inout [UInt8], _ length: Int) {
    guard length >= 128 else {
        out.append(UInt8(length))
        return
    }
    var n = 1
    var i = length
    while i > 255 {
        n += 1
        i >>= 8
    }
    out.append(0x80 | UInt8(n))
    for k in stride(from: n - 1, through: 0, by: -1) {
        out.append(UInt8(truncatingIfNeeded: length >> (k * 8)))
    }
}

/// One DER TLV read without descending into its contents, with Go
/// encoding/asn1's `parseTagAndLength` rules: definite lengths only, no
/// leading zeros, long form only for lengths ≥ 128, minimal high tag numbers.
struct DERHeader {
    /// The identifier octets.
    var identifier: ArraySlice<UInt8>
    /// The contents octets.
    var content: ArraySlice<UInt8>
    /// The whole TLV.
    var full: ArraySlice<UInt8>

    /// Reads the TLV at the start of `bytes`; the rest is returned in `rest`.
    static func read(_ bytes: ArraySlice<UInt8>) throws -> (header: DERHeader, rest: ArraySlice<UInt8>) {
        var i = bytes.startIndex
        let end = bytes.endIndex
        func truncated() -> SigstoreError { SigstoreError("asn1: syntax error: data truncated") }
        guard end - i >= 2 else { throw truncated() }
        let first = bytes[i]
        i += 1
        if first & 0x1F == 0x1F {
            // Go `parseBase128Int`: at most 5 bytes, no leading 0x80, fits
            // an int32; then the tag must need the long form (≥ 31).
            var tag: Int64 = 0
            var shifted = 0
            while true {
                guard i < end else { throw SigstoreError("asn1: syntax error: truncated base 128 integer") }
                guard shifted < 5 else { throw SigstoreError("asn1: structure error: base 128 integer too large") }
                let byte = bytes[i]
                if shifted == 0 && byte == 0x80 {
                    throw SigstoreError("asn1: structure error: integer is not minimally encoded")
                }
                tag = tag << 7 | Int64(byte & 0x7F)
                i += 1
                shifted += 1
                if byte & 0x80 == 0 { break }
            }
            guard tag <= Int64(Int32.max) else { throw SigstoreError("asn1: structure error: base 128 integer too large") }
            guard tag >= 0x1F else { throw SigstoreError("asn1: syntax error: non-minimal tag") }
        }
        let identifierEnd = i
        guard i < end else { throw truncated() }
        let lengthByte = bytes[i]
        i += 1
        var length = 0
        if lengthByte & 0x80 == 0 {
            length = Int(lengthByte)
        } else {
            let numBytes = Int(lengthByte & 0x7F)
            guard numBytes != 0 else { throw SigstoreError("asn1: syntax error: indefinite length found (not DER)") }
            for _ in 0..<numBytes {
                guard i < end else { throw truncated() }
                guard length < 1 << 23 else { throw SigstoreError("asn1: structure error: length too large") }
                length = length << 8 | Int(bytes[i])
                i += 1
                if length == 0 {
                    throw SigstoreError("asn1: structure error: superfluous leading zeros in length")
                }
            }
            guard length >= 0x80 else { throw SigstoreError("asn1: structure error: non-minimal length") }
        }
        guard end - i >= length else { throw truncated() }
        let contentEnd = i + length
        let header = DERHeader(
            identifier: bytes[bytes.startIndex..<identifierEnd],
            content: bytes[i..<contentEnd],
            full: bytes[bytes.startIndex..<contentEnd])
        return (header, bytes[contentEnd...])
    }
}
