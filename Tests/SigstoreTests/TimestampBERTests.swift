import Foundation
import Sigstore
@testable import SigstoreRoot
import Testing

// BER TimeStampTokens: port of digitorus/pkcs7 05f79448fa77 ber_test.go,
// plus end-to-end checks that a token re-encoded as BER verifies exactly as
// its DER original, and that the response around it must stay DER (Go
// parses it with encoding/asn1).

// MARK: - DER ⇄ BER helpers

/// A DER TLV split into its parts (single-byte tags, definite lengths).
private func splitDER(_ bytes: ArraySlice<UInt8>) -> (tag: UInt8, content: ArraySlice<UInt8>, rest: ArraySlice<UInt8>) {
    var i = bytes.startIndex
    let tag = bytes[i]
    i += 1
    var length = Int(bytes[i])
    i += 1
    if length >= 0x80 {
        let n = length & 0x7F
        length = 0
        for _ in 0..<n {
            length = length << 8 | Int(bytes[i])
            i += 1
        }
    }
    return (tag, bytes[i..<(i + length)], bytes[(i + length)...])
}

private func derLength(_ n: Int) -> [UInt8] {
    if n < 0x80 { return [UInt8(n)] }
    var bytes: [UInt8] = []
    var v = n
    while v > 0 {
        bytes.insert(UInt8(v & 0xFF), at: 0)
        v >>= 8
    }
    return [0x80 | UInt8(bytes.count)] + bytes
}

private func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] { [tag] + derLength(content.count) + content }

/// How to re-encode DER as BER.
private enum BERStyle {
    /// Every constructed value with an indefinite length (`80 … 00 00`).
    case indefinite
    /// Every length below 128 in the long form (`81 nn`), which BER allows.
    case longFormLengths
}

/// Re-encodes every TLV of a DER sequence of values as BER.
private func toBER(_ der: ArraySlice<UInt8>, _ style: BERStyle) -> [UInt8] {
    var out: [UInt8] = []
    var rest = der
    while !rest.isEmpty {
        let (tag, content, next) = splitDER(rest)
        let constructed = tag & 0x20 != 0
        let body = constructed ? toBER(content, style) : Array(content)
        switch style {
        // pkcs7's ber2der cannot read an empty indefinite-length value (it
        // reads `00 00` as a child first), so those stay definite.
        case .indefinite where constructed && !body.isEmpty:
            out += [tag, 0x80] + body + [0x00, 0x00]
        // `81 00` would be a leading-zero length, which pkcs7 rejects.
        case .longFormLengths where !body.isEmpty && body.count < 0x80:
            out += [tag, 0x81, UInt8(body.count)] + body
        default:
            out += [tag] + derLength(body.count) + body
        }
        rest = next
    }
    return out
}

/// The status and token TLVs of a DER TimeStampResp.
private func splitResponse(_ response: [UInt8]) -> (status: [UInt8], token: [UInt8]) {
    let outer = splitDER(response[...]).content
    let status = splitDER(outer)
    let statusTLV = Array(outer[outer.startIndex..<status.rest.startIndex])
    return (statusTLV, Array(status.rest))
}

/// The response with its token's contents re-encoded as BER. The token's
/// own header stays definite: Go reads it with encoding/asn1.
private func responseWithBERToken(_ response: [UInt8], _ style: BERStyle) -> [UInt8] {
    let (status, token) = splitResponse(response)
    let parts = splitDER(token[...])
    let berToken = tlv(parts.tag, toBER(parts.content, style))
    return tlv(0x30, status + berToken)
}

// MARK: - Fixtures

/// sigstore-conformance `intoto-with-custom-trust-root`: a real TSA token.
private enum ConformanceTSA {
    static let time = Date(timeIntervalSince1970: 1_675_209_600)

    static func json() throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Fixtures.file("conformance/intoto-with-custom-trust-root/bundle.sigstore.json"))
            as! [String: Any]
    }

    static func trustedRoot() throws -> TrustedRoot {
        try TrustedRoot(json: Fixtures.file("conformance/intoto-with-custom-trust-root/trusted_root.json"))
    }

    static func response() throws -> [UInt8] {
        let vm = try json()["verificationMaterial"] as! [String: Any]
        let tvd = vm["timestampVerificationData"] as! [String: Any]
        let first = (tvd["rfc3161Timestamps"] as! [[String: Any]])[0]
        return Array(try #require(Data(base64Encoded: first["signedTimestamp"] as! String)))
    }

    static func bundle(response: [UInt8]) throws -> SigstoreBundle.Bundle {
        var json = try json()
        var vm = json["verificationMaterial"] as! [String: Any]
        var tvd = vm["timestampVerificationData"] as! [String: Any]
        tvd["rfc3161Timestamps"] = [["signedTimestamp": Data(response).base64EncodedString()]]
        vm["timestampVerificationData"] = tvd
        json["verificationMaterial"] = vm
        return try SigstoreBundle.Bundle(json: JSONSerialization.data(withJSONObject: json))
    }
}

private func expectError(
    _ fragment: String, sourceLocation: SourceLocation = #_sourceLocation, _ body: () async throws -> Void
) async {
    do {
        try await body()
        Issue.record("expected an error containing \"\(fragment)\"", sourceLocation: sourceLocation)
    } catch {
        #expect("\(error)".contains(fragment), "unexpected error: \(error)", sourceLocation: sourceLocation)
    }
}

@Suite("RFC 3161 BER tokens")
struct TimestampBERTests {
    private let artifact = Array("signature bytes".utf8)

    // MARK: ber2der (pkcs7 ber_test.go)

    @Test func ber2derIndefiniteLength() throws {
        let der = try ber2der([0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00])
        #expect(der == [0x30, 0x03, 0x02, 0x01, 0x01])
        #expect(try ber2der(der) == der)  // idempotent on DER
    }

    @Test func ber2derNestedMultipleIndefinite() throws {
        let ber: [UInt8] = [0x30, 0x80, 0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00, 0x30, 0x80, 0x02, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00]
        let der = try ber2der(ber)
        #expect(der == [0x30, 0x0A, 0x30, 0x03, 0x02, 0x01, 0x01, 0x30, 0x03, 0x02, 0x01, 0x02])
        #expect(try ber2der(der) == der)
    }

    @Test func ber2derKeepsHighTagNumbers() throws {
        for input: [UInt8] in [[0x1F, 0x1F, 0x02, 0x01, 0x07], [0x1F, 0x81, 0x00, 0x01, 0x41]] {
            #expect(try ber2der(input) == input)
        }
    }

    @Test func ber2derMinimizesLongFormLengths() throws {
        #expect(try ber2der([0x04, 0x81, 0x02, 0xAA, 0xBB]) == [0x04, 0x02, 0xAA, 0xBB])
        // A leading zero is accepted when the next length byte is ≥ 0x80
        // (pkcs7's check), and the length is re-encoded minimally.
        let long = [UInt8](repeating: 7, count: 128)
        #expect(try ber2der([0x04, 0x82, 0x00, 0x80] + long) == [0x04, 0x81, 0x80] + long)
    }

    /// TestBer2Der_Negatives and TestParseMalformedBERNoPanic.
    @Test(arguments: [
        ([], "input ber is empty"),
        ([0x30], "cannot move offset forward, end of ber data reached"),
        ([0x30, 0x08], "BER tag length is more than available dat"),
        ([0x30, 0x81], "cannot move offset forward, end of ber data reached"),
        ([0x30, 0x81, 0x00], "BER tag length has leading zero"),
        ([0x30, 0x85, 0x00], "tag length too long"),
        ([0x30, 0x84, 0x80, 0x0, 0x0, 0x0], "length is negative"),
        ([0x30, 0x82, 0x0, 0x1], "length has leading zero"),
        ([0x30, 0x80, 0x1, 0x2, 0x1, 0x2], "Invalid BER format"),
        ([0x30, 0x80, 0x1, 0x2], "BER tag length is more than available data"),
        ([0x30, 0x03, 0x01, 0x02], "length is more than available data"),
        ([0x1F, 0x80], "end of ber data reached"),
        ([0x1F, 0x05], "end of ber data reached"),
        ([0x30, 0x84, 0x01], "end of ber data reached"),
        // Indefinite lengths need constructed encoding.
        ([0x04, 0x80, 0x00, 0x00], "Indefinite form tag must have constructed encoding"),
        // Unterminated indefinite length.
        ([0x30, 0x80, 0x02, 0x01, 0x01], "Invalid BER format"),
        // pkcs7 reads the first child before looking for end-of-contents, so
        // an empty indefinite-length value is rejected (as in Go).
        ([0x30, 0x80, 0x00, 0x00], "Invalid BER format"),
        // A leading-zero length followed by a byte below 0x80.
        ([0x04, 0x83, 0x00, 0x01, 0x2C], "length has leading zero"),
    ] as [([UInt8], String)])
    func ber2derRejects(_ input: [UInt8], _ fragment: String) async {
        await expectError(fragment) { _ = try ber2der(input) }
    }

    @Test func ber2derLimitsNesting() throws {
        let nested = { (depth: Int) -> [UInt8] in
            Array(repeating: [UInt8]([0x30, 0x80]), count: depth).flatMap { $0 } + [0x05, 0x00]
                + Array(repeating: [UInt8]([0x00, 0x00]), count: depth).flatMap { $0 }
        }
        _ = try ber2der(nested(ber2derMaximumDepth - 1))
        #expect(throws: (any Error).self) { try ber2der(nested(ber2derMaximumDepth)) }
        #expect(throws: (any Error).self) { try ber2der(nested(10_000)) }
    }

    /// TestVerifyIndefiniteLengthBer's real-world shape: the conformance token
    /// re-encoded with indefinite lengths transcodes back to the original DER.
    @Test func ber2derRestoresTheOriginalToken() throws {
        let token = splitResponse(try ConformanceTSA.response()).token
        let parts = splitDER(token[...])
        for style in [BERStyle.indefinite, .longFormLengths] {
            let ber = tlv(parts.tag, toBER(parts.content, style))
            #expect(ber != token)
            #expect(try ber2der(ber) == token)
        }
    }

    // MARK: End to end

    @Test func conformanceBERTokenVerifiesLikeDER() async throws {
        let original = try ConformanceTSA.response()
        for style in [BERStyle.indefinite, .longFormLengths] {
            let response = responseWithBERToken(original, style)
            #expect(response != original)
            let verified = try await verifySignedTimestampWithThreshold(
                ConformanceTSA.bundle(response: response), trustedMaterial: ConformanceTSA.trustedRoot(), threshold: 1)
            #expect(verified.first?.time == ConformanceTSA.time, "\(style)")
        }
    }

    @Test func syntheticBERTokenVerifies() async throws {
        let tsa = try TestTSA()
        for style in [BERStyle.indefinite, .longFormLengths] {
            let response = responseWithBERToken(Array(try tsa.response(for: artifact)), style)
            let result = try await tsa.authority().verify(signedTimestamp: Data(response), signature: Data(artifact))
            #expect(result.time == TestTSA.defaultTime, "\(style)")
        }
    }

    /// The BER path still checks the signature: flipping one byte of the
    /// TSTInfo (genTime's last digit) inside a BER token fails.
    @Test func tamperedBERTokenFails() async throws {
        let tsa = try TestTSA()
        var response = responseWithBERToken(Array(try tsa.response(for: artifact)), .indefinite)
        let genTime = try #require(response.firstRange(of: Array("Z".utf8)))  // GeneralizedTime ends in Z
        response[genTime.lowerBound - 1] ^= 0x01
        await expectError("pkcs7: Message digest mismatch") {
            _ = try await tsa.authority().verify(signedTimestamp: Data(response), signature: Data(self.artifact))
        }
        // And over the other signature.
        let good = responseWithBERToken(Array(try tsa.response(for: artifact)), .indefinite)
        await expectError("hashed messages don't match") {
            _ = try await tsa.authority().verify(signedTimestamp: Data(good), signature: Data("other".utf8))
        }
    }

    // MARK: The response itself stays DER (Go encoding/asn1)

    @Test func responseMustBeDER() async throws {
        let tsa = try TestTSA()
        let der = Array(try tsa.response(for: artifact))
        let (status, token) = splitResponse(der)
        let outerContent = status + token
        let cases: [(String, [UInt8], String)] = [
            ("indefinite response", [0x30, 0x80] + outerContent + [0x00, 0x00], "indefinite length found (not DER)"),
            // A long-form length with a leading zero (Go: superfluous leading zeros).
            ("non-minimal response length", [0x30, 0x83, 0x00] + derLength(outerContent.count).dropFirst() + outerContent,
             "superfluous leading zeros in length"),
            ("indefinite token header", tlv(0x30, status + [token[0], 0x80] + splitDER(token[...]).content + [0x00, 0x00]),
             "indefinite length found (not DER)"),
            ("indefinite status", tlv(0x30, toBER(status[...], .indefinite) + token), "indefinite length found (not DER)"),
            ("trailing data", der + [0x00], "trailing data in Time-Stamp response"),
            ("not a SEQUENCE", [0x31] + der.dropFirst(), "not a SEQUENCE"),
            ("no token", tlv(0x30, status), "no pkcs7 data in Time-Stamp response"),
            ("empty token", tlv(0x30, status + [0x30, 0x00]), "no pkcs7 data in Time-Stamp response"),
            ("element after token", tlv(0x30, outerContent + [0x05, 0x00]), "unexpected data after the TimeStampToken"),
            ("truncated", Array(der.dropLast()), "data truncated"),
            // A malformed BER token is rejected by ber2der.
            ("unterminated BER token",
             tlv(0x30, status + tlv(token[0], Array(toBER(splitDER(token[...]).content, .indefinite).dropLast(2)))),
             "ber2der"),
        ]
        for (name, response, fragment) in cases {
            #expect(response != der, "\(name)")
            await expectError(fragment) {
                _ = try await tsa.authority().verify(signedTimestamp: Data(response), signature: Data(self.artifact))
            }
        }
    }

    @Test func derHeaderFollowsGoParseTagAndLength() throws {
        let ok = try DERHeader.read([0x04, 0x02, 0xAA, 0xBB, 0x05][...])
        #expect(Array(ok.header.content) == [0xAA, 0xBB])
        #expect(Array(ok.rest) == [0x05])
        #expect(Array(try DERHeader.read([0x1F, 0x1F, 0x00][...]).header.identifier) == [0x1F, 0x1F])
        let bad: [([UInt8], String)] = [
            ([0x04], "data truncated"),
            ([0x04, 0x80, 0x00, 0x00], "indefinite length"),
            ([0x04, 0x81, 0x05] + [UInt8](repeating: 0, count: 5), "non-minimal length"),
            ([0x04, 0x82, 0x00, 0x80] + [UInt8](repeating: 0, count: 128), "superfluous leading zeros"),
            ([0x1F, 0x05, 0x00], "non-minimal tag"),
            ([0x1F, 0x80, 0x1F, 0x00], "not minimally encoded"),
            ([0x1F, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00, 0x00], "too large"),
            ([0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00], "length too large"),
            ([0x04, 0x05, 0x00], "data truncated"),
        ]
        for (input, fragment) in bad {
            #expect(throws: (any Error).self, "\(input)") { _ = try DERHeader.read(input[...]) }
            do { _ = try DERHeader.read(input[...]) } catch {
                #expect("\(error)".contains(fragment), "\(input): \(error)")
            }
        }
    }
}
