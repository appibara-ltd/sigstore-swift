import Crypto
import Foundation

/// Ed25519ph signature verification (RFC 8032 §5.1, PH = SHA-512).
///
/// Mirrors Go's `crypto/ed25519.VerifyWithOptions` with
/// `Options{Hash: crypto.SHA512, Context: ctx}`, which sigstore-go uses for
/// Ed25519 keys in certificates. swift-crypto has no Ed25519ph.
///
/// Acceptance rules (see `isValidSignature(_:prehash:publicKey:context:)`):
/// - cofactorless equation, checked as Go does: encode([S]B - [k]A) == R;
/// - S must be < L;
/// - the public key A is decoded strictly per RFC 8032 §5.1.3. This is the
///   one deliberate difference from Go, whose decoder also accepts y >= p and
///   x = 0 with the sign bit set (non-canonical encodings of valid points).
///   Rejecting them can only turn a Go "valid" into "invalid"; no honest key
///   generator produces such encodings.
public enum Ed25519ph {
    /// The length of an Ed25519ph signature, in bytes.
    public static let signatureLength = 64
    /// The length of an encoded Ed25519 public key, in bytes.
    public static let publicKeyLength = 32
    /// The length of the SHA-512 prehash, in bytes.
    public static let prehashLength = 64
    /// The maximum context length, in bytes (RFC 8032 §5.1).
    public static let maxContextLength = 255

    /// RFC 8032 Ed25519ph verification of `signature` (64 bytes) over the
    /// SHA-512 digest `prehash` (64 bytes) of the message, with `context`
    /// (at most 255 bytes). Returns false, never traps, on any malformed input.
    public static func isValidSignature(
        _ signature: some DataProtocol,
        prehash: some DataProtocol,
        publicKey: some DataProtocol,
        context: some DataProtocol
    ) -> Bool {
        verify(signature: Array(signature), prehash: Array(prehash), publicKey: Array(publicKey), context: Array(context))
    }

    /// Ed25519ph verification over a SHA-512 `prehash` with an empty context.
    public static func isValidSignature(
        _ signature: some DataProtocol,
        prehash: some DataProtocol,
        publicKey: some DataProtocol
    ) -> Bool {
        verify(signature: Array(signature), prehash: Array(prehash), publicKey: Array(publicKey), context: [])
    }

    /// Ed25519ph verification of `message`, hashed here with SHA-512 (PH).
    public static func isValidSignature(
        _ signature: some DataProtocol,
        message: some DataProtocol,
        publicKey: some DataProtocol,
        context: some DataProtocol
    ) -> Bool {
        let prehash = Array(SHA512.hash(data: Array(message)))
        return verify(signature: Array(signature), prehash: prehash, publicKey: Array(publicKey), context: Array(context))
    }

    /// Ed25519ph verification of `message` with an empty context.
    public static func isValidSignature(
        _ signature: some DataProtocol,
        message: some DataProtocol,
        publicKey: some DataProtocol
    ) -> Bool {
        isValidSignature(signature, message: message, publicKey: publicKey, context: [UInt8]())
    }

    /// L = 2^252 + 27742317777372353535851937790883648493, little endian
    /// (RFC 8032 §5.1).
    static let orderLE: [UInt8] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ]
    // A 32-byte constant always fits in 4 limbs.
    // swiftlint:disable:next force_unwrapping
    private static let orderLimbs: BigUInt.Limbs = BigUInt.limbs(bigEndian: orderLE.reversed(), count: 4)!

    /// "SigEd25519 no Ed25519 collisions" (RFC 8032 §2, dom2).
    private static let domPrefix = Array("SigEd25519 no Ed25519 collisions".utf8)

    static func verify(signature: [UInt8], prehash: [UInt8], publicKey: [UInt8], context: [UInt8]) -> Bool {
        // Input lengths (RFC 8032 §5.1: 64-byte signatures, 32-byte keys;
        // PH = SHA-512 gives 64 bytes; §2: context at most 255 octets).
        guard signature.count == signatureLength,
              publicKey.count == publicKeyLength,
              prehash.count == prehashLength,
              context.count <= maxContextLength
        else { return false }

        // §5.1.7 step 1: decode A (strictly, §5.1.3).
        guard let a = EdwardsPoint(encoded: publicKey) else { return false }

        // §5.1.7 step 1: S is the integer encoded by the second half; fail
        // if S >= L. (Go: sig[63]&224 check, then Scalar.SetCanonicalBytes.)
        let rBytes = Array(signature[0..<32])
        let sBytes = Array(signature[32..<64])
        guard isBelowOrder(sBytes) else { return false }

        // §5.1.7 step 1 also decodes R. Like Go, we instead compare R's bytes
        // with the canonical encoding of the computed point (step 3); any R
        // that fails to decode, or is non-canonical, can never be equal, so
        // the outcome is the same.

        // §5.1.7 step 2: k = SHA-512(dom2(1, ctx) || R || A || PH(M)) mod L,
        // with dom2(1, ctx) = prefix || octet(1) || octet(len(ctx)) || ctx.
        var h = SHA512()
        h.update(data: domPrefix)
        h.update(data: [1, UInt8(context.count)])
        h.update(data: context)
        h.update(data: rBytes)
        h.update(data: publicKey)
        h.update(data: prehash)
        let k = reduceModOrder(Array(h.finalize()))

        // §5.1.7 step 3, cofactorless as in Go's crypto/ed25519:
        // [S]B = R + [k]A  <=>  [S]B + [k](-A) = R, compared as encodings.
        // RFC 8032 permits this ("sufficient, but not required") instead of
        // the cofactored [8][S]B = [8]R + [8][k]A.
        let rCheck = EdwardsPoint.doubleScalarMultiply(sBytes, .base, k, a.negated)
        return rCheck.encoded == rBytes
    }

    /// S < L for a 32-byte little-endian S.
    static func isBelowOrder(_ sLE: [UInt8]) -> Bool {
        for i in stride(from: 31, through: 0, by: -1) where sLE[i] != orderLE[i] {
            return sLE[i] < orderLE[i]
        }
        return false // S == L
    }

    /// A 64-byte little-endian integer mod L, as 32 little-endian bytes.
    static func reduceModOrder(_ digestLE: [UInt8]) -> [UInt8] {
        // The input is a 64-byte SHA-512 digest: always 8 limbs.
        // swiftlint:disable:next force_unwrapping
        let limbs = BigUInt.limbs(bigEndian: digestLE.reversed(), count: 8)!
        let r = BigUInt.remainder(limbs, orderLimbs)
        // The remainder is below L < 2^253: always fits in 32 bytes.
        // swiftlint:disable:next force_unwrapping
        return BigUInt.bigEndian(r, count: 32)!.reversed()
    }
}
