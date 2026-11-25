// Encodings of FIPS 204 §7.1–7.2 needed for verification.
//
// All bit packing is little-endian in bits and bytes (BitsToBytes,
// Algorithm 12; IntegerToBits, Algorithm 9).

/// Reads 256 `bits`-wide little-endian unsigned integers from
/// `bytes[offset ..< offset + 32·bits]` (the inverse of SimpleBitPack,
/// Algorithm 16/18). The caller guarantees the range is in bounds.
func unpackBits(_ bytes: [UInt8], offset: Int, bits: Int) -> [Int64] {
    precondition(bits > 0 && bits <= 32 && offset >= 0 && offset + 32 * bits <= bytes.count)
    var out = [Int64](repeating: 0, count: 256)
    var acc: UInt64 = 0
    var accBits = 0
    var pos = offset
    let mask: UInt64 = (1 << UInt64(bits)) - 1
    for i in 0..<256 {
        while accBits < bits {
            acc |= UInt64(bytes[pos]) << UInt64(accBits)
            pos += 1
            accBits += 8
        }
        out[i] = Int64(acc & mask)
        acc >>= UInt64(bits)
        accBits -= bits
    }
    return out
}

/// Appends SimpleBitPack(w, 2^bits − 1) (Algorithm 16) for w with coefficients
/// in [0, 2^bits).
func packBits(_ w: [Int64], bits: Int, into out: inout [UInt8]) {
    var acc: UInt64 = 0
    var accBits = 0
    for c in w {
        acc |= UInt64(c) << UInt64(accBits)
        accBits += bits
        while accBits >= 8 {
            out.append(UInt8(truncatingIfNeeded: acc))
            acc >>= 8
            accBits -= 8
        }
    }
}

/// FIPS 204 Algorithm 23, pkDecode(pk) → (ρ, t1). `pk` must have the
/// parameter set's public-key length.
func pkDecode(_ pk: [UInt8], _ p: MLDSAParameters) -> (rho: [UInt8], t1: [Poly]) {
    precondition(pk.count == p.publicKeyLength)
    let rho = Array(pk[0..<32])
    var t1: [Poly] = []
    t1.reserveCapacity(p.k)
    for i in 0..<p.k {
        // SimpleBitUnpack(z_i, 2^(bitlen(q−1)−d) − 1): 10 bits per coefficient.
        t1.append(unpackBits(pk, offset: 32 + 320 * i, bits: 10))
    }
    return (rho, t1)
}

/// A decoded signature (c̃, z, h) per FIPS 204 Algorithm 27.
struct DecodedSignature {
    var cTilde: [UInt8]
    /// z as signed integers in [−γ1 + 1, γ1] (BitUnpack, Algorithm 19).
    var z: [[Int64]]
    var h: [[Bool]]
}

/// FIPS 204 Algorithm 27, sigDecode(σ). Returns nil for a wrong length or
/// when HintBitUnpack returns ⊥.
func sigDecode(_ sig: [UInt8], _ p: MLDSAParameters) -> DecodedSignature? {
    guard sig.count == p.signatureLength else { return nil }
    let cTilde = Array(sig[0..<p.cTildeLength])
    var z: [[Int64]] = []
    z.reserveCapacity(p.l)
    let zBytes = 32 * p.zBits
    for i in 0..<p.l {
        // BitUnpack(x_i, γ1 − 1, γ1) (Algorithm 19): coefficient = γ1 − value.
        let packed = unpackBits(sig, offset: p.cTildeLength + zBytes * i, bits: p.zBits)
        z.append(packed.map { p.gamma1 - $0 })
    }
    let hintOffset = p.cTildeLength + zBytes * p.l
    guard let h = hintBitUnpack(Array(sig[hintOffset...]), p) else { return nil }
    return DecodedSignature(cTilde: cTilde, z: z, h: h)
}

/// FIPS 204 Algorithm 21, HintBitUnpack(y). `y` has ω + k bytes: the hint
/// positions, then the k cumulative counts. Returns nil (⊥) when the encoding
/// is malformed: a count that decreases or exceeds ω, positions within one
/// polynomial that are not strictly increasing, or non-zero padding. This
/// strictness makes the encoding of h unique (strong unforgeability).
func hintBitUnpack(_ y: [UInt8], _ p: MLDSAParameters) -> [[Bool]]? {
    guard y.count == p.omega + p.k else { return nil }
    var h = [[Bool]](repeating: [Bool](repeating: false, count: 256), count: p.k)
    var index = 0
    for i in 0..<p.k {
        let count = Int(y[p.omega + i])
        // Step 4: y[ω + i] < Index or y[ω + i] > ω → ⊥.
        if count < index || count > p.omega { return nil }
        let first = index
        // Here index < count ≤ ω, so y[index] is in bounds; y[index] < 256.
        while index < count {
            // Step 8: positions must be strictly increasing within a polynomial.
            if index > first, y[index - 1] >= y[index] { return nil }
            h[i][Int(y[index])] = true
            index += 1
        }
    }
    // Steps 13–15: unused position bytes must be zero.
    for i in index..<p.omega where y[i] != 0 {
        return nil
    }
    return h
}

/// FIPS 204 Algorithm 28, w1Encode(w1).
func w1Encode(_ w1: [[Int64]], _ p: MLDSAParameters) -> [UInt8] {
    var out: [UInt8] = []
    out.reserveCapacity(w1.count * 32 * p.w1Bits)
    for poly in w1 {
        packBits(poly, bits: p.w1Bits, into: &out)
    }
    return out
}
