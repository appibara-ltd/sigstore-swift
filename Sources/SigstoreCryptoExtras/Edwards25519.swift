// The twisted Edwards curve edwards25519, -x^2 + y^2 = 1 + d x^2 y^2,
// in extended homogeneous coordinates (RFC 8032 §5.1.4).

struct EdwardsPoint: Sendable {
    var x: FieldElement
    var y: FieldElement
    var z: FieldElement
    var t: FieldElement

    /// The neutral element (0, 1).
    static let identity = EdwardsPoint(x: .zero, y: .one, z: .one, t: .zero)

    /// The base point B (RFC 8032 §5.1: y = 4/5, x positive), from its
    /// standard encoding.
    static let base: EdwardsPoint = {
        var enc = [UInt8](repeating: 0x66, count: 32)
        enc[0] = 0x58
        guard let b = EdwardsPoint(encoded: enc) else { preconditionFailure("base point constant") }
        return b
    }()

    init(x: FieldElement, y: FieldElement, z: FieldElement, t: FieldElement) {
        self.x = x
        self.y = y
        self.z = z
        self.t = t
    }

    /// Decodes a point as specified in RFC 8032 §5.1.3. Returns nil for any
    /// input that is not 32 bytes, is a non-canonical encoding (y >= p, or
    /// x = 0 with the sign bit set), or does not lie on the curve.
    ///
    /// Go's edwards25519.Point.SetBytes (used by crypto/ed25519 for public
    /// keys) accepts both kinds of non-canonical encodings; this decoder
    /// follows the RFC and rejects them.
    init?(encoded: [UInt8]) {
        guard encoded.count == 32 else { return nil }
        // Step 1: bit 255 is x_0, the rest is y; fail if y >= p.
        let x0 = encoded[31] >> 7
        var yBytes = encoded
        yBytes[31] &= 0x7f
        guard let y = FieldElement(canonicalBytes: yBytes) else { return nil }

        // Step 2: x^2 = (y^2 - 1) / (d y^2 + 1) = u / v; candidate root
        // x = u v^3 (u v^7)^((p-5)/8).
        let y2 = y.squared
        let u = y2 - .one
        let v = FieldElement.d * y2 + .one
        let v3 = v.squared * v
        let v7 = v3.squared * v
        var x = u * v3 * (u * v7).power(FieldElement.pMinus5Over8)

        // Step 3: if v x^2 = u, x is a root; if v x^2 = -u, x * sqrt(-1) is;
        // otherwise there is no square root and decoding fails.
        let vx2 = v * x.squared
        if vx2.equals(u) {
            // x is a root.
        } else if vx2.equals(-u) {
            x = x * FieldElement.sqrtMinusOne
        } else {
            return nil
        }

        // Step 4: x = 0 with x_0 = 1 fails; otherwise pick the root whose
        // low bit equals x_0.
        if x.isZero && x0 == 1 { return nil }
        if (x.isOdd ? 1 : 0) != x0 { x = -x }

        self.init(x: x, y: y, z: .one, t: x * y)
    }

    /// Encoding as specified in RFC 8032 §5.1.2: y little endian with the low
    /// bit of x in bit 255. Always canonical.
    var encoded: [UInt8] {
        let zInv = z.inverted
        let ax = x * zInv
        var out = (y * zInv).bytes
        if ax.isOdd { out[31] |= 0x80 }
        return out
    }

    var negated: EdwardsPoint { EdwardsPoint(x: -x, y: y, z: z, t: -t) }

    static let twoD = FieldElement.d + FieldElement.d

    /// Point addition (RFC 8032 §5.1.4); complete for all inputs.
    static func + (p: EdwardsPoint, q: EdwardsPoint) -> EdwardsPoint {
        let a = (p.y - p.x) * (q.y - q.x)
        let b = (p.y + p.x) * (q.y + q.x)
        let c = p.t * twoD * q.t
        let d = (p.z + p.z) * q.z
        let e = b - a
        let f = d - c
        let g = d + c
        let h = b + a
        return EdwardsPoint(x: e * f, y: g * h, z: f * g, t: e * h)
    }

    /// Point doubling (RFC 8032 §5.1.4).
    var doubled: EdwardsPoint {
        let a = x.squared
        let b = y.squared
        let c = z.squared + z.squared
        let h = a + b
        let e = h - (x + y).squared
        let g = a - b
        let f = c + g
        return EdwardsPoint(x: e * f, y: g * h, z: f * g, t: e * h)
    }

    /// [a]P + [b]Q for 32-byte little-endian scalars (Straus–Shamir, variable
    /// time; only used on public data).
    static func doubleScalarMultiply(_ a: [UInt8], _ p: EdwardsPoint, _ b: [UInt8], _ q: EdwardsPoint) -> EdwardsPoint {
        let pq = p + q
        var acc = EdwardsPoint.identity
        for bit in stride(from: 255, through: 0, by: -1) {
            acc = acc.doubled
            let ab = (a[bit / 8] >> (bit % 8)) & 1 == 1
            let bb = (b[bit / 8] >> (bit % 8)) & 1 == 1
            switch (ab, bb) {
            case (true, true): acc = acc + pq
            case (true, false): acc = acc + p
            case (false, true): acc = acc + q
            case (false, false): break
            }
        }
        return acc
    }
}
