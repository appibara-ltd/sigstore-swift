/// The ML-DSA parameter sets of FIPS 204 §4, Table 1.
///
/// Mirrors Go's `crypto/mldsa` `Parameters` (`MLDSA44()`, `MLDSA65()`,
/// `MLDSA87()`).
public enum MLDSAParameterSet: Sendable, Hashable, CaseIterable, CustomStringConvertible {
    case mlDSA44
    case mlDSA65
    case mlDSA87

    /// FIPS 204 name, e.g. "ML-DSA-44" (as Go's `Parameters.String()`).
    public var description: String {
        switch self {
        case .mlDSA44: "ML-DSA-44"
        case .mlDSA65: "ML-DSA-65"
        case .mlDSA87: "ML-DSA-87"
        }
    }

    /// Length of a pkEncode public key in bytes (FIPS 204 Table 2).
    public var publicKeySize: Int { parameters.publicKeyLength }

    /// Length of a sigEncode signature in bytes (FIPS 204 Table 2).
    public var signatureSize: Int { parameters.signatureLength }

    var parameters: MLDSAParameters {
        switch self {
        case .mlDSA44: .mlDSA44
        case .mlDSA65: .mlDSA65
        case .mlDSA87: .mlDSA87
        }
    }
}

/// Modulus q = 2^23 − 2^13 + 1 (FIPS 204 §4).
let mldsaQ: Int64 = 8_380_417
/// d: dropped bits from t (FIPS 204 Table 1).
let mldsaD = 13

/// Values of FIPS 204 Table 1 used by verification.
struct MLDSAParameters: Sendable {
    let k: Int
    let l: Int
    /// τ: number of ±1 coefficients in c.
    let tau: Int
    /// β = τ·η.
    let beta: Int64
    /// γ1: coefficient range of y (a power of two).
    let gamma1: Int64
    /// γ2: low-order rounding range.
    let gamma2: Int64
    /// ω: maximum number of 1s in the hint h.
    let omega: Int
    /// λ: collision strength of c̃, in bits.
    let lambda: Int

    static let mlDSA44 = MLDSAParameters(
        k: 4, l: 4, tau: 39, beta: 78, gamma1: 1 << 17, gamma2: (mldsaQ - 1) / 88, omega: 80, lambda: 128)
    static let mlDSA65 = MLDSAParameters(
        k: 6, l: 5, tau: 49, beta: 196, gamma1: 1 << 19, gamma2: (mldsaQ - 1) / 32, omega: 55, lambda: 192)
    static let mlDSA87 = MLDSAParameters(
        k: 8, l: 7, tau: 60, beta: 120, gamma1: 1 << 19, gamma2: (mldsaQ - 1) / 32, omega: 75, lambda: 256)

    /// Length of c̃ in bytes: λ/4 (FIPS 204 Algorithm 26).
    var cTildeLength: Int { lambda / 4 }

    /// Bits per packed z coefficient: bitlen((γ1 − 1) + γ1) (Algorithm 26/27).
    var zBits: Int { gamma1 == 1 << 17 ? 18 : 20 }

    /// Bits per w1 coefficient: bitlen((q − 1)/(2γ2) − 1) (Algorithm 28).
    var w1Bits: Int { gamma2 == (mldsaQ - 1) / 88 ? 6 : 4 }

    /// |pk| = 32 + 32·k·(bitlen(q − 1) − d) (FIPS 204 Table 2).
    var publicKeyLength: Int { 32 + 32 * k * 10 }

    /// |σ| = λ/4 + l·32·(1 + bitlen(γ1 − 1)) + ω + k (FIPS 204 Table 2).
    var signatureLength: Int { cTildeLength + l * 32 * zBits + omega + k }
}
