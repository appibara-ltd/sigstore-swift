// RFC 6962 / RFC 9162 Merkle inclusion proofs. Port of
// github.com/transparency-dev/merkle (proof.VerifyInclusion, rfc6962 hasher),
// which rekor uses.

import Crypto
import Foundation
import SigstoreCommon

public enum Merkle {
    public static func hashLeaf<D: DataProtocol>(_ leaf: D) -> [UInt8] {
        var h = SHA256()
        h.update(data: [0x00])
        h.update(data: leaf)
        return Array(h.finalize())
    }

    public static func hashChildren(_ l: [UInt8], _ r: [UInt8]) -> [UInt8] {
        var h = SHA256()
        h.update(data: [0x01])
        h.update(data: l)
        h.update(data: r)
        return Array(h.finalize())
    }

    /// Mirrors `proof.VerifyInclusion`.
    public static func verifyInclusion(
        index: UInt64, size: UInt64, leafHash: [UInt8], proof: [[UInt8]], root: [UInt8]
    ) throws {
        let calculated = try rootFromInclusionProof(index: index, size: size, leafHash: leafHash, proof: proof)
        guard calculated == root else {
            throw SigstoreError(
                "calculated root:\n\(Hex.encode(calculated))\n does not match expected root:\n\(Hex.encode(root))"
            )
        }
    }

    /// Mirrors `proof.RootFromInclusionProof`.
    public static func rootFromInclusionProof(
        index: UInt64, size: UInt64, leafHash: [UInt8], proof: [[UInt8]]
    ) throws -> [UInt8] {
        guard index < size else {
            throw SigstoreError("index is beyond size: \(index) >= \(size)")
        }
        guard leafHash.count == 32 else {
            throw SigstoreError("leafHash has unexpected size \(leafHash.count), want 32")
        }
        let (inner, border) = decompInclProof(index: index, size: size)
        guard proof.count == inner + border else {
            throw SigstoreError("wrong proof size \(proof.count), want \(inner + border)")
        }
        for h in proof where h.count != 32 {
            throw SigstoreError("proof hash has unexpected size \(h.count), want 32")
        }
        var res = chainInner(seed: leafHash, proof: proof[0..<inner], index: index)
        res = chainBorderRight(seed: res, proof: proof[inner...])
        return res
    }

    static func decompInclProof(index: UInt64, size: UInt64) -> (inner: Int, border: Int) {
        let inner = innerProofSize(index: index, size: size)
        let border = (index >> UInt64(inner)).nonzeroBitCount
        return (inner, border)
    }

    static func innerProofSize(index: UInt64, size: UInt64) -> Int {
        let x = index ^ (size - 1)
        return x == 0 ? 0 : 64 - x.leadingZeroBitCount
    }

    static func chainInner(seed: [UInt8], proof: ArraySlice<[UInt8]>, index: UInt64) -> [UInt8] {
        var seed = seed
        for (i, h) in proof.enumerated() {
            if (index >> UInt64(i)) & 1 == 0 {
                seed = hashChildren(seed, h)
            } else {
                seed = hashChildren(h, seed)
            }
        }
        return seed
    }

    static func chainBorderRight(seed: [UInt8], proof: ArraySlice<[UInt8]>) -> [UInt8] {
        var seed = seed
        for h in proof {
            seed = hashChildren(h, seed)
        }
        return seed
    }
}
