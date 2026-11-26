// One libFuzzer entry point; SIGSTORE_FUZZ_TARGET picks the parser. A
// target only checks that parsing never traps or hangs, plus cheap
// invariants (round trips) where the parser has an inverse.

import Crypto
import Foundation
import Sigstore
import SigstoreMLDSA

enum FuzzTarget: String, CaseIterable {
    case json, protojson, bundle, trustedroot, statement, rfc3161, note, tuf, pathmatch, mldsa
}

let target: FuzzTarget = {
    guard let name = ProcessInfo.processInfo.environment["SIGSTORE_FUZZ_TARGET"], let t = FuzzTarget(rawValue: name)
    else {
        fatalError("set SIGSTORE_FUZZ_TARGET to one of \(FuzzTarget.allCases.map(\.rawValue))")
    }
    return t
}()

/// Fixed note verifier (the key is irrelevant: parsing is what is fuzzed).
let noteVerifier: NoteVerifier = {
    let key = try! P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 1, count: 32))
    return try! NoteVerifier(origin: "log.example", verifier: SignatureVerifier(publicKey: .init(key.publicKey)))
}()

let mldsaKeys: [MLDSAPublicKey] = MLDSAParameterSet.allCases.map {
    try! MLDSAPublicKey(rawRepresentation: Data(repeating: 7, count: $0.publicKeySize), parameterSet: $0)
}

@_cdecl("LLVMFuzzerTestOneInput")
public func fuzz(_ start: UnsafeRawPointer, _ count: Int) -> CInt {
    let data = Data(bytes: start, count: count)
    switch target {
    case .json:
        if let v = try? JSONValue(parsing: data) {
            // Serialization must re-parse to the same value.
            precondition((try? JSONValue(parsing: v.serialized())) == v, "JSON round trip changed the value")
            _ = try? v.canonicalBytes()
        }
    case .protojson:
        if let normalized = try? ProtoJSON.normalizeBytesFields(data) {
            // Normalizing is idempotent.
            precondition((try? ProtoJSON.normalizeBytesFields(normalized)) == normalized, "normalization not idempotent")
        }
    case .bundle:
        if let b = try? SigstoreBundle.Bundle(json: data) {
            _ = try? b.tlogEntries()
            _ = try? b.timestamps()
            _ = try? b.signatureContent()
            _ = try? b.verificationContent()
            _ = try? b.marshalJSON()
        }
        _ = try? BundleV2(json: data)
    case .trustedroot:
        _ = try? TrustedRoot(json: data)
    case .statement:
        if let s = try? Statement(json: data) { _ = try? s.jsonData() }
    case .rfc3161:
        _ = try? RFC3161Timestamp.parseResponse(Array(data))
        _ = try? RFC3161Timestamp.parse(token: Array(data))
    case .note:
        let text = String(decoding: data, as: UTF8.self)
        _ = try? openNote(text, verifier: noteVerifier)
        _ = try? LogCheckpoint(text: text)
        _ = try? SignedCheckpoint(text: text)
    case .tuf:
        _ = try? Metadata<RootType>(fromBytes: data)
        _ = try? Metadata<TimestampType>(fromBytes: data)
        _ = try? Metadata<SnapshotType>(fromBytes: data)
        if let t = try? Metadata<TargetsType>(fromBytes: data) {
            _ = t.signed.delegations?.rolesForTarget("a/b/c.json")
        }
    case .pathmatch:
        // pattern \0 name
        let parts = data.split(separator: 0, maxSplits: 1, omittingEmptySubsequences: false)
        let pattern = String(decoding: parts.first ?? Data(), as: UTF8.self)
        let name = String(decoding: parts.count > 1 ? parts[1] : Data(), as: UTF8.self)
        if let role = try? DelegatedRole(
            .object(["name": .string("r"), "keyids": .array([]), "threshold": .number("1"), "paths": .array([.string(pattern)])]))
        {
            _ = role.isDelegatedPath(name)
        }
    case .mldsa:
        guard let first = data.first else { break }
        let key = mldsaKeys[Int(first) % mldsaKeys.count]
        let rest = data.dropFirst()
        let split = rest.count / 2
        _ = key.isValidSignature(rest.prefix(split), for: rest.suffix(rest.count - split))
        _ = try? MLDSAPublicKey(rawRepresentation: rest, parameterSet: key.parameterSet)
    }
    return 0
}
