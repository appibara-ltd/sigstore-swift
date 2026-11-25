// Port of sigstore-go pkg/verify/signature.go.

import Crypto
import Foundation
import SigstoreCommon
import SigstoreRoot
import X509

let maxAllowedSubjects = 1024
let maxAllowedSubjectDigests = 32

/// Mirrors `ErrDSSEInvalidSignatureCount`.
public struct DSSEInvalidSignatureCountError: Error, CustomStringConvertible, Sendable {
    public var description: String { "exactly one signature is required" }
}

/// One or more signature verifiers tried in order (Go `compatVerifier`
/// wrapping, or a single `signature.Verifier`).
struct CompatVerifier: Sendable {
    var verifiers: [SignatureVerifier]

    func verify(signature: Data, message: Data) -> Bool {
        verifiers.contains { $0.verify(signature: signature, message: message) }
    }
}

/// Mirrors `VerifySignature`.
public func verifySignature(
    _ sigContent: any SignatureContent,
    _ verificationContent: any VerificationContent,
    trustedMaterial: any TrustedMaterial
) throws {
    let verifier: CompatVerifier
    do {
        verifier = try getSignatureVerifier(sigContent, verificationContent, trustedMaterial, enableCompat: false)
    } catch {
        throw error.wrapped("could not load signature verifier")
    }
    try verifySignatureWithVerifier(verifier, sigContent)
}

/// Mirrors `VerifySignatureWithArtifacts`.
public func verifySignatureWithArtifacts(
    _ sigContent: any SignatureContent,
    _ verificationContent: any VerificationContent,
    trustedMaterial: any TrustedMaterial,
    artifacts: [Data]
) throws {
    let verifier: CompatVerifier
    do {
        verifier = try getSignatureVerifier(sigContent, verificationContent, trustedMaterial, enableCompat: false)
    } catch {
        throw error.wrapped("could not load signature verifier")
    }
    try verifySignatureWithVerifierAndArtifacts(verifier, sigContent, artifacts)
}

/// Mirrors `VerifySignatureWithArtifactDigests`.
public func verifySignatureWithArtifactDigests(
    _ sigContent: any SignatureContent,
    _ verificationContent: any VerificationContent,
    trustedMaterial: any TrustedMaterial,
    digests: [ArtifactDigest]
) throws {
    let verifier: CompatVerifier
    do {
        verifier = try getSignatureVerifier(sigContent, verificationContent, trustedMaterial, enableCompat: false)
    } catch {
        throw error.wrapped("could not load signature verifier")
    }
    try verifySignatureWithVerifierAndArtifactDigests(verifier, sigContent, digests)
}

func verifySignatureWithVerifier(_ verifier: CompatVerifier, _ sigContent: any SignatureContent) throws {
    if let envelope = sigContent.envelopeContent {
        try verifyEnvelope(verifier, envelope)
        return
    }
    if sigContent.messageSignatureContent != nil {
        throw SigstoreError("artifact must be provided to verify message signature")
    }
    throw SigstoreError("signature content has neither an envelope or a message")
}

func verifySignatureWithVerifierAndArtifacts(
    _ verifier: CompatVerifier, _ sigContent: any SignatureContent, _ artifacts: [Data]
) throws {
    let envelope = sigContent.envelopeContent
    let msg = sigContent.messageSignatureContent
    if envelope == nil && msg == nil {
        throw SigstoreError("signature content has neither an envelope or a message")
    }
    guard let envelope else {
        guard artifacts.count == 1, let msg else {
            throw SigstoreError("only one artifact can be verified with a message signature")
        }
        try verifyMessageSignatureContent(verifier, msg, artifacts[0])
        return
    }
    try verifyEnvelopeWithArtifacts(verifier, envelope, artifacts)
}

func verifySignatureWithVerifierAndArtifactDigests(
    _ verifier: CompatVerifier, _ sigContent: any SignatureContent, _ digests: [ArtifactDigest]
) throws {
    let envelope = sigContent.envelopeContent
    let msg = sigContent.messageSignatureContent
    if envelope == nil && msg == nil {
        throw SigstoreError("signature content has neither an envelope or a message")
    }
    guard let envelope else {
        guard digests.count == 1, let msg else {
            throw SigstoreError("only one artifact can be verified with a message signature")
        }
        try verifyMessageSignatureWithArtifactDigest(verifier, msg, digests[0].digest)
        return
    }
    try verifyEnvelopeWithArtifactDigests(verifier, envelope, digests)
}

/// Mirrors `compatSignatureVerifier`. For bundles <= v0.3, ECDSA P-384/P-521
/// keys additionally accept SHA-256 (historical client behaviour).
func compatSignatureVerifier(_ leafCert: Certificate, enableCompat: Bool, isDSSE: Bool) throws -> CompatVerifier {
    let defaultVerifier = try SignatureVerifier(publicKey: leafCert.publicKey)
    if defaultVerifier.isEd25519 && !isDSSE {
        // sigstore-go loads Ed25519ph for message signatures (hashedrekord).
        throw SigstoreError("Ed25519ph message signatures are not supported yet")
    }
    guard enableCompat else { return CompatVerifier(verifiers: [defaultVerifier]) }
    switch defaultVerifier.key {
    case .ecdsaP384, .ecdsaP521:
        let compat = try SignatureVerifier(publicKey: leafCert.publicKey, hashFunction: .sha256)
        return CompatVerifier(verifiers: [defaultVerifier, compat])
    default:
        return CompatVerifier(verifiers: [defaultVerifier])
    }
}

/// Mirrors `getSignatureVerifier`.
func getSignatureVerifier(
    _ sigContent: any SignatureContent,
    _ verificationContent: any VerificationContent,
    _ tm: any TrustedMaterial,
    enableCompat: Bool
) throws -> CompatVerifier {
    if let leafCert = verificationContent.certificate {
        return try compatSignatureVerifier(
            leafCert, enableCompat: enableCompat, isDSSE: sigContent.envelopeContent != nil)
    }
    if let pk = verificationContent.publicKey {
        return CompatVerifier(verifiers: [try tm.publicKeyVerifier(pk.hint).verifier])
    }
    throw SigstoreError("no public key or certificate found")
}

/// Mirrors `verifyEnvelope` (go-securesystemslib `EnvelopeVerifier.Verify`
/// with a threshold of one).
func verifyEnvelope(_ verifier: CompatVerifier, _ envelope: any EnvelopeContent) throws {
    let env = envelope.rawEnvelope
    guard env.signatures.count == 1 else {
        throw DSSEInvalidSignatureCountError()
    }
    let pae = DSSEEnvelope.pae(payloadType: env.payloadType, payload: env.payload)
    guard verifier.verify(signature: env.signatures[0].sig, message: pae) else {
        throw SigstoreError("could not verify envelope: accepted signatures do not match threshold, Found: 0, Expected 1")
    }
}

func verifyEnvelopeWithArtifacts(_ verifier: CompatVerifier, _ envelope: any EnvelopeContent, _ artifacts: [Data])
    throws
{
    guard !artifacts.isEmpty else {
        throw SigstoreError("no artifacts provided for verification")
    }
    try verifyEnvelope(verifier, envelope)
    let statement: Statement
    do {
        statement = try summarizeStatement(envelope)
    } catch {
        throw error.wrapped("could not verify artifact: unable to extract statement from envelope")
    }
    try limitSubjects(statement)
    guard !statement.subject.isEmpty else {
        throw SigstoreError("no subjects found in statement")
    }

    let hashFuncs: [HashFunc]
    do {
        hashFuncs = try getHashFunctions(statement)
    } catch {
        throw error.wrapped("unable to determine hash functions")
    }

    let hashedArtifacts: [[HashFunc: [UInt8]]] = artifacts.map { artifact in
        Dictionary(uniqueKeysWithValues: hashFuncs.map { ($0, $0.digest(artifact)) })
    }

    var subjectDigests: [HashFunc: [[UInt8]]] = [:]
    for subject in statement.subject {
        for (alg, hexDigest) in subject.digest {
            guard let hf = try? HashFunc(algorithmString: alg) else { continue }
            guard let digest = Hex.decode(hexDigest) else { continue }
            subjectDigests[hf, default: []].append(digest)
        }
    }

    for ha in hashedArtifacts {
        var matchFound = false
        for (key, value) in ha {
            guard let statementDigests = subjectDigests[key] else {
                throw SigstoreError("no matching artifact hash algorithm found in subject digests")
            }
            if statementDigests.contains(value) {
                matchFound = true
                break
            }
        }
        if !matchFound {
            throw SigstoreError("provided artifact digests do not match digests in statement")
        }
    }
}

func verifyEnvelopeWithArtifactDigests(
    _ verifier: CompatVerifier, _ envelope: any EnvelopeContent, _ digests: [ArtifactDigest]
) throws {
    guard !digests.isEmpty else {
        throw SigstoreError("no artifact digests provided for verification")
    }
    try verifyEnvelope(verifier, envelope)
    let statement: Statement
    do {
        statement = try summarizeStatement(envelope)
    } catch {
        throw error.wrapped("could not verify artifact: unable to extract statement from envelope")
    }
    try limitSubjects(statement)

    var subjectDigests: [String: [[UInt8]]] = [:]
    for subject in statement.subject {
        for (alg, digest) in subject.digest {
            guard let decoded = Hex.decode(digest) else {
                throw SigstoreError("could not verify artifact: unable to decode subject digest")
            }
            subjectDigests[alg, default: []].append(decoded)
        }
    }

    for artifactDigest in digests {
        guard let statementDigests = subjectDigests[artifactDigest.algorithm] else {
            throw SigstoreError("provided artifact digests does not match digests in statement")
        }
        if !statementDigests.contains(Array(artifactDigest.digest)) {
            throw SigstoreError("provided artifact digest does not match any digest in statement")
        }
    }
}

func verifyMessageSignatureContent(_ verifier: CompatVerifier, _ msg: any MessageSignatureContent, _ artifact: Data)
    throws
{
    if msg.digest.isEmpty {
        throw SigstoreError("message is missing artifact digest")
    }
    let hashFunc: HashFunc
    do {
        hashFunc = try HashFunc(algorithmString: msg.digestAlgorithm)
    } catch {
        throw error.wrapped("could not verify message digest algorithm")
    }
    guard verifier.verify(signature: msg.signature, message: artifact) else {
        throw SigstoreError("could not verify message: invalid signature")
    }
    if hashFunc.digest(artifact) != Array(msg.digest) {
        throw SigstoreError("artifact digest does not match message digest")
    }
}

func verifyMessageSignatureWithArtifactDigest(
    _ verifier: CompatVerifier, _ msg: any MessageSignatureContent, _ artifactDigest: Data
) throws {
    if artifactDigest != msg.digest {
        throw SigstoreError("artifact does not match digest")
    }
    // TODO: prehashed ECDSA/RSA verification (sigstore options.WithDigest).
    throw SigstoreError("verifying message signatures against an artifact digest is not implemented yet")
}

func limitSubjects(_ statement: Statement) throws {
    if statement.subject.count > maxAllowedSubjects {
        throw SigstoreError("too many subjects: \(statement.subject.count) > \(maxAllowedSubjects)")
    }
    for subject in statement.subject where subject.digest.count > maxAllowedSubjectDigests {
        throw SigstoreError("too many digests: \(subject.digest.count) > \(maxAllowedSubjectDigests)")
    }
}

/// Mirrors `getHashFunctions`: picks, per subject, the strongest supported
/// hash unless one already chosen covers it.
func getHashFunctions(_ statement: Statement) throws -> [HashFunc] {
    guard !statement.subject.isEmpty else {
        throw SigstoreError("no subjects found in statement")
    }
    let supported: [HashFunc] = [.sha512, .sha384, .sha256]
    var chosen: [HashFunc] = []
    for subject in statement.subject {
        let hfs = subject.digest.keys.compactMap { try? HashFunc(algorithmString: $0) }
        if hfs.contains(where: chosen.contains) { continue }
        if let hf = supported.first(where: hfs.contains) {
            chosen.append(hf)
        }
    }
    guard !chosen.isEmpty else {
        throw SigstoreError("no supported digest algorithms found")
    }
    return chosen
}
