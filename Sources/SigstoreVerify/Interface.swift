// Port of sigstore-go pkg/verify/interface.go.

import Foundation
import SigstoreRoot
import SigstoreTLog
import X509

/// Mirrors `verify.SignedEntity`. Go getter methods that return an error stay
/// throwing methods; infallible ones become properties.
public protocol SignedEntity: Sendable {
    var hasInclusionPromise: Bool { get }
    var hasInclusionProof: Bool { get }
    func signatureContent() throws -> any SignatureContent
    /// RFC 3161 signed timestamps (DER).
    func timestamps() throws -> [Data]
    func tlogEntries() throws -> [Entry]
    func verificationContent() throws -> any VerificationContent
    func version() throws -> String
}

/// Mirrors `verify.VerificationContent`.
public protocol VerificationContent: Sendable {
    func compareKey(_ key: EntryPublicKey?, trustedMaterial: any TrustedMaterial) -> Bool
    func validAtTime(_ time: Date, trustedMaterial: any TrustedMaterial) -> Bool
    var certificate: Certificate? { get }
    var intermediates: [Certificate] { get }
    var publicKey: (any PublicKeyProvider)? { get }
}

/// Mirrors `verify.SignatureContent`.
public protocol SignatureContent: Sendable {
    var signature: Data { get }
    var envelopeContent: (any EnvelopeContent)? { get }
    var messageSignatureContent: (any MessageSignatureContent)? { get }
}

/// Mirrors `verify.PublicKeyProvider`.
public protocol PublicKeyProvider: Sendable {
    var hint: String { get }
}

/// Mirrors `verify.MessageSignatureContent`.
public protocol MessageSignatureContent: Sendable {
    var digest: Data { get }
    var digestAlgorithm: String { get }
    var signature: Data { get }
}

/// Mirrors `verify.EnvelopeContent`.
public protocol EnvelopeContent: Sendable {
    var rawEnvelope: DSSEEnvelope { get }
    func statement() throws -> Statement
}
