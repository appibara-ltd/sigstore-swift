// Port of sigstore-go pkg/bundle/signature_content.go and
// verification_content.go.
//
// `Certificate` and `PublicKey` are nested in `Bundle` (Go: bundle.Certificate,
// bundle.PublicKey) to avoid clashing with X509.Certificate at top level.

import Foundation
import SigstoreCommon
import SigstoreRoot
import SigstoreTLog
import SigstoreVerify
import X509

/// Mirrors `bundle.MessageSignature`.
public struct MessageSignature: SignatureContent, MessageSignatureContent {
    public let digest: Data
    public let digestAlgorithm: String
    public let signature: Data

    /// Mirrors `NewMessageSignature`.
    public init(digest: Data, digestAlgorithm: String, signature: Data) {
        self.digest = digest
        self.digestAlgorithm = digestAlgorithm
        self.signature = signature
    }

    public var envelopeContent: (any EnvelopeContent)? { nil }
    public var messageSignatureContent: (any MessageSignatureContent)? { self }
}

/// Mirrors `bundle.Envelope`.
public struct Envelope: SignatureContent, EnvelopeContent {
    public let rawEnvelope: DSSEEnvelope

    public init(_ envelope: DSSEEnvelope) {
        self.rawEnvelope = envelope
    }

    /// Mirrors `Envelope.Statement`.
    public func statement() throws -> Statement {
        guard rawEnvelope.payloadType == intotoMediaType else {
            throw BundleError.unsupportedMediaType(rawEnvelope.payloadType)
        }
        do {
            return try Statement(json: rawEnvelope.payload)
        } catch {
            throw BundleError.decodingJSON
        }
    }

    /// First signature, or empty (Go `Envelope.Signature`).
    public var signature: Data { rawEnvelope.signatures.first?.sig ?? Data() }
    public var envelopeContent: (any EnvelopeContent)? { self }
    public var messageSignatureContent: (any MessageSignatureContent)? { nil }
}

extension Bundle {
    /// Mirrors `bundle.Certificate`.
    public struct Certificate: VerificationContent {
        public let certificate: X509.Certificate?
        public let intermediates: [X509.Certificate]

        /// Mirrors `NewCertificate`.
        public init(certificate: X509.Certificate, intermediates: [X509.Certificate] = []) {
            self.certificate = certificate
            self.intermediates = intermediates
        }

        public func compareKey(_ key: EntryPublicKey?, trustedMaterial: any TrustedMaterial) -> Bool {
            guard case .certificate(let other) = key, let certificate else { return false }
            return certificate == other
        }

        public func validAtTime(_ time: Date, trustedMaterial: any TrustedMaterial) -> Bool {
            guard let certificate else { return false }
            return !(certificate.notValidAfter < time) && !(certificate.notValidBefore > time)
        }

        public var publicKey: (any PublicKeyProvider)? { nil }
    }

    /// Mirrors `bundle.PublicKey`.
    public struct PublicKey: VerificationContent, PublicKeyProvider {
        public let hint: String

        public init(hint: String) {
            self.hint = hint
        }

        public func compareKey(_ key: EntryPublicKey?, trustedMaterial: any TrustedMaterial) -> Bool {
            guard let verifier = try? trustedMaterial.publicKeyVerifier(hint) else { return false }
            guard case .publicKey(let other) = key else { return false }
            return verifier.verifier.publicKey == other
        }

        public func validAtTime(_ time: Date, trustedMaterial: any TrustedMaterial) -> Bool {
            guard let verifier = try? trustedMaterial.publicKeyVerifier(hint) else { return false }
            return verifier.validAtTime(time)
        }

        public var certificate: X509.Certificate? { nil }
        public var intermediates: [X509.Certificate] { [] }
        public var publicKey: (any PublicKeyProvider)? { self }
    }
}
