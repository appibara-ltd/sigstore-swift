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
    /// The message digest that was signed.
    public let digest: Data
    /// The digest algorithm name (from a bundle: the protobuf enum name, e.g.
    /// `SHA2_256`).
    public let digestAlgorithm: String
    /// The raw signature over the digest.
    public let signature: Data

    /// Mirrors `NewMessageSignature`.
    public init(digest: Data, digestAlgorithm: String, signature: Data) {
        self.digest = digest
        self.digestAlgorithm = digestAlgorithm
        self.signature = signature
    }

    /// Always `nil`: a message signature is not an envelope.
    public var envelopeContent: (any EnvelopeContent)? { nil }
    /// This message signature.
    public var messageSignatureContent: (any MessageSignatureContent)? { self }
}

/// Mirrors `bundle.Envelope`.
public struct Envelope: SignatureContent, EnvelopeContent {
    /// The underlying DSSE envelope.
    public let rawEnvelope: DSSEEnvelope

    /// Wraps a DSSE envelope.
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
    /// This envelope.
    public var envelopeContent: (any EnvelopeContent)? { self }
    /// Always `nil`: an envelope is not a message signature.
    public var messageSignatureContent: (any MessageSignatureContent)? { nil }
}

extension Bundle {
    /// Mirrors `bundle.Certificate`.
    public struct Certificate: VerificationContent {
        /// The leaf (signing) certificate.
        public let certificate: X509.Certificate?
        /// Intermediate certificates, leaf excluded. From a bundle, empty
        /// unless certificate chains are allowed.
        public let intermediates: [X509.Certificate]

        /// Mirrors `NewCertificate`.
        public init(certificate: X509.Certificate, intermediates: [X509.Certificate] = []) {
            self.certificate = certificate
            self.intermediates = intermediates
        }

        /// Returns `true` when `key` is a certificate equal to ``certificate``.
        /// `trustedMaterial` is unused.
        public func compareKey(_ key: EntryPublicKey?, trustedMaterial: any TrustedMaterial) -> Bool {
            guard case .certificate(let other) = key, let certificate else { return false }
            return certificate == other
        }

        /// Returns `true` when `time` lies within the certificate's validity
        /// period (bounds inclusive). `trustedMaterial` is unused.
        public func validAtTime(_ time: Date, trustedMaterial: any TrustedMaterial) -> Bool {
            guard let certificate else { return false }
            return !(certificate.notValidAfter < time) && !(certificate.notValidBefore > time)
        }

        /// Always `nil`: certificate content has no public key hint.
        public var publicKey: (any PublicKeyProvider)? { nil }
    }

    /// Mirrors `bundle.PublicKey`.
    public struct PublicKey: VerificationContent, PublicKeyProvider {
        /// The public key hint, used to look up the key in trusted material.
        public let hint: String

        /// Creates public key content with the given hint.
        public init(hint: String) {
            self.hint = hint
        }

        /// Returns `true` when `key` is a public key equal to the key that
        /// `trustedMaterial` holds for ``hint``; `false` if there is none.
        public func compareKey(_ key: EntryPublicKey?, trustedMaterial: any TrustedMaterial) -> Bool {
            guard let verifier = try? trustedMaterial.publicKeyVerifier(hint) else { return false }
            guard case .publicKey(let other) = key else { return false }
            return verifier.verifier.publicKey == other
        }

        /// Returns `true` when `trustedMaterial` holds a key for ``hint`` that
        /// is valid at `time`.
        public func validAtTime(_ time: Date, trustedMaterial: any TrustedMaterial) -> Bool {
            guard let verifier = try? trustedMaterial.publicKeyVerifier(hint) else { return false }
            return verifier.validAtTime(time)
        }

        /// Always `nil`: public key content has no certificate.
        public var certificate: X509.Certificate? { nil }
        /// Always empty: public key content has no certificates.
        public var intermediates: [X509.Certificate] { [] }
        /// This public key content.
        public var publicKey: (any PublicKeyProvider)? { self }
    }
}
