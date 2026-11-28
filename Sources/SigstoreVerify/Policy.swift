// Policy half of sigstore-go pkg/verify/signed_entity.go.
//
// Go functional options (`func(*PolicyConfig) error`) become option values
// with static factories, e.g. `.withCertificateIdentity(id)`.

import Foundation
import SigstoreCommon

/// Mirrors `verify.ArtifactDigest`.
public struct ArtifactDigest: Sendable, Hashable {
    /// The digest algorithm name, such as `sha256`.
    public var algorithm: String
    /// The raw digest bytes.
    public var digest: Data

    /// Creates a digest from an algorithm name and raw digest bytes.
    public init(algorithm: String, digest: Data) {
        self.algorithm = algorithm
        self.digest = digest
    }
}

/// Mirrors `verify.PolicyConfig`.
public struct PolicyConfig: Sendable {
    var ignoreArtifact = false
    var ignoreIdentities = false
    /// Mirrors `PolicyConfig.RequireSigningKey`: whether the entity must be signed
    /// with a key rather than a certificate.
    public internal(set) var requireSigningKey = false
    var context: Data = Data()
    var certificateIdentities: CertificateIdentities = []
    var verifyArtifacts = false
    var artifacts: [Data] = []
    var verifyArtifactDigests = false
    var artifactDigests: [ArtifactDigest] = []

    init() {}

    func withVerifyAlreadyConfigured() throws {
        if verifyArtifacts || verifyArtifactDigests {
            throw SigstoreError(
                "only one invocation of WithArtifact/WithArtifacts/WithArtifactDigest/WithArtifactDigests is allowed")
        }
    }

    func validate() throws {
        if requireIdentities && certificateIdentities.isEmpty {
            throw SigstoreError("can't verify identities without providing at least one identity")
        }
        if !context.isEmpty && !requireSigningKey {
            throw SigstoreError("WithContext must be used with WithKey")
        }
    }

    /// Mirrors `PolicyConfig.RequireArtifact`: whether verification checks the
    /// signature against a provided artifact or digest.
    public var requireArtifact: Bool { !ignoreArtifact }
    /// Mirrors `PolicyConfig.RequireIdentities`: whether verification checks the
    /// certificate against the provided identities.
    public var requireIdentities: Bool { !ignoreIdentities }
}

/// Mirrors `verify.PolicyOption`.
public struct PolicyOption: Sendable {
    let apply: @Sendable (inout PolicyConfig) throws -> Void

    /// Mirrors `WithoutIdentitiesUnsafe`.
    public static func withoutIdentitiesUnsafe() -> PolicyOption {
        PolicyOption { p in
            if !p.certificateIdentities.isEmpty {
                throw SigstoreError("can't use WithoutIdentitiesUnsafe while specifying CertificateIdentities")
            }
            p.ignoreIdentities = true
        }
    }

    /// Mirrors `WithCertificateIdentity`. May be given several times; any
    /// matching identity is sufficient.
    public static func withCertificateIdentity(_ identity: CertificateIdentity) -> PolicyOption {
        PolicyOption { p in
            if p.ignoreIdentities {
                throw SigstoreError("can't use WithCertificateIdentity while using WithoutIdentitiesUnsafe")
            }
            if p.requireSigningKey {
                throw SigstoreError("can't use WithCertificateIdentity while using WithKey")
            }
            if !p.context.isEmpty {
                throw SigstoreError("can't use WithCertificateIdentity while using WithContext")
            }
            p.certificateIdentities.append(identity)
        }
    }

    /// Mirrors `WithKey`.
    public static func withKey() -> PolicyOption {
        PolicyOption { p in
            if !p.certificateIdentities.isEmpty {
                throw SigstoreError("can't use WithKey while using WithCertificateIdentity")
            }
            p.requireSigningKey = true
            p.ignoreIdentities = true
        }
    }

    /// Mirrors `WithContext`.
    public static func withContext(_ context: Data) -> PolicyOption {
        PolicyOption { p in
            if context.count != 32 {
                throw SigstoreError("context must be a 32-byte SHA-256 digest, got \(context.count) bytes")
            }
            if !p.certificateIdentities.isEmpty {
                throw SigstoreError("can't use WithContext while using WithCertificateIdentity")
            }
            p.context = context
        }
    }
}

/// Mirrors `verify.ArtifactPolicyOption`.
public struct ArtifactPolicyOption: Sendable {
    let apply: @Sendable (inout PolicyConfig) throws -> Void

    /// Mirrors `WithoutArtifactUnsafe`.
    public static func withoutArtifactUnsafe() -> ArtifactPolicyOption {
        ArtifactPolicyOption { p in
            try p.withVerifyAlreadyConfigured()
            p.ignoreArtifact = true
        }
    }

    /// Mirrors `WithArtifact` (takes the artifact bytes instead of an `io.Reader`).
    public static func withArtifact(_ artifact: Data) -> ArtifactPolicyOption {
        withArtifacts([artifact])
    }

    /// Mirrors `WithArtifacts`.
    public static func withArtifacts(_ artifacts: [Data]) -> ArtifactPolicyOption {
        ArtifactPolicyOption { p in
            try p.withVerifyAlreadyConfigured()
            if p.ignoreArtifact {
                throw SigstoreError("can't use WithArtifact while using WithoutArtifactUnsafe")
            }
            p.verifyArtifacts = true
            p.artifacts = artifacts
        }
    }

    /// Mirrors `WithArtifactDigest`.
    public static func withArtifactDigest(algorithm: String, digest: Data) -> ArtifactPolicyOption {
        ArtifactPolicyOption { p in
            try p.withVerifyAlreadyConfigured()
            if p.ignoreArtifact {
                throw SigstoreError("can't use WithArtifactDigest while using WithoutArtifactUnsafe")
            }
            p.verifyArtifactDigests = true
            p.artifactDigests = [ArtifactDigest(algorithm: algorithm, digest: digest)]
        }
    }

    /// Mirrors `WithArtifactDigests`.
    public static func withArtifactDigests(_ digests: [ArtifactDigest]) -> ArtifactPolicyOption {
        ArtifactPolicyOption { p in
            try p.withVerifyAlreadyConfigured()
            if p.ignoreArtifact {
                throw SigstoreError("can't use WithArtifactDigests while using WithoutArtifactUnsafe")
            }
            p.verifyArtifactDigests = true
            p.artifactDigests = digests
        }
    }
}

/// Mirrors `verify.PolicyBuilder` / `NewPolicy(artifactOpt, options...)`.
public struct PolicyBuilder: Sendable {
    let artifactPolicy: ArtifactPolicyOption
    let policyOptions: [PolicyOption]

    /// Mirrors `NewPolicy`: an artifact policy plus any further policy options.
    /// Options are applied and validated by ``buildConfig()``.
    public init(_ artifactPolicy: ArtifactPolicyOption, _ options: PolicyOption...) {
        self.init(artifactPolicy, options: options)
    }

    /// Mirrors `NewPolicy` with the options passed as an array.
    public init(_ artifactPolicy: ArtifactPolicyOption, options: [PolicyOption]) {
        self.artifactPolicy = artifactPolicy
        self.policyOptions = options
    }

    /// Mirrors `PolicyBuilder.BuildConfig`.
    public func buildConfig() throws -> PolicyConfig {
        var policy = PolicyConfig()
        try artifactPolicy.apply(&policy)
        for option in policyOptions {
            try option.apply(&policy)
        }
        try policy.validate()
        return policy
    }
}
