# PROGRESS

Continuity log. Update at the end of every session.

## Status (2026-11-27, session 1, part 15)

Since 0.2.0 (unreleased): `SigningConfig` (`pkg/root`) ported; BER
TimeStampTokens accepted (pkcs7 `ber2der`); test data embedded instead of
resource bundles (no target has one now); signed attributes verified over
the sorted DER SET as pkcs7 does; the Fulcio code-signing EKU check now
covers the root, as Go's. `swift test`: 204 tests. The only verify gap
left is ML-DSA in X.509 certificates (deferred, see Next steps).

**Verify-side parity with sigstore-go v1.4.1 is released as 0.2.0
(922063b).** CI run 45795632671 on that commit is green on all five jobs:
macOS, Linux, Windows, conformance and fuzz (30 s per target, ~1.8M
inputs in total, no crash, hang or invariant failure). `swift test`: 174
tests; conformance 135/135 (pin) and 141/141 (suite main).

**First consumer: appitool** (appibara-ltd/appitool, depends on
`.upToNextMinor(from: "0.2.0")`, macOS 26):

- `self-update` (appitool 850eb19) verifies the release archive's SLSA
  provenance with sigstore-swift on every update: bundles from the
  public attestations API, trusted roots over TUF (public-good, or
  GitHub's instance from `tuf-repo.github.com` with `gh`'s root v3
  embedded), the `gh attestation verify` verifier options per instance,
  and a release-workflow certificate identity. When `gh` is installed,
  `gh attestation verify` must agree; a disagreement aborts the update.
- `appitool verify -f <file>` (released in appitool v0.11.6) runs the
  same sigstore-swift checks without `gh`, with
  `--bundle`, `--repo`, `--signer-workflow` and `--predicate-type`
  (defaults: appitool's release attestations).
- appitool's 558-test suite passes with the 0.2.0 dependency, including
  tests against the real v0.11.0 bundles and both trusted roots.

Fuzz, first run (inputs in 30 s): json 65k, protojson 82k, bundle 28k,
trustedroot 28k, statement 228k, rfc3161 277k, note 182k, tuf 22k,
pathmatch 360k, mldsa 852k.

Platform: macOS 26 or later (`platforms: [.macOS(.v26)]`, raised from 13
after 0.1.0 at the user's request), Linux, Windows. CI tests the latest
macOS (`macos-latest`, macOS 26), Linux and Windows. 0.1.0 itself still
declares macOS 13.

### Conformance (sigstore-conformance, verify tests only)

Run locally with `scripts/run-conformance.sh` (needs `uv`); CI runs the
`conformance` job in `.github/workflows/ci.yml`. Client:
`Sources/sigstore-swift-conformance` (port of sigstore-go
`test/conformance/main.go`, verify-bundle only).

| Suite ref | Passed | Expected failures | Unexpected | CPython release bundles |
| --- | --- | --- | --- | --- |
| v0.0.29 (CI pin) | 135 | 0 | 0 | 81/81 |
| suite `main` e275ffb (unreleased; local run only) | 141 | 0 | 0 | 81/81 |

`.github/conformance-xfail.txt` (strict) is empty. Every `_fail` case was
re-checked by running the client on the asset dir: each is rejected for the
defect it targets. `rekor2-timestamp-with-incorrect-time_fail` is rejected
at bundle parsing with the same error as sigstore-go's own client
("invalid value for bytes field signedTimestamp"; checked by building
sigstore-go v1.4.1 `test/conformance` and running it on the asset).

When no `--trusted-root` is given, the client fetches `trusted_root.json`
over TUF from the public-good repository, or with `--staging` the staging
one, as sigstore-go's client does (no cache validity, so every invocation
refreshes: the suite takes ~80 s instead of ~20 s).

The appitool v0.11.0 SLSA provenance bundle (`appitool-darwin-arm64.tar.gz`,
sha256 `b5eeec2e…f0ce`) verifies against the public-good trusted root (test
fixture snapshot; at runtime from TUF via `fetchTrustedRoot()`)
with the `gh attestation verify` configuration
(`.withSignedCertificateTimestamps(threshold: 1)`,
`.withTransparencyLog(threshold: 1)`, `.withObserverTimestamps(threshold: 1)`)
and a policy of artifact digest + OIDC issuer
`https://token.actions.githubusercontent.com` + SAN regex for
`appibara-ltd/appitool/.github/workflows/release.yml@`.

### Verified

- Bundle parsing v0.1–v0.3 (protojson, unknown fields rejected), media-type
  versioning, v0.1 promise / v0.2+ proof requirements, v0.4+ rejected.
- DSSE PAE + signature (ECDSA P-256/384/521, Ed25519, RSA PKCS#1 v1.5),
  exactly one signature, v0.1–v0.3 P-384/P-521 SHA-256 compat.
- Fulcio chain: RFC 5280 path validation (swift-certificates) at each
  observer time, code-signing EKU on every certificate that lists EKUs,
  root included (Go `checkChainForKeyUsage`; the root used to be skipped,
  fixed 2026-11-27), CA `validFor` window, intermediates from bundle (v0.3
  + `.withAllowCertificateChain()`).
- Fulcio OID extensions (1.3.6.1.4.1.57264.1.1–22), SAN (URI, email,
  OtherName), `CertificateIdentity` matching (exact/regex SAN and issuer,
  extension equality).
- Embedded SCTs (RFC 6962 precert entry, CT log `validFor`, threshold).
- Trusted-root tlog keys: ECDSA, Ed25519, RSA (PKIX and raw PKCS#1).
- Rekor v1 entries (`dsse` 0.0.1, `hashedrekord` 0.0.1, `intoto` 0.0.2):
  RFC 6962 Merkle inclusion proof, signed checkpoint (key hint + signature +
  root-hash match), SET over JCS payload with log `validFor`, entry
  signature / certificate / payload-hash match, integrated time inside the
  certificate validity, duplicate-entry and entry-count limits.
- in-toto statement: subject digest vs artifact digest(s) or artifact bytes;
  subject/digest limits; predicate parsed to `Google_Protobuf_Struct`.
- TUF client (`Sources/SigstoreTUF`, port of sigstore-go `pkg/tuf` over
  go-tuf v2.4.2 `metadata`, `trustedmetadata`, `updater`, `config`,
  `fetcher`): root rotation (each new root signed by the old and new root
  role thresholds, version + 1, at most 256 rotations, stop on 404),
  timestamp/snapshot/targets with expiry against a fixed reference time,
  rollback checks (timestamp, snapshot meta versions), length/hash checks
  against the delegating metadata, threshold counted over distinct keys
  (PKIX fingerprint), duplicate-signature and `_type` checks, consistent
  snapshots (version-prefixed metadata, hash-prefixed targets), delegations
  (pre-order walk, terminating roles, `filepath.Match` paths, hash-prefix
  and succinct-role bins), max lengths, on-disk cache (`~/.sigstore/root`,
  same layout as sigstore-go) with `cacheValidity` / `forceCache`, and
  OLPC canonical JSON. Key types: ecdsa (P-256/384), ed25519, rsa (PSS).
  Verified live against `tuf-repo-cdn.sigstore.dev` and
  `tuf-repo.github.com` (gh's root v3 → v9). `fetchTrustedRoot()`,
  `fetchTrustedRootWithOptions(_:)`, `getTrustedRoot(_:)` in SigstoreRoot.
- ML-DSA (FIPS 204) verification for ML-DSA-44/65/87 in pure Swift
  (`Sources/SigstoreMLDSA`, with Keccak/SHAKE): tested against Go 1.27
  `crypto/mldsa` vectors (24 per parameter set, incl. malformed hints and z
  bounds) and NIST ACVP sigVer (15 per set). Wired in as pure ML-DSA with
  an empty context (sigstore `MLDSAVerifier`): SPKI keys
  (`SigstorePublicKey`), `ML_DSA_44` trusted-root log keys, rekor-tiles
  ML-DSA-44 note key IDs and cosignature/v1 checkpoint signatures, Rekor v2
  key details, digest-only verification refused as in Go.
- Ed25519ph (RFC 8032) and RSA PKCS#1 v1.5 / PSS over a precomputed digest
  in pure Swift (`Sources/SigstoreCryptoExtras`), tested against Go 1.27
  vectors (43 Ed25519ph, 530 RSA) incl. the RFC 8032 §7.3 vector, with a
  mutation check per security check. Certificate message signatures with
  Ed25519 keys verify as Ed25519ph (sigstore-go `compatSignatureVerifier`),
  also with only a SHA-512 digest; RSA keys verify digest-only; TUF
  RSA-PSS keys verify with salt auto-detection (go-tuf).
- `LiveTrustedRoot` (background TUF refresh, keeps the last good root,
  `stop()` in place of Go's context cancellation).
- `VerificationResult.jsonData()` / `init(json:)`: equal to sigstore-go
  v1.4.1's `json.Marshal` output for the provenance and release bundles
  (`scripts/verificationresult-reference`, `Fixtures/verification-result-*.go.json`).
- in-toto Statement from generated in-toto/attestation v1.2.0 protos:
  strict protojson for full statements (as `Envelope.Statement()`), Go's
  lenient "lite" decode when the predicate is skipped (`summarizeStatement`).
- `BundleV2` (validation, accessors, JSON) and the v1.4.1 v2 API:
  `VerifiableEntity`, `IdentityVerifier`, `PKIVerifier` (+
  `withPKISignedTimestamps`), `KeyVerifier` (+ `withKeySignedTimestamps`),
  whose `verify` throws "not implemented" exactly as in sigstore-go.
- TUF delegation paths use a port of Go's `path.Match` (polynomial time,
  Go's bad-pattern semantics), replacing a recursive matcher that was
  exponential on star-heavy patterns.
- RFC 3161 signed timestamps (`Sources/SigstoreRoot/RFC3161.swift`, port of
  timestamp-authority v2.2.0 `pkg/verification` + digitorus `timestamp` /
  `pkcs7` at sigstore-go's pins): TimeStampResp status, CMS SignedData
  signature (signed attributes + messageDigest, signingTime vs signer cert),
  signer chain to the TSA root at genTime with the timeStamping EKU on every
  certificate that has an EKU, leaf rules (end-entity, critical EKU, exactly
  one EKU = timeStamping, intermediates' EKU, trusted-root leaf must equal
  the embedded signer), SHA-256/384/512 imprint = hash of the signature
  bytes, PQC policy OID rejected for non-ML-DSA chains, TSA `validFor`
  (inclusive), duplicate-TSA and token-count limits.
- BER TimeStampTokens: the token is transcoded with a port of pkcs7
  `ber2der` before parsing, as in Go; tests port pkcs7's `ber_test.go` and
  check that the conformance and synthetic tokens re-encoded as BER
  (indefinite lengths, long-form lengths) verify like their DER originals,
  that a tampered BER token fails, and that the response around the token
  must stay DER.
- GitHub release attestations (`release.sigstore.json`) verify against
  GitHub's trusted root with `.withSignedTimestamps(threshold: 1)`.
- Rekor v2 entries (port of sigstore-go `pkg/verify/tlog.go` +
  `pkg/tlog/entry.go` v2 paths, rekor-tiles v2.4.2 `pkg/note`,
  `pkg/verify`, `pkg/types/hashedrekord`, x/mod `sumdb/note`,
  transparency-dev/formats `log`): strict protojson `hashedrekord` 0.0.2
  bodies (unknown fields rejected; dsse 0.0.2 is not accepted, as in Go),
  body validation, inclusion proof required, C2SP signed-note checkpoint
  (origin = trusted-root `baseUrl` host, rekor-tiles key IDs for
  ECDSA/Ed25519/RSA, unknown cosignatures ignored, a bad signature by the
  log key fails, at most 100 signatures), checkpoint origin match, and
  inclusion of the *reconstructed* entry hash (bundle signature + signing
  cert/key with its default algorithm + digest, or the PAE digest for DSSE)
  under the checkpoint root. Rekor v2 entries give no integrated timestamp;
  a TSA timestamp is required.
- `SigningConfig` (`Sources/SigstoreRoot/SigningConfig.swift`, port of
  sigstore-go v1.4.1 `pkg/root/signing_config.go`): v0.2 media type,
  strict protojson parsing (unknown fields, duplicate keys, unknown enum
  names rejected), `Service` / `ServiceConfiguration`, `selectService`
  (newest service of the highest supported API version valid at a time)
  and `selectServices` (`ALL` / `ANY` / `EXACT`, one service per operator,
  only the highest API version with a match), builders, `marshalJSON()`
  (equal to Go's `protojson.Marshal` output in Go's test), and
  `fetchSigningConfig()` / `fetchSigningConfigWithOptions(_:)` /
  `getSigningConfig(_:)` over TUF (`signing_config.v0.2.json`). Tests port
  Go's `signing_config_test.go` cases. Fetched live from
  `tuf-repo-cdn.sigstore.dev` on 2026-11-27 (Fulcio, OAuth2, Rekor v1 and
  the TSA, all `ANY`). Not used by verification; it prepares signing.

### Stubbed / not implemented

- ML-DSA inside X.509 certificates (Fulcio leaves, TSA chains):
  swift-certificates 1.21.2 (latest) cannot parse ML-DSA keys or
  signatures, so such a certificate fails to parse. ML-DSA is supported for
  raw keys only (managed keys, log keys). Plan: add ML-DSA to
  swift-certificates upstream (see Decisions and "ML-DSA in X.509:
  upstream status" below); not started.

### ML-DSA in X.509: what Sigstore uses (checked 2026-11-27)

ML-DSA in Sigstore is experimental and for private deployments only:
protobuf-specs `sigstore_common.proto` defines `ML_DSA_44` (23),
`ML_DSA_65` (21) and `ML_DSA_87` (22) as pure ML-DSA (FIPS 204, RFC 9881)
with a "USER WARNING: … experimental … MAY be used by private Sigstore
deployments, but they are not yet fully functional". By component:

- **sigstore-go v1.4.1**: `pkg/sign/mldsa.go` (`MLDSAKeypair`, added in
  #697) generates ephemeral **ML-DSA-44** signing keys; `pkg/root`
  accepts only ML-DSA-44 transparency-log keys. So a Fulcio leaf issued to
  sigstore-go's signer carries an ML-DSA-44 public key.
- **Fulcio** (`--experimental-enable-pqc`, added in #2522, 2026-11-10;
  `docs/setup.md`): issues ML-DSA certificates only for private
  deployments, with no CT log (so no SCTs). With the flag, the CA key and
  chain must be ML-DSA (any of 44/65/87; the `ephemeralca` backend uses
  **ML-DSA-65**), the chain must not mix ML-DSA and other keys, and client
  keys default to `mldsa-44,mldsa-65,mldsa-87`.
- **timestamp-authority**: ML-DSA signers of any parameter set (file
  keys), `--timestamp-signer-hash=sha512` required, and the PQC policy
  OID `1.3.6.1.4.1.57264.2.1` ties ML-DSA chains to that policy (we already
  port that check).
- **Public-good**: no ML-DSA anywhere in its trusted root (fixture
  snapshot of 2026-11-25): Rekor keys ECDSA P-256 and Ed25519, CT log keys
  ECDSA P-256, Fulcio and TSA chains ECDSA (ecdsa-with-SHA384).

So verifying a Sigstore ML-DSA deployment needs **all three** parameter
sets in certificates, and **ML-DSA-44** at least for leaf keys.

### ML-DSA in X.509: upstream status (checked 2026-11-27)

- **apple/swift-certificates #312** "Add ML-DSA-65 and ML-DSA-87
  certificate parsing and verification" (opened 2026-08-11 by an outside
  contributor; open, `CHANGES_REQUESTED`, last update 2026-10-16,
  `semver/minor`): RFC 9881 parsing and verification of ML-DSA-65/87 keys
  and signatures, chains through `Verifier` + `RFC5280Policy`. After review
  (Lukasa, Joannis) ML-DSA subject keys sit behind a default-off `MLDSA`
  package trait (needs swift-crypto ≥ 4.0.0; parsing certificates *signed*
  with ML-DSA works without it). On Apple platforms ML-DSA comes from
  CryptoKit (macOS/iOS 26 at runtime). A rebased head (all tests green)
  waits on a fork branch while downstream SHA pins move. No ML-DSA-44.
- **apple/swift-crypto #422** "Add ML-DSA-44 to CryptoExtras" (opened
  2025-10-23; open, awaiting review; last activity 2026-08-17, a request
  for maintainer interest without reply). swift-crypto has ML-DSA-65/87
  only, which is why `SigstoreMLDSA` exists.
- Consequence: #312 alone covers ML-DSA-65/87 CA and TSA chains but not
  ML-DSA-44 leaves (sigstore-go's signer default); a certificate with an
  ML-DSA-44 key would still fail to parse. ML-DSA-44 needs swift-crypto
  #422 and then a follow-up to #312.
- RFC 3161 `subjectKeyIdentifier` signer IDs are intentionally unsupported
  and revocation is not checked; Go's pkcs7 / sigstore-go do neither (see
  Decisions).
- The v2 verifiers (`IdentityVerifier`, `PKIVerifier`, `KeyVerifier`)
  throw "not implemented", as in sigstore-go v1.4.1.

### Fixtures

`Tests/SigstoreTests/Fixtures/appitool-v0.11.0/` from
`GET https://api.github.com/repos/appibara-ltd/appitool/attestations/sha256:b5eeec2e36db5cfbdda72707ac80b3c807cab76631a35cf618739e29d331f0ce`
(fetched 2026-11-25):

- `provenance.sigstore.json` — `https://slsa.dev/provenance/v1`, Fulcio cert,
  one Rekor v1 `dsse` 0.0.1 entry with proof + promise, no TSA.
- `release.sigstore.json` — `https://in-toto.io/attestation/release/v0.2`,
  GitHub-instance TSA token only, no tlog. SAN
  `https://dotcom.releases.github.com`.

`Tests/SigstoreTests/Fixtures/github_trusted_root.json` is GitHub's
instance trusted root from `gh attestation trusted-root` (second line),
sha256 `072b653e…b3c4`, fetched 2026-11-25.

`Tests/SigstoreTests/Fixtures/conformance/{intoto-with-custom-trust-root,
rekor2-happy-path,rekor2-dsse-happy-path}/` are copied from
sigstore-conformance (Apache-2.0) @ `e275ffb` `test/assets/bundle-verify/`
(the Rekor v2 ones with the suite's `a.txt` as `artifact`): a real TSA token
(genTime 2023-02-01T00:00:00Z) and real staging `log2025-alpha1` Rekor v2
entries.
Negative TSA tests build tokens with a throwaway PKI (`TestTSA` in
`TimestampAuthorityTests.swift`).

`Sources/SigstoreTUF/Resources/{root,staging_root}.json` are sigstore-go
v1.4.1 `pkg/tuf/repository/`, compiled in as
`Sources/SigstoreTUF/EmbeddedRoots.swift` by `scripts/embed-tuf-roots.sh` (sha256 `f1560a64…b96c` / `baf71cd3…2875`).

`Tests/SigstoreTests/Fixtures/tuf-repo.github.com/` is GitHub's TUF
repository captured 2026-11-25: `3.root.json` is `gh`'s embedded root
(cli/cli `pkg/cmd/attestation/verification/embed/tuf-repo.github.com/root.json`
@ `4618a267`, sha256 `98cba97b…1a8d`), `4`–`9.root.json`, `timestamp.json`
(v1026, expires 2026-12-02), `84.snapshot.json`, `10.targets.json` and the
hash-prefixed `trusted_root.json`. Tests pin the reference time to
2026-11-26. Negative TUF tests use a synthetic signed repository
(`TestTUFRepo` in `TUFTests.swift`).

`Tests/SigstoreTests/Fixtures/signing_config.v0.2.json` is sigstore-go
v1.4.1 `examples/signing_config.v0.2.json` (Apache-2.0), sha256
`9711a6d5…539c`.

`Tests/SigstoreTests/Fixtures/trusted_root.json` is `sigstore/root-signing`
`targets/trusted_root.json` @ main, sha256 `6494e21e…0b66`, fetched
2026-11-25 (test fixture only; the package embeds no trusted root).

## Next steps

Done: 0.2.0 tagged and released; appitool `self-update` integration
(embedded GitHub TUF root, sigstore-swift first, `gh` cross-check);
`SigningConfig` (`pkg/root`), BER TimeStampTokens and embedded test data,
unreleased.

1. **Hardening before announcing.** Watch the weekly fuzz runs (Mondays
   03:00 UTC, 15 min per target). Then a security review, with a human
   review of the hand-written cryptography (ML-DSA, Ed25519ph, RSA) and
   the parsers (protojson, DER/CMS, signed notes, TUF metadata).
2. **Repository hygiene as in sigstore-go**, whose workflows include
   `scorecard.yml` (OpenSSF Scorecard), `codeql.yml` and `depsreview.yml`:
   add Scorecard, a SAST job, dependency review, `SECURITY.md`,
   Dependabot, and pin actions by SHA.
3. **ML-DSA in X.509 certificates**, the only remaining verify gap
   (experimental, private deployments only; see "ML-DSA in X.509" above):
   upstream route (user decision, 2026-11-27; not yet). Follow or help
   swift-certificates #312 (ML-DSA-65/87), then enable its `MLDSA` trait
   and bump the dependency; ML-DSA-44 (sigstore-go's leaf key) also needs
   swift-crypto #422 and a swift-certificates follow-up. Re-check both PRs
   before starting.
4. **Signing** (sigstore-go `pkg/sign`): ephemeral keys, OIDC token
   handling, Fulcio certificate requests, Rekor v1/v2 uploads, TSA
   requests, bundle building. Then enable sigstore-conformance's sign
   tests.

## Decisions

- Minimum macOS is 26 (after 0.1.0, user decision): no support for older
  macOS. Linux and Windows unchanged.
- Verify-only first; signing later.
- Mirror sigstore-go names (see AGENTS.md for translation rules).
- Protobuf types generated from protobuf-specs @ `a84bc5ff572a` (the commit
  sigstore-go v1.4.1 pins) with swift-protobuf 1.41.0; generated code checked
  in; regenerate with `scripts/generate-protos.sh`. Swift names are the
  generated defaults (`Dev_Sigstore_Bundle_V1_Bundle`, ...).
- `Verifier.verify` is `async throws` (deviation from the planned sync
  `try verifier.verify(...)`): swift-certificates' path validator is async.
  No network I/O happens in it.
- `bundle.Certificate` / `bundle.PublicKey` are nested as `Bundle.Certificate`
  / `Bundle.PublicKey` to avoid clashing with `X509.Certificate`. `Bundle`
  itself clashes with `Foundation.Bundle`; callers write
  `SigstoreBundle.Bundle`.
- `crypto.Hash` → `HashFunc` (swift-crypto already has a `HashFunction`
  protocol).
- Artifacts are `Data` (Go takes `io.Reader`); streaming can be added later.
- Regexes use `NSRegularExpression` (ICU), not RE2; unanchored like Go.
- Predicate-type checks are left to the caller (as in sigstore-go; `gh`
  checks it after `Verify`).
- Extra strictness vs Go: Merkle proof hashes must be 32 bytes; Rekor v1
  body hashes must have the algorithm's length.
- `swift-crypto` range `3.12.0..<6.0.0` (resolves to 5.2.0).
- swift-tools-version stays 6.4. GitHub's macOS runners only have Xcode
  Swift 6.3 (macos-26 image, Xcode up to 26.6 as of 2026-11-17), so the
  macOS CI job installs Swift 6.4 with swiftly. Consequence: consumers on a
  release Xcode with Swift 6.3 cannot build the package.
- CI `build` job mirrors sigstore-go `build.yml`: build + test on
  `macos-latest`, `ubuntu-24.04` (`swift:6.4-noble` container) and
  `windows-2022` (swift.org 6.4.3 via `compnerd/gha-setup-swift`),
  `fail-fast: false`. Deviation: sigstore-go uses `windows-latest`, whose
  VS 18 MSVC STL (14.52) rejects Clang < 22 (STL1000, hit compiling
  swift-crypto's BoringSSL C++), and Swift 6.4.3 bundles Clang 21. Switch to
  `windows-latest` once Swift 6.5 (LLVM 23) is released; the unsupported
  `_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH` escape hatch was rejected.
- `.gitattributes` marks fixtures and embedded trust roots `-text`: the
  first Windows run checked out the conformance `artifact` with CRLF, so its
  digest no longer matched the signed statement.
- TUF cache paths are joined with Foundation URLs (platform separators),
  as sigstore-go uses `filepath.Join`.
- TUF signatures are checked over the OLPC canonical JSON of the received
  `signed` object (go-tuf canonicalizes its re-marshalled structs; the same
  bytes for well-formed metadata). Metadata go-tuf could never re-marshal
  (both `paths` and `path_hash_prefixes`, or both `roles` and
  `succinct_roles`) is rejected at parse. A timestamp without
  `snapshot.json` meta is an error (Go would nil-dereference).
- Cryptography swift-crypto lacks is implemented in pure Swift, in
  separate targets with Go-generated vectors (user decision, 2026-11-25):
  `SigstoreMLDSA` (FIPS 204 verify + SHAKE; swift-crypto has no ML-DSA-44
  and its 65/87 come from CryptoKit) and `SigstoreCryptoExtras` (Ed25519ph,
  RSA PKCS#1 v1.5/PSS over a digest). Verification only. Deviations, all
  fail-closed: Ed25519 key encodings are decoded strictly per RFC 8032
  §5.1.3 (Go's `SetBytes` accepts y ≥ p and x = 0 with the sign bit); RSA
  moduli above 8192 bits are rejected (Go `crypto/rsa`: no upper bound).
  That limit comes from swift-crypto's BoringSSL
  (`OPENSSL_RSA_MAX_MODULUS_BITS` = 8192, checked in
  `rsa_check_public_key`), which every RSA key passes through
  (`_RSA.Signing.PublicKey`, swift-certificates); `SigstoreCryptoExtras`'
  own cap of 16384 bits is never the binding one. Sigstore uses 2048–4096; PSS
  `saltLength: 0` means exactly zero (Go's 0 means auto; we use `nil`).
- `SigstorePublicKey` (classical `Certificate.PublicKey` or ML-DSA)
  replaces `Certificate.PublicKey` in `SignatureVerifier.publicKey`,
  `TransparencyLog.publicKey` and `EntryPublicKey.publicKey`.
- `VerificationResult` JSON keys are emitted sorted (Go: struct order);
  values, `omitempty` rules, `"statement": {}` for no statement and
  `null` for no timestamps match Go. Times are UTC (Go uses the local zone).
- Go's `BaseSignedEntity` / `BaseVerifiableEntity` are protocol-extension
  defaults on `SignedEntity` / `VerifiableEntity`.
- ProtoJSON's bytes normalization skips free-form `google.protobuf.Struct`
  fields (`predicate`, `annotations`), whose keys are not proto fields.
- Fuzzing: `Fuzz/` package + `scripts/fuzz.sh` (libFuzzer, ASan, 64 KB
  inputs as sigstore-go), CI job 30 s/target per push and 15 min/target
  weekly; failing inputs are uploaded as artifacts.
- `tuf.Client` is an actor; `Options` uses `with...` copies; the fetcher is
  async (`URLSession`) with up to 3 attempts on transport errors, 429 and
  5xx (sigstore-go uses an httpretry client). As go-tuf's fetcher, a
  `Content-Length` above the limit is rejected before the body is read and
  the body is streamed and abandoned once it exceeds the limit
  (`LimitedDownload`, a `URLSessionDataDelegate`).
- protojson inputs (bundles, trusted roots, Rekor v2 bodies) go through
  `ProtoJSON.normalizeBytesFields` before swift-protobuf: bytes fields
  (by JSON/proto name; no string field shares those names) are decoded with
  Go protojson's base64 rules (std or URL alphabet, no-padding mode when the
  length is not a multiple of 4, `\r`/`\n` skipped) and re-encoded, or
  rejected as Go would; duplicate fields are rejected as protojson does.
  `JSONValue` moved from SigstoreTUF to SigstoreCommon for this.
- Consistent-snapshot target paths prefer the sha256 hash (Go picks an
  arbitrary map entry).
- The conformance client fetches trusted roots over TUF like sigstore-go;
  the embedded staging trusted root was removed.
- No embedded trusted root (sigstore-go has none): callers fetch one over
  TUF (`fetchTrustedRoot()`) or load a file (`TrustedRoot(path:)`).
  `TrustedRoot.embeddedPublicGood()` was removed.
- TUF `root.json` files are compiled in as base64 literals generated by
  `scripts/embed-tuf-roots.sh` (Go: `go:embed`), not a resource bundle; a
  test pins their sha256 to sigstore-go's files.
- Conformance CI is pinned to sigstore-conformance v0.0.29 (as sigstore-go);
  verify tests only (`skip-signing`), no staging run until signing exists.
- Rekor v1 `intoto` 0.0.2 signatures decode leniently like Go (bad inner
  base64 → empty signature → "signature does not match"), not at parse time.
- RFC 3161 parsing is a hand-written SwiftASN1 walk (swift-certificates' CMS
  types are internal). Signed attributes are verified over the DER SET OF
  their encodings sorted bytewise, as pkcs7 `marshalAttributes` re-marshals
  them (Go `asn1.Marshal` sorts `set` slices with `bytes.Compare`), so
  attributes sent out of order verify when signed over the sorted set and
  fail when signed as sent, as in Go. Deviations from Go: SHA-1
  digests/signatures rejected at parse rather than by x509; chain
  validation returns one chain (swift-certificates) instead of all.
- BER TimeStampTokens (`Sources/SigstoreRoot/BER.swift`): `ber2der` is a
  port of digitorus/pkcs7 05f79448fa77 `ber.go`, run on the token in
  `PKCS7SignedData.parse` as `pkcs7.Parse` does, including its quirks (an
  empty indefinite-length value is rejected; a leading-zero length is
  accepted when the next byte is ≥ 0x80; bytes after the first object are
  ignored). Our addition: nesting deeper than 50 is rejected (SwiftASN1's
  limit for the DER that follows; Go recurses without a limit). The
  TimeStampResp around the token is read like Go's encoding/asn1 (DER
  headers, token kept as a raw TLV, `DERHeader`) instead of being fully
  DER-parsed, so a BER token inside a DER response is reachable. Stricter
  than Go, as before: elements after the token are rejected.
- Test data is embedded like the TUF roots: `scripts/embed-test-data.sh`
  writes `Tests/<target>/EmbeddedTestData.swift` (one base64 literal per
  file, with its sha256) from `Tests/SigstoreTests/Fixtures` and the
  `Vectors` directories, which `Package.swift` excludes from the targets.
  The CI `generated` job reruns both embed scripts and fails on a diff
  (sigstore-go: `check-embedded-root.yml`).
- `TimestampingAuthority.verify` and `verifySignedTimestamp*` are `async`
  (swift-certificates' path validator is async).
- rekor-tiles v2.4.2 `rekor/v2/*.proto` (sigstore-go's pin) are generated
  into `SigstoreProtobufSpecs` alongside protobuf-specs
  (`Dev_Sigstore_Rekor_V2_*`), by the same script.
- Rekor v2 entry hashes use swift-protobuf JSON + `JSONCanonicalizer`
  (RFC 8785, integers only) in place of Go protojson +
  cyberphone `jsoncanonicalizer`; unit tests check the result equals the
  leaf hash of real logged bodies.
- Conformance xfail list is read with `sed '/^#/d'` (an all-comment file
  made `grep -v` exit 1 under `set -e`).
- `SigningConfig` is a value type: the `with…` / `add…` builders return a
  modified copy (Go mutates the receiver and returns it). Infallible Go
  getters are properties (`rekorLogURLs`, `rekorLogURLsConfig`, …). An
  unset `rekorTlogConfig` / `tsaConfig` reads as an empty configuration
  (Go dereferences nil and panics). `Service` validity bounds are `Date?`
  (`nil` for Go's zero time); `toServiceProtobuf()` writes Go's zero time
  (`0001-01-01T00:00:00Z`) for an unset start, as Go does. Ties in the
  newest-first ordering keep Go's order for slices under 13 elements
  (pdqsort's stable insertion sort); above that Go's order is unspecified.
  `selectServices` takes an optional `RandomNumberGenerator` for the
  `ANY` / `EXACT` choice (Go: `math/rand`).
- go-tuf `multirepo` is not ported: sigstore-go does not use it (`pkg/tuf`
  uses the single-repository updater only).
- RFC 3161 `subjectKeyIdentifier` signer IDs are not supported, as in Go's
  pkcs7 (issuer-and-serial only).
- ML-DSA in X.509 certificates will be added to swift-certificates
  upstream (Option A, user decision 2026-11-27), not by parsing
  certificates ourselves; deferred.

## Spec questions

- sigstore-go accepts any Rekor v1 checkpoint whose root hash matches the
  proof, without comparing the checkpoint tree size to the proof's
  `treeSize` (rekor `VerifyCheckpointSignature`). Kept for parity; worth
  confirming this is intended (the root hash already binds the size).
- `hasRekorV1STH` distinguishes v1/v2 checkpoints by the origin line regex
  `.* - [0-9]+$`; a Rekor v2 log whose origin happened to match would take
  the v1 path. Is there a more robust discriminator in the spec?
- sigstore-go skips (rather than fails on) entries with a bad SET, so a
  bundle with one bad SET and no other entry fails only on the threshold.
  Kept for parity.
- GitHub's attestations API returns the release bundle signed by GitHub's
  Sigstore instance (TSA only). The public-good trusted root alone cannot
  verify it; a consumer needs GitHub's trusted root too.
- pkcs7 (and so sigstore-go) does not check the CMS `eContentType` is
  id-ct-TSTInfo nor the signed `contentType` attribute (RFC 5652 §11.1,
  RFC 3161 §2.4.2). Kept for parity; worth raising upstream.
- `rekor2-timestamp-with-incorrect-time_fail` carries base64 wrapped at 76
  columns ending in `=`, with a total length not a multiple of 4: Go's
  protojson then decodes without padding and rejects the `=`, so neither
  sigstore-go nor we reach the timestamp check this case targets (it is
  covered by `intoto-tsa-timestamp-outside-cert-validity_fail`). Worth
  reporting to sigstore-conformance.
- go-tuf matches `path_hash_prefixes` against base64url(sha256(path)); the
  TUF spec uses the hex digest. Mirrored; worth raising upstream.
- swift-build on Windows intermittently fails to "touch" a SwiftPM
  resource bundle directory (`copy /b <dir> +,,`): seen for the conformance
  client, SigstoreTUF and, on 2026-11-27 (run 46034322298), the
  SigstoreCryptoExtrasTests test bundle. No target has resource bundles
  any more (test data is embedded too). Worth reporting to swift-build.
