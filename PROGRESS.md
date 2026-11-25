# PROGRESS

Continuity log. Update at the end of every session.

## Status (2026-11-25, session 1, part 4)

**Rekor v2 verification implemented (uncommitted); every conformance verify
test passes with no expected failures.** `main` (6268aee) has RFC 3161 and a
macOS/Linux/Windows CI matrix, all green (run 45665092861). `swift test`:
79 tests pass on macOS.

### Conformance (sigstore-conformance, verify tests only)

Run locally with `scripts/run-conformance.sh` (needs `uv`); CI runs the
`conformance` job in `.github/workflows/ci.yml`. Client:
`Sources/sigstore-swift-conformance` (port of sigstore-go
`test/conformance/main.go`, verify-bundle only).

| Suite ref | Passed | Expected failures | Unexpected | CPython release bundles |
| --- | --- | --- | --- | --- |
| v0.0.29 (CI pin) | 135 | 0 | 0 | 81/81 |
| main e275ffb | 141 | 0 | 0 | 81/81 |

`.github/conformance-xfail.txt` (strict) is empty. Every `_fail` case was
re-checked by running the client on the asset dir: each is rejected for the
defect it targets, except `rekor2-timestamp-with-incorrect-time_fail`
(see Spec questions: rejected at bundle parsing, before the timestamp check).

When no `--trusted-root` is given, the client uses the embedded public-good
root, or with `--staging` an embedded staging root
(`Sources/sigstore-swift-conformance/Resources/staging_trusted_root.json`,
`sigstore/root-signing-staging` `targets/trusted_root.json` @ main, sha256
`44deb991…6ed8`, fetched 2026-11-25). sigstore-go fetches both via TUF.

The appitool v0.11.0 SLSA provenance bundle (`appitool-darwin-arm64.tar.gz`,
sha256 `b5eeec2e…f0ce`) verifies against the embedded public-good trusted root
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
  observer time, code-signing EKU, CA `validFor` window, intermediates from
  bundle (v0.3 + `.withAllowCertificateChain()`).
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

### Stubbed / not implemented

- RFC 3161: BER-encoded tokens, `subjectKeyIdentifier` signer IDs (also
  unsupported by Go's pkcs7), ML-DSA TSA keys, revocation (not checked by Go
  either).
- Rekor v2: ML-DSA log keys (cosignature/v1 note framing), RSA-PSS
  signing keys (sigstore-go's default details never pick PSS either).
- TUF client (`SigstoreTUF` holds only `Options`); trusted root is embedded.
- Message signatures over a digest only: ECDSA done (prehashed `Digest`
  wrapper); RSA not (swift-crypto RSA rejects foreign digest types).
  Ed25519ph; ML-DSA tlog keys.
- `IdentityVerifier` / `VerifiableEntity` / bundle v2, `SigningConfig`,
  `LiveTrustedRoot`, `VerificationResult` JSON encoding.

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

`Sources/SigstoreRoot/Resources/trusted_root.json` (also copied to test
fixtures) is `sigstore/root-signing` `targets/trusted_root.json` @ main,
sha256 `6494e21e…0b66`, fetched 2026-11-25.

## Next steps (toward conformance)

1. **CI**: confirm the Rekor v2 commit is green, including the conformance
   action with an empty xfail input.
2. **GitHub trusted root for consumers**: ship or fetch (TUF,
   `tuf-repo.github.com`) GitHub's trusted root so appitool can verify
   release attestations; tests use a fixture copy only.
3. **Base64 leniency**: Go's protojson accepts `\n`/`\r` inside base64
   bytes fields (`base64.StdEncoding` skips them); swift-protobuf rejects
   them (see Spec questions). Decide whether to match.
4. **TUF client** (`pkg/tuf`): root rotation, timestamp/snapshot/targets,
   delegations, consistent snapshots, on-disk cache; embedded root.json for
   the public-good and GitHub repos; `TrustedRoot.fetch()` / live refresh.
5. Prehashed signature verification (message signatures with digest only),
   Ed25519ph, ML-DSA, `SigningConfig`, `VerificationResult` JSON.
6. Fuzz/property tests for parsers (bundle, Rekor bodies, CMS/TSTInfo), then a
   security review before announcing.
7. appitool integration: replace `gh attestation verify --bundle` in
   `self-update` (fetch bundles from the attestations API, verify with the
   provenance policy above, check `predicateType`).

## Decisions

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
- TUF cache paths must stay portable when `SigstoreTUF` lands (sigstore-go
  uses `filepath.Join`).
- Conformance CI is pinned to sigstore-conformance v0.0.29 (as sigstore-go);
  verify tests only (`skip-signing`), no staging run until signing exists.
- Rekor v1 `intoto` 0.0.2 signatures decode leniently like Go (bad inner
  base64 → empty signature → "signature does not match"), not at parse time.
- RFC 3161 parsing is a hand-written SwiftASN1 walk (swift-certificates' CMS
  types are internal). Deviations from Go: DER only (pkcs7 runs `ber2der`
  first); SHA-1 digests/signatures rejected at parse rather than by x509;
  signed attributes are verified over their received encoding re-tagged as
  SET (Go re-marshals and sorts; identical for DER input); chain validation
  returns one chain (swift-certificates) instead of all.
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
  columns (`\n` inside the JSON string). Go protojson decodes it (Go's
  base64 decoder skips newlines) and then rejects the timestamp; we reject
  the bundle as malformed JSON bytes. Same verdict, different reason; the
  targeted check is covered by `intoto-tsa-timestamp-outside-cert-validity_fail`.
- `CodeSigningPolicy` (Fulcio) skips the root's EKU, but Go's
  `checkChainForKeyUsage` checks every certificate including the root
  (`TimestampingPolicy` does). Harmless for current Fulcio roots (no EKU);
  align it in a follow-up.
