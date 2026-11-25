# PROGRESS

Continuity log. Update at the end of every session.

## Status (2026-11-25, session 1, part 2)

**v0.1 is on `main` (9c0941d). Conformance harness added (uncommitted).**
`swift build` / `swift test` pass on macOS (Swift 6.4, 29 tests). Linux is
first exercised by `.github/workflows/ci.yml` (not yet run).

### Conformance (sigstore-conformance, verify tests only)

Run locally with `scripts/run-conformance.sh` (needs `uv`); CI runs the
`conformance` job in `.github/workflows/ci.yml`. Client:
`Sources/sigstore-swift-conformance` (port of sigstore-go
`test/conformance/main.go`, verify-bundle only).

| Suite ref | Passed | Expected failures | Unexpected | CPython release bundles |
| --- | --- | --- | --- | --- |
| v0.0.29 (CI pin) | 109 | 26 | 0 | 81/81 |
| main e275ffb | 113 | 28 | 0 | 81/81 |

Expected failures (`.github/conformance-xfail.txt`, strict) are all happy
paths needing Rekor v2 or RFC 3161. Every `_fail` case is rejected, but
these are rejected only because Rekor v2 is unsupported, not for the defect
they target, so they prove nothing yet: all `rekor2-*_fail` and
`trust-root-tlog-missing-validity-start_fail`. Same for
`intoto-tsa-timestamp-outside-cert-validity_fail` (rejected because RFC 3161
is unimplemented). Re-check their rejection reasons when those features land
(`scripts/run-conformance.sh -rA`, or run the client on the asset dir).

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

### Stubbed / not implemented

- RFC 3161 timestamps (`verifySignedTimestamp` reports every token as
  unverified; `.withSignedTimestamps` therefore always fails).
- Rekor v2 entries / signed-note checkpoints (throws "not supported yet").
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
  GitHub-instance TSA token only, no tlog (needs RFC 3161 + GitHub trusted root).

`Sources/SigstoreRoot/Resources/trusted_root.json` (also copied to test
fixtures) is `sigstore/root-signing` `targets/trusted_root.json` @ main,
sha256 `6494e21e…0b66`, fetched 2026-11-25.

## Next steps (toward conformance)

1. **First CI run**: push and fix whatever Linux / the GitHub action reveal
   (Linux build is untested; the conformance job builds with
   `--static-swift-stdlib` in `swift:6.4-noble` and runs on the host).
2. **RFC 3161 / TSA** (sigstore-go `pkg/verify/tsa.go`, `root/timestamping_authority.go`):
   parse TimeStampResp/TSTInfo (CMS SignedData) with swift-asn1, verify the
   signer chain to the TSA root at genTime, message imprint = hash of the
   signature bytes, TSA `validFor`. Unblocks `release.sigstore.json` (also
   needs GitHub's trusted root, which `gh` fetches via TUF from
   `tuf-repo.github.com`).
3. **Rekor v2**: `hashedrekord` 0.0.2 / `dsse` 0.0.2 bodies, C2SP signed-note
   checkpoints (origin from `baseUrl` host, Ed25519/ECDSA note key IDs),
   entry hash reconstruction (`reconstructV2EntryHash`), inclusion proof
   required.
4. **TUF client** (`pkg/tuf`): root rotation, timestamp/snapshot/targets,
   delegations, consistent snapshots, on-disk cache; embedded root.json for
   the public-good and GitHub repos; `TrustedRoot.fetch()` / live refresh.
5. Prehashed signature verification (message signatures with digest only),
   Ed25519ph, ML-DSA, `SigningConfig`, `VerificationResult` JSON.
6. Linux CI (swift:6.4 image), fuzz/property tests for parsers, then a
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
- Conformance CI is pinned to sigstore-conformance v0.0.29 (as sigstore-go);
  verify tests only (`skip-signing`), no staging run until signing exists.
- Rekor v1 `intoto` 0.0.2 signatures decode leniently like Go (bad inner
  base64 → empty signature → "signature does not match"), not at parse time.

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
