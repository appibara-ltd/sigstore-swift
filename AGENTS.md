# AGENTS.md

Rules for AI agents (and humans) working on sigstore-swift.

## Project

sigstore-swift is a general-purpose Swift port of the verification side of
[sigstore-go](https://github.com/sigstore/sigstore-go) (reference: v1.4.1).
It mirrors sigstore-go; it is not an app-specific tool. Signing comes later.

Read `PROGRESS.md` first: it holds status, next steps and decisions. Update it
at the end of every session.

## Ground rules

- Keep responses concise.
- Ground every behavioural claim in a source: sigstore-go (cite package/file),
  the Sigstore client spec, protobuf-specs, the relevant RFC (5280, 6962/9162,
  3161, 8785), or sigstore-conformance. If something is unspecified, say so
  and record it under "Spec questions" in `PROGRESS.md` instead of guessing.
- Mirror sigstore-go names, translated to Swift:
  - `(T, error)` → `throws`; network calls → `async`.
  - Functional options → option values with static factories
    (`.withTransparencyLog(threshold: 1)`).
  - `NewX(...)` → `X.init(...)`; package-level funcs → module-level funcs.
  - Infallible Go getters → properties; fallible ones stay `throws` methods.
  - Deviations are listed in `PROGRESS.md` → Decisions.
- Security-sensitive code: never weaken a check to make a test pass. Every new
  check needs a negative test.
- Generated code in `Sources/SigstoreProtobufSpecs/Generated` and
  `Sources/SigstoreTUF/EmbeddedRoots.swift` is never edited by hand; change
  `scripts/generate-protos.sh` / `scripts/embed-tuf-roots.sh` (or their
  inputs) and regenerate.
- Library targets have no SwiftPM resource bundles (they make swift-build
  on Windows flaky); embed data via a generator script.

## Allowed without asking

- `swift build`, `swift test`, `swift package resolve`
- `scripts/generate-protos.sh`, `scripts/embed-tuf-roots.sh`
- read-only `git` commands (`status`, `diff`, `log`, `show`, `blame`)
- the sigstore-conformance harness, once added

## Requires the user's request

- `git commit`, `git push`, tags, releases, PRs.
- Commit messages follow sigstore-go's `CONTRIBUTING.md` (Chris Beams'
  "How to Write a Git Commit Message"), not Conventional Commits:
  - imperative subject of about 50 characters, no `feat:`/`fix:` type; an
    area prefix is fine (`CI: …`, `verify: …`);
  - blank line, then a body wrapped at about 72 columns explaining why;
  - issue references at the bottom (`Resolves: #123`).
- Every commit is signed off (DCO): commit with `git commit -s`, which adds
  `Signed-off-by:` for the committer. AI agents also add a
  `Co-Authored-By:` trailer for themselves.
- Propose commit messages to the user as a markdown code block only.

## Layout

| Module | sigstore-go |
| --- | --- |
| `SigstoreProtobufSpecs` | `github.com/sigstore/protobuf-specs/gen/pb-go` (generated) |
| `SigstoreBundle` | `pkg/bundle` |
| `SigstoreRoot` | `pkg/root` |
| `SigstoreTLog` | `pkg/tlog` |
| `SigstoreTUF` | `pkg/tuf` (+ go-tuf v2 `metadata`) |
| `SigstoreVerify` | `pkg/verify` |
| `SigstoreFulcio` | `pkg/fulcio/certificate` |
| `SigstoreMLDSA` | Go `crypto/mldsa` (verify only, pure Swift) |
| `SigstoreCryptoExtras` | Go `crypto/ed25519` Ed25519ph and `crypto/rsa` over a digest (verify only, pure Swift) |
| `SigstoreCommon` | helpers standing in for `sigstore/sigstore` signature verifiers etc. |
| `Sigstore` | umbrella, re-exports all of the above |
