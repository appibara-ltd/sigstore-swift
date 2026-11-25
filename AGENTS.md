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
- Generated code in `Sources/SigstoreProtobufSpecs/Generated` is never edited
  by hand; change `scripts/generate-protos.sh` and regenerate.

## Allowed without asking

- `swift build`, `swift test`, `swift package resolve`
- `scripts/generate-protos.sh`
- read-only `git` commands (`status`, `diff`, `log`, `show`, `blame`)
- the sigstore-conformance harness, once added

## Requires the user's request

- `git commit`, `git push`, tags, releases, PRs.
- Commit messages: AI agents add a `Co-Authored-By:` trailer for
  themselves. Propose commit messages to the user as a markdown code block
  only.

## Layout

| Module | sigstore-go |
| --- | --- |
| `SigstoreProtobufSpecs` | `github.com/sigstore/protobuf-specs/gen/pb-go` (generated) |
| `SigstoreBundle` | `pkg/bundle` |
| `SigstoreRoot` | `pkg/root` |
| `SigstoreTLog` | `pkg/tlog` |
| `SigstoreTUF` | `pkg/tuf` (stub) |
| `SigstoreVerify` | `pkg/verify` |
| `SigstoreFulcio` | `pkg/fulcio/certificate` |
| `SigstoreCommon` | helpers standing in for `sigstore/sigstore` signature verifiers etc. |
| `Sigstore` | umbrella, re-exports all of the above |
