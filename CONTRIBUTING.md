# Contributing to sigstore-swift

Thanks for your interest. Bug reports, feature requests and pull requests
are welcome.

## Reporting bugs and requesting features

Open a [GitHub issue](https://github.com/appibara-ltd/sigstore-swift/issues).
For a verification bug, include the bundle, trusted root and verifier
options if you can, and what sigstore-go does with the same input.

Report security vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md), not in a public issue.

## What the project is

sigstore-swift is a Swift port of the verification side of
[sigstore-go](https://github.com/sigstore/sigstore-go) (reference: v1.4.1).
It mirrors sigstore-go's behaviour and names; signing comes later.
[PROGRESS.md](PROGRESS.md) holds the status, next steps and the decisions
behind every deviation from sigstore-go. For a larger change, open an issue
first so we can agree on the approach.

## Building and testing

Requires Swift 6.4 (macOS 26 or later, Linux or Windows).

```bash
swift build
swift test
```

Other checks CI runs:

- `scripts/run-conformance.sh`: the
  [sigstore-conformance](https://github.com/sigstore/sigstore-conformance)
  verify tests (needs `uv`).
- `scripts/fuzz.sh`: libFuzzer over the parsers (Linux).
- Embedded data must match its sources: run `scripts/embed-tuf-roots.sh`
  and `scripts/embed-test-data.sh`, then check `git diff`.

## Rules for changes

- **Ground behaviour in a source.** Cite sigstore-go (package and file), the
  Sigstore client spec, protobuf-specs, the relevant RFC (5280, 6962/9162,
  3161, 8785) or sigstore-conformance. If something is unspecified, say so
  in the pull request; it is recorded under "Spec questions" in
  PROGRESS.md.
- **Mirror sigstore-go names**, translated to Swift: `(T, error)` becomes
  `throws`, network calls are `async`, functional options become option
  values with static factories, `NewX(...)` becomes `X.init(...)`. See
  [AGENTS.md](AGENTS.md) for the full list.
- **Security-sensitive code:** never weaken a check to make a test pass.
  Every new check needs a negative test, a test that the check rejects bad
  input.
- **Tests:** new behaviour comes with tests (Swift Testing, in `Tests/`).
- **Generated code is never edited by hand:**
  `Sources/SigstoreProtobufSpecs/Generated`,
  `Sources/SigstoreTUF/EmbeddedRoots.swift` and
  `Tests/*/EmbeddedTestData.swift`. Change the generator script or its
  inputs and regenerate. After changing a file under
  `Tests/SigstoreTests/Fixtures` or a test target's `Vectors` directory, run
  `scripts/embed-test-data.sh`.
- **No SwiftPM resource bundles** in any target; embed data with a
  generator script.

## Commits and pull requests

- Commit messages follow sigstore-go's
  [CONTRIBUTING.md](https://github.com/sigstore/sigstore-go/blob/main/CONTRIBUTING.md)
  ([How to Write a Git Commit Message](https://cbea.ms/git-commit/)), not
  Conventional Commits: an imperative subject of about 50 characters (an
  area prefix such as `verify: ` is fine), a blank line, then a body
  wrapped at about 72 columns explaining why. Put issue references at the
  bottom (`Resolves: #123`).
- **Sign off every commit** ([Developer Certificate of Origin](https://developercertificate.org)):
  `git commit -s` adds the `Signed-off-by:` line.
- Open the pull request against `main`. CI (build and tests on macOS, Linux
  and Windows, conformance, fuzzing, CodeQL and dependency review) must
  pass.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
