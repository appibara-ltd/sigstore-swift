# Security policy

sigstore-swift verifies Sigstore signatures, so a bug that makes it accept
something sigstore-go would reject is a security issue.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: on the repository's
**Security** tab, choose **Report a vulnerability**
(<https://github.com/appibara-ltd/sigstore-swift/security/advisories/new>).
Do not open a public issue.

Include the affected version or commit, steps to reproduce (for example a
bundle, trusted root and verifier options that are wrongly accepted), and the
behaviour you expected, ideally with what sigstore-go does on the same input.

sigstore-swift is not a Sigstore project. Vulnerabilities in Sigstore itself
(sigstore-go, Fulcio, Rekor, the public-good instance, the specifications) go
to the Sigstore Security Response Committee at security@sigstore.dev, as
described in <https://github.com/sigstore/.github/blob/main/SECURITY.md>.

## Supported versions

sigstore-swift is in early development (0.x) and has not had a security
review. Fixes are released only in the latest minor version.

| Version | Supported |
| --- | --- |
| 0.3.x | Yes |
| < 0.3 | No |
