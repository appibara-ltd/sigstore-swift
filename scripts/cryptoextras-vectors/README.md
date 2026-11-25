# cryptoextras-vectors

Generates the Ed25519ph and RSA (PKCS#1 v1.5 / PSS over a digest) JSON test
vectors in `Tests/SigstoreCryptoExtrasTests/Vectors/` from Go's
`crypto/ed25519` and `crypto/rsa` (Go 1.27). Run from the repository root:

    (cd scripts/cryptoextras-vectors && go run . -out ../../Tests/SigstoreCryptoExtrasTests/Vectors)

Each vector records Go's verdict (`goValid`) and the verdict sigstore-swift
must give (`valid`); the generator aborts if they differ without a `note`
explaining the deviation. RSA keys and PSS salts are random, so RSA output
changes on every run; Ed25519ph output is deterministic.
