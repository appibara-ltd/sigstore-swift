# mldsa-vectors

Generates the ML-DSA (FIPS 204) and SHAKE test vectors in
`Tests/SigstoreMLDSATests/Vectors/` from Go's standard library
(`crypto/mldsa`, `crypto/sha3`; Go 1.26+). Output is deterministic.

Run from this directory:

    go run . -acvp /path/to/internalProjection.json

`-acvp` is optional: pass NIST's
[ACVP-Server `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-sigVer-FIPS204)
to regenerate `acvp-mldsa-sigver-pure.json` (pure, external-interface groups
only, re-checked against Go).
