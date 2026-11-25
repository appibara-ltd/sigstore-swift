// Generates ML-DSA integration fixtures for sigstore-swift with Go 1.27's
// crypto/mldsa and crypto/x509 (deterministic seeds):
//   - PKIX SubjectPublicKeyInfo for ML-DSA-44/65/87 and a pure signature
//     (empty context) over a fixed message, as sigstore's MLDSAVerifier checks;
//   - a C2SP checkpoint signed with ML-DSA-44 in rekor-tiles' cosignature/v1
//     note format (8-byte timestamp || signature over the subtree/v1 message).
//
//	go run . ../../Tests/SigstoreTests/Fixtures/mldsa.json
package main

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
)

type keyCase struct {
	Params    string `json:"params"`
	SPKI      string `json:"spki"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

func seed(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b + byte(i)
	}
	return s
}

func main() {
	out := map[string]any{}
	var keys []keyCase
	msg := []byte("sigstore-swift ML-DSA integration message")
	for i, p := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		sk, err := mldsa.NewPrivateKey(p, seed(byte(i*40)))
		check(err)
		spki, err := x509.MarshalPKIXPublicKey(sk.PublicKey())
		check(err)
		sig, err := sk.SignDeterministic(msg, nil)
		check(err)
		check(mldsa.Verify(sk.PublicKey(), msg, sig, nil))
		keys = append(keys, keyCase{p.String(), b64(spki), b64(msg), b64(sig)})
	}
	out["keys"] = keys

	// Checkpoint signed by an ML-DSA-44 log key (rekor-tiles note.go).
	origin := "log.example.dev"
	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed(200))
	check(err)
	spki, err := x509.MarshalPKIXPublicKey(sk.PublicKey())
	check(err)
	root := sha256.Sum256([]byte("root"))
	body := fmt.Sprintf("%s\n42\n%s\n", origin, base64.StdEncoding.EncodeToString(root[:]))
	ts := uint64(1764000000)
	var m []byte
	m = append(m, []byte("subtree/v1\n\x00")...)
	m = append(m, byte(len(origin)))
	m = append(m, origin...)
	m = binary.BigEndian.AppendUint64(m, ts)
	m = append(m, byte(len(origin)))
	m = append(m, origin...)
	m = binary.BigEndian.AppendUint64(m, 0)
	m = binary.BigEndian.AppendUint64(m, 42)
	m = append(m, root[:]...)
	sig, err := sk.SignDeterministic(m, nil)
	check(err)
	h := sha256.New()
	h.Write([]byte(origin + "\n"))
	h.Write([]byte{6})
	h.Write(sk.PublicKey().Bytes())
	keyHash := h.Sum(nil)[:4]
	blob := append(append(append([]byte{}, keyHash...), binary.BigEndian.AppendUint64(nil, ts)...), sig...)
	out["checkpoint"] = map[string]string{
		"origin": origin,
		"spki":   b64(spki),
		"note":   body + "\n— " + origin + " " + b64(blob) + "\n",
	}
	j, err := json.MarshalIndent(out, "", "  ")
	check(err)
	check(os.WriteFile(os.Args[1], append(j, '\n'), 0o644))
	fmt.Println("wrote", os.Args[1])
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func check(err error) {
	if err != nil {
		panic(err)
	}
}
