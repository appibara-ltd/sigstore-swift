// Command mldsa-vectors generates ML-DSA (FIPS 204) verification test vectors
// and SHAKE known-answer tests for Tests/SigstoreMLDSATests, using Go's
// standard library crypto/mldsa and crypto/sha3 as the reference.
//
// Output is fully deterministic: keys come from fixed seeds
// (mldsa.NewPrivateKey) and signatures from PrivateKey.SignDeterministic.
// Every case's expected verdict is cross-checked against mldsa.Verify; the
// program fails if Go disagrees with the label.
//
// Optionally (-acvp), it also extracts the "pure", external-interface groups
// from NIST ACVP's ML-DSA-sigVer-FIPS204/internalProjection.json, re-checks
// each case with Go, and writes them (without private keys) as a second
// vector source.
//
// Usage (from this directory):
//
//	go run . [-out DIR] [-acvp path/to/internalProjection.json]
package main

import (
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type paramInfo struct {
	name       string
	params     mldsa.Parameters
	lambdaB    int // λ/4: length of c̃ in bytes
	gamma1Bits int // bitlen(γ1-1)+1: bits per packed z coefficient
	l, k       int
	omega      int
}

var paramSets = []paramInfo{
	{"ML-DSA-44", mldsa.MLDSA44(), 32, 18, 4, 4, 80},
	{"ML-DSA-65", mldsa.MLDSA65(), 48, 20, 5, 6, 55},
	{"ML-DSA-87", mldsa.MLDSA87(), 64, 20, 7, 8, 75},
}

type testCase struct {
	Name string `json:"name"`
	// PublicKey is omitted when it equals the group's publicKey.
	PublicKey string `json:"pk,omitempty"`
	Message   string `json:"msg"`
	Context   string `json:"ctx"`
	Signature string `json:"sig"`
	Valid     bool   `json:"valid"`
}

type group struct {
	ParameterSet string     `json:"parameterSet"`
	PublicKey    string     `json:"publicKey,omitempty"`
	Cases        []testCase `json:"cases"`
}

type vectorFile struct {
	Source string  `json:"source"`
	Groups []group `json:"groups"`
}

// deterministic pseudo-random bytes derived from a label.
func detBytes(label string, n int) []byte {
	h := sha3.NewSHAKE256()
	h.Write([]byte(label))
	out := make([]byte, n)
	h.Read(out)
	return out
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

func flipBit(b []byte, byteIdx int, bit uint) []byte {
	c := clone(b)
	c[byteIdx] ^= 1 << bit
	return c
}

func mustVerify(name string, pk *mldsa.PublicKey, msg, ctx, sig []byte, want bool) {
	err := mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: string(ctx)})
	if (err == nil) != want {
		log.Fatalf("%s: Go verdict %v (err=%v), label %v", name, err == nil, err, want)
	}
}

func generate(p paramInfo) group {
	seed := sha256.Sum256([]byte("sigstore-swift mldsa vectors " + p.name))
	sk, err := mldsa.NewPrivateKey(p.params, seed[:])
	if err != nil {
		log.Fatal(err)
	}
	pk := sk.PublicKey()
	pkBytes := pk.Bytes()
	g := group{ParameterSet: p.name, PublicKey: hex.EncodeToString(pkBytes)}

	add := func(name string, pkb, msg, ctx, sig []byte, valid bool) {
		vpk, err := mldsa.NewPublicKey(p.params, pkb)
		if err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		mustVerify(p.name+"/"+name, vpk, msg, ctx, sig, valid)
		g.Cases = append(g.Cases, testCase{name, hex.EncodeToString(pkb), hex.EncodeToString(msg),
			hex.EncodeToString(ctx), hex.EncodeToString(sig), valid})
	}
	// addRaw is for cases Go's Verify cannot be called with (bad lengths);
	// they are still checked to be rejected by Go below where possible.
	addRaw := func(name string, pkb, msg, ctx, sig []byte) {
		g.Cases = append(g.Cases, testCase{name, hex.EncodeToString(pkb), hex.EncodeToString(msg),
			hex.EncodeToString(ctx), hex.EncodeToString(sig), false})
	}
	sign := func(msg, ctx []byte) []byte {
		sig, err := sk.SignDeterministic(msg, &mldsa.Options{Context: string(ctx)})
		if err != nil {
			log.Fatal(err)
		}
		return sig
	}

	// Valid cases.
	add("empty message, empty context", pkBytes, []byte{}, []byte{}, sign(nil, nil), true)
	msg := []byte("sigstore-swift ML-DSA test message")
	ctx := []byte("sigstore")
	sigNoCtx := sign(msg, nil)
	add("message, empty context", pkBytes, msg, []byte{}, sigNoCtx, true)
	sig := sign(msg, ctx)
	add("message, context", pkBytes, msg, ctx, sig, true)
	add("empty message, context", pkBytes, []byte{}, ctx, sign(nil, ctx), true)
	long := detBytes("long message "+p.name, 1000)
	add("1000-byte message, 255-byte context", pkBytes, long, detBytes("ctx255", 255), sign(long, detBytes("ctx255", 255)), true)
	add("1-byte message, 1-byte context", pkBytes, []byte{0}, []byte{0}, sign([]byte{0}, []byte{0}), true)

	// Invalid: tampering.
	add("flipped bit in c~", pkBytes, msg, ctx, flipBit(sig, 0, 0), false)
	add("flipped bit in z", pkBytes, msg, ctx, flipBit(sig, p.lambdaB+100, 3), false)
	add("flipped bit in last c~ byte", pkBytes, msg, ctx, flipBit(sig, p.lambdaB-1, 7), false)
	add("flipped bit in message", pkBytes, flipBit(msg, 3, 1), ctx, sig, false)
	add("flipped bit in pk rho", flipBit(pkBytes, 5, 2), msg, ctx, sig, false)
	add("flipped bit in pk t1", flipBit(pkBytes, 32+200, 4), msg, ctx, sig, false)
	add("wrong context", pkBytes, msg, []byte("sigstorf"), sig, false)
	add("context given, signed without", pkBytes, msg, ctx, sigNoCtx, false)
	add("context missing, signed with", pkBytes, msg, []byte{}, sig, false)

	// Invalid: lengths.
	for _, s := range [][]byte{sig[:len(sig)-1], append(clone(sig), 0)} {
		if mldsa.Verify(pk, msg, s, &mldsa.Options{Context: string(ctx)}) == nil {
			log.Fatal("bad-length signature accepted by Go")
		}
	}
	addRaw("truncated signature", pkBytes, msg, ctx, sig[:len(sig)-1])
	addRaw("extended signature", pkBytes, msg, ctx, append(clone(sig), 0))
	addRaw("empty signature", pkBytes, msg, ctx, []byte{})

	// Invalid: hint section (last ω+k bytes) malformations, FIPS 204 Alg. 21.
	hOff := len(sig) - (p.omega + p.k)
	counts := sig[hOff+p.omega:]
	total := int(counts[p.k-1])
	{
		s := clone(sig)
		s[hOff+p.omega] = byte(p.omega + 1) // first count > ω
		add("hint count exceeds omega", pkBytes, msg, ctx, s, false)
	}
	{
		// Make the cumulative counts decrease between polynomials 0 and 1.
		s := clone(sig)
		if counts[0] > 0 {
			s[hOff+p.omega+1] = counts[0] - 1
		} else {
			s[hOff+p.omega], s[hOff+p.omega+1] = 1, 0
		}
		add("hint counts decrease", pkBytes, msg, ctx, s, false)
	}
	{
		// Duplicate index within the first polynomial that has ≥ 2 hints.
		s := clone(sig)
		start, done := 0, false
		for i := 0; i < p.k && !done; i++ {
			end := int(counts[i])
			if end-start >= 2 {
				s[hOff+start+1] = s[hOff+start]
				done = true
			}
			start = end
		}
		if !done {
			log.Fatalf("%s: no polynomial with two hints", p.name)
		}
		add("hint indices not strictly increasing", pkBytes, msg, ctx, s, false)
	}
	if total < p.omega {
		s := clone(sig)
		s[hOff+p.omega-1] = 1
		add("hint padding non-zero", pkBytes, msg, ctx, s, false)
	} else {
		log.Fatalf("%s: hint section full, cannot test padding", p.name)
	}

	// Invalid: z coefficient out of range (FIPS 204 Alg. 8 step 13).
	// Packed values are γ1 − z (Alg. 19), so an all-zero field decodes to
	// z = γ1 and an all-ones field to z = −γ1 + 1; both have |z| ≥ γ1 − β.
	zOff := p.lambdaB
	{
		s := clone(sig)
		s[zOff], s[zOff+1] = 0, 0
		s[zOff+2] &^= byte(1<<(p.gamma1Bits-16) - 1)
		add("z coefficient equals gamma1", pkBytes, msg, ctx, s, false)
	}
	{
		s := clone(sig)
		s[zOff], s[zOff+1] = 0xff, 0xff
		s[zOff+2] |= byte(1<<(p.gamma1Bits-16) - 1)
		add("z coefficient equals -gamma1+1", pkBytes, msg, ctx, s, false)
	}
	return g
}

type shakeCase struct {
	Function string `json:"function"`
	Input    string `json:"input"`
	Output   string `json:"output"`
}

func shakeVectors() []shakeCase {
	var out []shakeCase
	for _, inLen := range []int{0, 1, 3, 135, 136, 137, 167, 168, 169, 500} {
		in := detBytes(fmt.Sprintf("shake input %d", inLen), inLen)
		for _, outLen := range []int{32, 200, 1000} {
			for _, fn := range []string{"SHAKE128", "SHAKE256"} {
				var h *sha3.SHAKE
				if fn == "SHAKE128" {
					h = sha3.NewSHAKE128()
				} else {
					h = sha3.NewSHAKE256()
				}
				h.Write(in)
				o := make([]byte, outLen)
				h.Read(o)
				out = append(out, shakeCase{fn, hex.EncodeToString(in), hex.EncodeToString(o)})
			}
		}
	}
	return out
}

type acvpFile struct {
	TestGroups []struct {
		TgID               int    `json:"tgId"`
		ParameterSet       string `json:"parameterSet"`
		SignatureInterface string `json:"signatureInterface"`
		PreHash            string `json:"preHash"`
		ExternalMu         bool   `json:"externalMu"`
		Tests              []struct {
			TcID       int    `json:"tcId"`
			TestPassed bool   `json:"testPassed"`
			Reason     string `json:"reason"`
			PK         string `json:"pk"`
			Message    string `json:"message"`
			Context    string `json:"context"`
			Signature  string `json:"signature"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func acvpVectors(path string) vectorFile {
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var f acvpFile
	if err := json.Unmarshal(raw, &f); err != nil {
		log.Fatal(err)
	}
	vf := vectorFile{Source: "NIST ACVP-Server gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json, " +
		"groups with signatureInterface=external, preHash=pure; cross-checked with Go crypto/mldsa"}
	for _, tg := range f.TestGroups {
		if tg.SignatureInterface != "external" || tg.PreHash != "pure" || tg.ExternalMu {
			continue
		}
		var p *paramInfo
		for i := range paramSets {
			if paramSets[i].name == tg.ParameterSet {
				p = &paramSets[i]
			}
		}
		if p == nil {
			log.Fatalf("unknown parameter set %s", tg.ParameterSet)
		}
		g := group{ParameterSet: tg.ParameterSet}
		for _, tc := range tg.Tests {
			dec := func(s string) []byte {
				b, err := hex.DecodeString(s)
				if err != nil {
					log.Fatal(err)
				}
				return b
			}
			pkb, msg, ctx, sig := dec(tc.PK), dec(tc.Message), dec(tc.Context), dec(tc.Signature)
			pk, err := mldsa.NewPublicKey(p.params, pkb)
			if err != nil {
				log.Fatal(err)
			}
			name := fmt.Sprintf("tcId %d: %s", tc.TcID, tc.Reason)
			mustVerify(name, pk, msg, ctx, sig, tc.TestPassed)
			g.Cases = append(g.Cases, testCase{name, hex.EncodeToString(pkb), hex.EncodeToString(msg),
				hex.EncodeToString(ctx), hex.EncodeToString(sig), tc.TestPassed})
		}
		vf.Groups = append(vf.Groups, g)
	}
	return vf
}

func writeJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Println("wrote", path)
}

func main() {
	out := flag.String("out", "../../Tests/SigstoreMLDSATests/Vectors", "output directory")
	acvp := flag.String("acvp", "", "optional path to ACVP ML-DSA-sigVer-FIPS204 internalProjection.json")
	flag.Parse()

	vf := vectorFile{Source: "scripts/mldsa-vectors (Go crypto/mldsa, deterministic keys and signatures)"}
	for _, p := range paramSets {
		vf.Groups = append(vf.Groups, generate(p))
	}
	for gi := range vf.Groups {
		for ci := range vf.Groups[gi].Cases {
			if vf.Groups[gi].Cases[ci].PublicKey == vf.Groups[gi].PublicKey {
				vf.Groups[gi].Cases[ci].PublicKey = ""
			}
		}
	}
	writeJSON(filepath.Join(*out, "go-mldsa.json"), vf)
	writeJSON(filepath.Join(*out, "go-shake.json"), shakeVectors())
	if *acvp != "" {
		writeJSON(filepath.Join(*out, "acvp-mldsa-sigver-pure.json"), acvpVectors(*acvp))
	}
}
