// Command cryptoextras-vectors generates the JSON test vectors used by
// Tests/SigstoreCryptoExtrasTests. Every vector carries the result Go's
// crypto/ed25519 or crypto/rsa gives for it ("goValid"), and the result
// sigstore-swift must give ("valid"). The two only differ where the Swift
// implementation deliberately deviates; such vectors carry a "note".
//
// Run from the repository root:
//
//	(cd scripts/cryptoextras-vectors && go run . -out ../../Tests/SigstoreCryptoExtrasTests/Vectors)
//
// RSA keys and PSS salts are random, so each run produces different (but
// equivalent) RSA vectors. Ed25519ph vectors are deterministic.
package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func unhex(s string) []byte { return must(hex.DecodeString(strings.ReplaceAll(s, " ", ""))) }

func flip(b []byte, bit int) []byte {
	c := bytes.Clone(b)
	c[bit/8] ^= 1 << (bit % 8)
	return c
}

func writeJSON(dir, name string, v any) {
	data := must(json.MarshalIndent(v, "", "  "))
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		panic(err)
	}
}

// ---------------------------------------------------------------- Ed25519ph

type edCase struct {
	Name      string  `json:"name"`
	PublicKey string  `json:"publicKey"`
	Message   *string `json:"message,omitempty"`
	Prehash   string  `json:"prehash"`
	Context   string  `json:"context"`
	Signature string  `json:"signature"`
	Valid     bool    `json:"valid"`
	GoValid   bool    `json:"goValid"`
	Note      string  `json:"note,omitempty"`
}

type edFile struct {
	Source string   `json:"source"`
	Tests  []edCase `json:"tests"`
}

func goVerifyPH(pub, prehash, ctx, sig []byte) bool {
	err := ed25519.VerifyWithOptions(pub, prehash, sig, &ed25519.Options{Hash: crypto.SHA512, Context: string(ctx)})
	return err == nil
}

// addEd records a case; valid is the expected sigstore-swift result. Unless a
// note explains a deliberate deviation, Go must agree.
func addEd(cases *[]edCase, name string, pub, msg, prehash, ctx, sig []byte, valid bool, note string) {
	goValid := goVerifyPH(pub, prehash, ctx, sig)
	if goValid != valid && note == "" {
		panic(fmt.Sprintf("ed25519ph %q: Go says %v, expected %v", name, goValid, valid))
	}
	c := edCase{Name: name, PublicKey: hx(pub), Prehash: hx(prehash), Context: hx(ctx),
		Signature: hx(sig), Valid: valid, GoValid: goValid, Note: note}
	if msg != nil {
		m := hx(msg)
		c.Message = &m
	}
	*cases = append(*cases, c)
}

var edL *big.Int

func init() {
	// L = 2^252 + 27742317777372353535851937790883648493
	l := new(big.Int).Lsh(big.NewInt(1), 252)
	l.Add(l, must2(new(big.Int).SetString("27742317777372353535851937790883648493", 10)))
	edL = l
}

func must2(v *big.Int, ok bool) *big.Int {
	if !ok {
		panic("bad big int")
	}
	return v
}

func leToInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

func intToLE32(x *big.Int) []byte {
	be := x.FillBytes(make([]byte, 32))
	out := make([]byte, 32)
	for i := range be {
		out[31-i] = be[i]
	}
	return out
}

// hramPH computes k = SHA-512(dom2(1, ctx) || R || A || PH(M)) mod L (RFC 8032 §5.1.7).
func hramPH(r, a, prehash, ctx []byte) *big.Int {
	h := sha512.New()
	h.Write([]byte("SigEd25519 no Ed25519 collisions"))
	h.Write([]byte{1, byte(len(ctx))})
	h.Write(ctx)
	h.Write(r)
	h.Write(a)
	h.Write(prehash)
	return new(big.Int).Mod(leToInt(h.Sum(nil)), edL)
}

func genEd25519ph(dir string) {
	var cases []edCase

	// RFC 8032 §7.3, test "abc" (Ed25519ph), verbatim.
	rfcSecret := unhex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
	rfcPublic := unhex("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
	rfcMsg := unhex("616263")
	rfcSig := unhex("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41" +
		"31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")
	rfcKey := ed25519.NewKeyFromSeed(rfcSecret)
	if !bytes.Equal(rfcKey.Public().(ed25519.PublicKey), rfcPublic) {
		panic("RFC 8032 §7.3 public key mismatch")
	}
	rfcPH := sha512.Sum512(rfcMsg)
	if !bytes.Equal(must(rfcKey.Sign(nil, rfcPH[:], &ed25519.Options{Hash: crypto.SHA512})), rfcSig) {
		panic("RFC 8032 §7.3 signature mismatch")
	}
	addEd(&cases, "RFC 8032 §7.3 Ed25519ph abc", rfcPublic, rfcMsg, rfcPH[:], nil, rfcSig, true, "")

	seed := sha256.Sum256([]byte("sigstore-swift ed25519ph vectors"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := []byte(priv.Public().(ed25519.PublicKey))

	long := bytes.Repeat([]byte("sigstore-swift long message. "), 150) // 4350 bytes
	msgs := []struct {
		name string
		msg  []byte
	}{{"empty message", []byte{}}, {"short message", []byte("hello, sigstore")}, {"long message", long}}
	ctxs := []struct {
		name string
		ctx  []byte
	}{{"empty context", nil}, {"context", []byte("sigstore context")}, {"255-byte context", bytes.Repeat([]byte{0xa5}, 255)}}

	for _, m := range msgs {
		for _, c := range ctxs {
			ph := sha512.Sum512(m.msg)
			sig := must(priv.Sign(nil, ph[:], &ed25519.Options{Hash: crypto.SHA512, Context: string(c.ctx)}))
			addEd(&cases, "valid, "+m.name+", "+c.name, pub, m.msg, ph[:], c.ctx, sig, true, "")
		}
	}

	msg := []byte("tamper me")
	ph := sha512.Sum512(msg)
	ctx := []byte("ctx")
	sig := must(priv.Sign(nil, ph[:], &ed25519.Options{Hash: crypto.SHA512, Context: string(ctx)}))
	addEd(&cases, "baseline for tampering", pub, msg, ph[:], ctx, sig, true, "")
	for _, bit := range []int{0, 7, 100, 255, 256, 300, 503} {
		addEd(&cases, fmt.Sprintf("flipped signature bit %d", bit), pub, nil, ph[:], ctx, flip(sig, bit), false, "")
	}
	for _, bit := range []int{0, 200, 511} {
		addEd(&cases, fmt.Sprintf("flipped prehash bit %d", bit), pub, nil, flip(ph[:], bit), ctx, sig, false, "")
	}
	for _, bit := range []int{0, 1, 128, 254, 255} {
		addEd(&cases, fmt.Sprintf("flipped public key bit %d", bit), flip(pub, bit), nil, ph[:], ctx, sig, false, "")
	}
	addEd(&cases, "wrong context", pub, nil, ph[:], []byte("ctx2"), sig, false, "")
	addEd(&cases, "empty context instead of non-empty", pub, nil, ph[:], nil, sig, false, "")
	pureSig := ed25519.Sign(priv, ph[:])
	addEd(&cases, "pure Ed25519 signature over the prehash", pub, nil, ph[:], nil, pureSig, false, "")
	ctxSig := must(priv.Sign(nil, ph[:], &ed25519.Options{Context: string(ctx)}))
	addEd(&cases, "Ed25519ctx signature over the prehash", pub, nil, ph[:], ctx, ctxSig, false, "")

	// S + L still fits in 253 bits, satisfies the verification equation mod L,
	// and must be rejected because S >= L (RFC 8032 §5.1.7 step 1).
	s := leToInt(sig[32:])
	sPlusL := new(big.Int).Add(s, edL)
	if sPlusL.BitLen() <= 253 {
		malleable := append(bytes.Clone(sig[:32]), intToLE32(sPlusL)...)
		addEd(&cases, "S + L (S >= L, malleability)", pub, nil, ph[:], ctx, malleable, false, "")
	} else {
		panic("S + L does not fit; change the tampered message")
	}
	addEd(&cases, "S = L", pub, nil, ph[:], ctx, append(bytes.Clone(sig[:32]), intToLE32(edL)...), false, "")
	highS := bytes.Clone(sig)
	highS[63] |= 0xe0
	addEd(&cases, "S with top three bits set", pub, nil, ph[:], ctx, highS, false, "")
	addEd(&cases, "all-zero signature", pub, nil, ph[:], ctx, make([]byte, 64), false, "")

	// Small-order and non-canonical encodings. Identity point: y = 1, x = 0.
	identity := make([]byte, 32)
	identity[0] = 1
	identityNeg := bytes.Clone(identity) // x = 0 with the sign bit set
	identityNeg[31] |= 0x80
	// y = p + 1 (non-canonical encoding of the identity).
	pPlus1 := unhex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	// y = p - 1: the point (0, -1) of order 2.
	order2 := unhex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	zeroS := make([]byte, 32)
	idSig := append(bytes.Clone(identity), zeroS...) // R = O, S = 0

	addEd(&cases, "identity public key, R = O, S = 0", identity, nil, ph[:], ctx, idSig, true,
		"")
	addEd(&cases, "non-canonical public key (y = p + 1)", pPlus1, nil, ph[:], ctx, idSig, false,
		"deviation: Go's edwards25519 accepts y >= p; RFC 8032 §5.1.3 step 1 rejects it")
	addEd(&cases, "non-canonical public key (x = 0, sign bit set)", identityNeg, nil, ph[:], ctx, idSig, false,
		"deviation: Go's edwards25519 accepts x = 0 with x_0 = 1; RFC 8032 §5.1.3 step 4 rejects it")
	addEd(&cases, "non-canonical R (y = p + 1)", identity, nil, ph[:], ctx, append(bytes.Clone(pPlus1), zeroS...), false, "")
	addEd(&cases, "non-canonical R (x = 0, sign bit set)", identity, nil, ph[:], ctx, append(bytes.Clone(identityNeg), zeroS...), false, "")

	// Order-2 public key T = (0, -1) with R = O, S = 0: [S]B = R + [k]T
	// holds iff k is even. The cofactored equation ([8][S]B = [8]R + [8][k]A)
	// would accept odd k too; Go (cofactorless) does not.
	var evenDone, oddDone bool
	for i := 0; !(evenDone && oddDone); i++ {
		m := []byte(fmt.Sprintf("order-2 key %d", i))
		p := sha512.Sum512(m)
		odd := hramPH(identity, order2, p[:], nil).Bit(0) == 1
		if odd && !oddDone {
			oddDone = true
			addEd(&cases, "order-2 public key, k odd (cofactored would accept)", order2, m, p[:], nil, idSig, false, "")
		} else if !odd && !evenDone {
			evenDone = true
			addEd(&cases, "order-2 public key, k even", order2, m, p[:], nil, idSig, true, "")
		}
	}

	// A y-coordinate that does not decode to a curve point.
	for y := 2; ; y++ {
		bad := make([]byte, 32)
		bad[0] = byte(y)
		err := ed25519.VerifyWithOptions(bad, ph[:], sig, &ed25519.Options{Hash: crypto.SHA512, Context: string(ctx)})
		if err != nil && strings.Contains(err.Error(), "bad public key") {
			addEd(&cases, fmt.Sprintf("public key not on the curve (y = %d)", y), bad, nil, ph[:], ctx, sig, false, "")
			break
		}
	}
	// R not on the curve.
	for y := 2; ; y++ {
		bad := make([]byte, 32)
		bad[0] = byte(y)
		if err := ed25519.VerifyWithOptions(bad, ph[:], sig, &ed25519.Options{Hash: crypto.SHA512}); err != nil &&
			strings.Contains(err.Error(), "bad public key") {
			addEd(&cases, fmt.Sprintf("R not on the curve (y = %d)", y), pub, nil, ph[:], ctx,
				append(bad, sig[32:]...), false, "")
			break
		}
	}

	writeJSON(dir, "ed25519ph.json", edFile{
		Source: "scripts/cryptoextras-vectors (Go crypto/ed25519 VerifyWithOptions, Hash: SHA512); RFC 8032 §7.3",
		Tests:  cases,
	})
	fmt.Printf("ed25519ph.json: %d vectors\n", len(cases))
}

// ---------------------------------------------------------------------- RSA

type rsaKey struct {
	Name  string `json:"name"`
	Bits  int    `json:"bits"`
	N     string `json:"n"`
	E     int    `json:"e"`
	PKCS1 string `json:"pkcs1"`
}

type rsaCase struct {
	Name       string `json:"name"`
	Key        string `json:"key"`
	Scheme     string `json:"scheme"` // "pkcs1v15" or "pss"
	Hash       string `json:"hash"`
	Digest     string `json:"digest"`
	Signature  string `json:"signature"`
	SaltLength *int   `json:"saltLength"` // PSS only; null = auto-detect
	Valid      bool   `json:"valid"`
	GoValid    *bool  `json:"goValid"` // null where Go's API cannot express the check
	Note       string `json:"note,omitempty"`
}

type rsaFile struct {
	Source string    `json:"source"`
	Keys   []rsaKey  `json:"keys"`
	Tests  []rsaCase `json:"tests"`
}

type hashSpec struct {
	name string
	h    crypto.Hash
	new  func() hash.Hash
}

var hashes = []hashSpec{
	{"sha256", crypto.SHA256, sha256.New},
	{"sha384", crypto.SHA384, sha512.New384},
	{"sha512", crypto.SHA512, sha512.New},
}

func digestOf(h hashSpec, msg []byte) []byte {
	x := h.new()
	x.Write(msg)
	return x.Sum(nil)
}

func ip(i int) *int { return &i }

type rsaGen struct {
	keys  []rsaKey
	cases []rsaCase
}

func (g *rsaGen) addKey(name string, pub *rsa.PublicKey) {
	g.keys = append(g.keys, rsaKey{Name: name, Bits: pub.N.BitLen(), N: hx(pub.N.Bytes()), E: pub.E,
		PKCS1: hx(x509.MarshalPKCS1PublicKey(pub))})
}

func (g *rsaGen) add(name, key string, pub *rsa.PublicKey, scheme string, h hashSpec, digest, sig []byte,
	salt *int, valid bool, note string) {
	var goValid *bool
	switch scheme {
	case "pkcs1v15":
		v := rsa.VerifyPKCS1v15(pub, h.h, digest, sig) == nil
		goValid = &v
	case "pss":
		// Go's PSSOptions.SaltLength 0 means auto-detect, so exact salt
		// length 0 is not expressible through crypto/rsa.
		if salt == nil {
			v := rsa.VerifyPSS(pub, h.h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}) == nil
			goValid = &v
		} else if *salt > 0 {
			v := rsa.VerifyPSS(pub, h.h, digest, sig, &rsa.PSSOptions{SaltLength: *salt}) == nil
			goValid = &v
		}
	default:
		panic(scheme)
	}
	if goValid != nil && *goValid != valid && note == "" {
		panic(fmt.Sprintf("rsa %q: Go says %v, expected %v", name, *goValid, valid))
	}
	g.cases = append(g.cases, rsaCase{Name: name, Key: key, Scheme: scheme, Hash: h.name, Digest: hx(digest),
		Signature: hx(sig), SaltLength: salt, Valid: valid, GoValid: goValid, Note: note})
}

// rawSign computes em^d mod n, left-padded to the modulus length.
func rawSign(priv *rsa.PrivateKey, em []byte) []byte {
	k := (priv.N.BitLen() + 7) / 8
	s := new(big.Int).Exp(new(big.Int).SetBytes(em), priv.D, priv.N)
	return s.FillBytes(make([]byte, k))
}

func mgf1XOR(out []byte, h hashSpec, seed []byte) {
	var counter [4]byte
	done := 0
	for done < len(out) {
		x := h.new()
		x.Write(seed)
		x.Write(counter[:])
		d := x.Sum(nil)
		for i := 0; i < len(d) && done < len(out); i++ {
			out[done] ^= d[i]
			done++
		}
		for i := 3; i >= 0; i-- {
			counter[i]++
			if counter[i] != 0 {
				break
			}
		}
	}
}

// pssSignSalt signs with an explicit salt (RFC 8017 §9.1.1), for salt lengths
// Go's SignPSS cannot produce (0).
func pssSignSalt(priv *rsa.PrivateKey, h hashSpec, mHash, salt []byte) []byte {
	emBits := priv.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	hLen := len(mHash)
	x := h.new()
	x.Write(make([]byte, 8))
	x.Write(mHash)
	x.Write(salt)
	hh := x.Sum(nil)
	db := make([]byte, emLen-hLen-1)
	db[emLen-len(salt)-hLen-2] = 0x01
	copy(db[len(db)-len(salt):], salt)
	mgf1XOR(db, h, hh)
	db[0] &= 0xff >> (8*emLen - emBits)
	em := append(append(db, hh...), 0xbc)
	return rawSign(priv, em)
}

// pkcs1Sign signs with a hand-built EMSA-PKCS1-v1_5 encoding, for keys Go's
// SignPKCS1v15 refuses (e = 3).
func pkcs1Sign(priv *rsa.PrivateKey, prefix, digest []byte) []byte {
	k := (priv.N.BitLen() + 7) / 8
	t := append(bytes.Clone(prefix), digest...)
	em := make([]byte, k)
	em[1] = 1
	for i := 2; i < k-len(t)-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-len(t):], t)
	return rawSign(priv, em)
}

// pssEM builds EMSA-PSS-ENCODE (RFC 8017 §9.1.1) output, letting the caller
// corrupt DB before masking and EM afterwards.
func pssEM(h hashSpec, mHash, salt []byte, emBits int, tweakDB, tweakEM func([]byte)) []byte {
	emLen := (emBits + 7) / 8
	hLen := len(mHash)
	x := h.new()
	x.Write(make([]byte, 8))
	x.Write(mHash)
	x.Write(salt)
	hh := x.Sum(nil)
	db := make([]byte, emLen-hLen-1)
	db[emLen-len(salt)-hLen-2] = 0x01
	copy(db[len(db)-len(salt):], salt)
	if tweakDB != nil {
		tweakDB(db)
	}
	mgf1XOR(db, h, hh)
	db[0] &= 0xff >> (8*emLen - emBits)
	em := append(append(db, hh...), 0xbc)
	if tweakEM != nil {
		tweakEM(em)
	}
	return em
}

// signRawEM signs an arbitrary k-octet encoded message; ok is false if the
// integer is not below n (the caller then retries with a fresh salt).
func signRawEM(priv *rsa.PrivateKey, em []byte) (sig []byte, ok bool) {
	if new(big.Int).SetBytes(em).Cmp(priv.N) >= 0 {
		return nil, false
	}
	return rawSign(priv, em), true
}

// crafted adds vectors whose encoded message is well-formed except for one
// property, signed with the raw private key, so that each check in
// EMSA-PKCS1-v1_5 and EMSA-PSS-VERIFY is exercised on its own.
func (g *rsaGen) crafted(kn string, priv *rsa.PrivateKey, msg []byte) {
	pub := &priv.PublicKey
	h := hashes[0]
	d := digestOf(h, msg)
	k := (pub.N.BitLen() + 7) / 8
	pre := kn + " sha256 crafted "

	// s + n: the same residue as a valid signature, but s >= n
	// (RFC 8017 §5.2.2 step 1). Fits in k octets when n < 2^(8k-1).
	valid := must(rsa.SignPKCS1v15(nil, priv, h.h, d))
	sPlusN := new(big.Int).Add(new(big.Int).SetBytes(valid), pub.N)
	if sPlusN.BitLen() <= 8*k {
		g.add(pre+"pkcs1v15 signature + n", kn, pub, "pkcs1v15", h, d, sPlusN.FillBytes(make([]byte, k)), nil, false, "")
	}
	validPSS := must(rsa.SignPSS(rand.Reader, priv, h.h, d, &rsa.PSSOptions{SaltLength: 32}))
	sPlusN = new(big.Int).Add(new(big.Int).SetBytes(validPSS), pub.N)
	if sPlusN.BitLen() <= 8*k {
		g.add(pre+"pss signature + n", kn, pub, "pss", h, d, sPlusN.FillBytes(make([]byte, k)), ip(32), false, "")
	}

	// EMSA-PKCS1-v1_5 (RFC 8017 §9.2).
	pkcs1 := func(name string, tweak func(em []byte) []byte, valid bool) {
		t := append(bytes.Clone(sha256Prefix), d...)
		em := make([]byte, k)
		em[1] = 1
		for i := 2; i < k-len(t)-1; i++ {
			em[i] = 0xff
		}
		copy(em[k-len(t):], t)
		em = tweak(em)
		sig, ok := signRawEM(priv, em)
		if !ok {
			panic(name + ": encoded message >= n")
		}
		g.add(pre+"pkcs1v15 "+name, kn, pub, "pkcs1v15", h, d, sig, nil, valid, "")
	}
	pkcs1("control (well-formed)", func(em []byte) []byte { return em }, true)
	pkcs1("block type 2", func(em []byte) []byte { em[1] = 2; return em }, false)
	pkcs1("PS octet 0xfe", func(em []byte) []byte { em[5] = 0xfe; return em }, false)
	pkcs1("separator 0x01", func(em []byte) []byte { em[k-len(sha256Prefix)-len(d)-1] = 0x01; return em }, false)
	pkcs1("DigestInfo without NULL parameters", func(em []byte) []byte {
		// SEQUENCE { SEQUENCE { OID sha256 }, OCTET STRING } (RFC 8017 §9.2
		// note 1 allows verifiers to accept this; Go does not).
		t := append([]byte{0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20}, d...)
		out := make([]byte, k)
		out[1] = 1
		for i := 2; i < k-len(t)-1; i++ {
			out[i] = 0xff
		}
		copy(out[k-len(t):], t)
		return out
	}, false)
	pkcs1("trailing octet after digest", func(em []byte) []byte {
		// PS one octet shorter, T followed by one garbage octet.
		out := append(bytes.Clone(em[1:]), 0x42)
		out[0] = 0x00
		out[1] = 0x01
		return out
	}, false)

	// EMSA-PSS (RFC 8017 §9.1), salt length 32.
	emBits := pub.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	pss := func(name string, tweakDB, tweakEM func([]byte), wantValid bool, salts []*int) {
		for range 100 {
			salt := make([]byte, 32)
			rand.Read(salt)
			em := pssEM(h, d, salt, emBits, tweakDB, tweakEM)
			full := make([]byte, k-emLen) // leading zero octet when emLen = k - 1
			full = append(full, em...)
			if name == "non-zero octet above emLen" {
				if k == emLen {
					return // not applicable to this modulus size
				}
				full[0] = 0x01
			}
			sig, ok := signRawEM(priv, full)
			if !ok {
				continue
			}
			for _, s := range salts {
				label := "auto"
				if s != nil {
					label = fmt.Sprintf("exact %d", *s)
				}
				g.add(pre+"pss "+name+" ("+label+")", kn, pub, "pss", h, d, sig, s, wantValid, "")
			}
			return
		}
		panic(name + ": could not find an encoding below n")
	}
	both := []*int{nil, ip(32)}
	psLen := emLen - 32 - 32 - 2
	pss("control (well-formed)", nil, nil, true, both)
	pss("trailer 0xbd", nil, func(em []byte) { em[len(em)-1] = 0xbd }, false, both)
	pss("separator 0x02", func(db []byte) { db[psLen] = 0x02 }, nil, false, []*int{ip(32)})
	pss("separator 0x00", func(db []byte) { db[psLen] = 0x00 }, nil, false, both)
	pss("non-zero PS octet", func(db []byte) { db[psLen-1] = 0x05 }, nil, false, both)
	pss("non-zero first PS octet", func(db []byte) { db[0] = 0x01 }, nil, false, both)
	if 8*emLen-emBits > 0 {
		pss("leftmost bit of EM set", nil, func(em []byte) { em[0] |= 0x80 }, false, both)
	}
	pss("non-zero octet above emLen", nil, nil, false, both)
}

var sha256Prefix = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

func exponent3Key(bits int) *rsa.PrivateKey {
	three := big.NewInt(3)
	one := big.NewInt(1)
	for {
		p := must(rand.Prime(rand.Reader, bits/2))
		q := must(rand.Prime(rand.Reader, bits/2))
		if p.Cmp(q) == 0 {
			continue
		}
		pm1 := new(big.Int).Sub(p, one)
		qm1 := new(big.Int).Sub(q, one)
		if new(big.Int).Mod(pm1, three).Sign() == 0 || new(big.Int).Mod(qm1, three).Sign() == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != bits {
			continue
		}
		phi := new(big.Int).Mul(pm1, qm1)
		d := new(big.Int).ModInverse(three, phi)
		return &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: 3}, D: d, Primes: []*big.Int{p, q}}
	}
}

func genRSA(dir string) {
	g := &rsaGen{}
	msg := []byte("sigstore-swift RSA digest verification")

	for _, bits := range []int{2048, 2049, 3072, 4096} {
		priv := must(rsa.GenerateKey(rand.Reader, bits))
		pub := &priv.PublicKey
		kn := fmt.Sprintf("rsa%d", bits)
		g.addKey(kn, pub)
		k := (bits + 7) / 8

		for _, h := range hashes {
			d := digestOf(h, msg)
			pre := fmt.Sprintf("%s %s ", kn, h.name)

			// PKCS#1 v1.5 (RFC 8017 §8.2).
			sig := must(rsa.SignPKCS1v15(nil, priv, h.h, d))
			g.add(pre+"pkcs1v15 valid", kn, pub, "pkcs1v15", h, d, sig, nil, true, "")
			g.add(pre+"pkcs1v15 flipped signature bit", kn, pub, "pkcs1v15", h, d, flip(sig, 8*k-1), nil, false, "")
			g.add(pre+"pkcs1v15 flipped low signature bit", kn, pub, "pkcs1v15", h, d, flip(sig, 0), nil, false, "")
			g.add(pre+"pkcs1v15 flipped digest bit", kn, pub, "pkcs1v15", h, flip(d, 3), sig, nil, false, "")
			g.add(pre+"pkcs1v15 truncated signature", kn, pub, "pkcs1v15", h, d, sig[:k-1], nil, false, "")
			g.add(pre+"pkcs1v15 signature = n", kn, pub, "pkcs1v15", h, d, pub.N.FillBytes(make([]byte, k)), nil, false, "")
			g.add(pre+"pkcs1v15 signature = 0xff..ff (> n)", kn, pub, "pkcs1v15", h, d, bytes.Repeat([]byte{0xff}, k), nil, false, "")
			g.add(pre+"pkcs1v15 signature = 0", kn, pub, "pkcs1v15", h, d, make([]byte, k), nil, false, "")
			for _, other := range hashes {
				if other.name == h.name {
					continue
				}
				g.add(pre+"pkcs1v15 verified as "+other.name, kn, pub, "pkcs1v15", other, digestOf(other, msg), sig, nil, false, "")
			}
			g.add(pre+"pkcs1v15 verified as pss", kn, pub, "pss", h, d, sig, nil, false, "")

			// PSS (RFC 8017 §8.1) with salt lengths 0, hLen and maximum.
			hLen := len(d)
			emLen := (bits - 1 + 7) / 8
			maxSalt := emLen - hLen - 2
			salt0 := pssSignSalt(priv, h, d, nil)
			saltH := must(rsa.SignPSS(rand.Reader, priv, h.h, d, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}))
			saltMax := must(rsa.SignPSS(rand.Reader, priv, h.h, d, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}))
			for _, sc := range []struct {
				name string
				salt int
				sig  []byte
			}{{"salt 0", 0, salt0}, {"salt hLen", hLen, saltH}, {"salt max", maxSalt, saltMax}} {
				p := pre + "pss " + sc.name + " "
				g.add(p+"exact", kn, pub, "pss", h, d, sc.sig, ip(sc.salt), true, "")
				g.add(p+"auto", kn, pub, "pss", h, d, sc.sig, nil, true, "")
				if sc.salt+1 <= maxSalt {
					g.add(p+"wrong exact salt (+1)", kn, pub, "pss", h, d, sc.sig, ip(sc.salt+1), false, "")
				}
				if sc.salt > 0 {
					g.add(p+"wrong exact salt (-1)", kn, pub, "pss", h, d, sc.sig, ip(sc.salt-1), false, "")
				}
				g.add(p+"flipped signature bit", kn, pub, "pss", h, d, flip(sc.sig, 8*k-9), nil, false, "")
				g.add(p+"flipped digest bit", kn, pub, "pss", h, flip(d, 0), sc.sig, nil, false, "")
				g.add(p+"truncated signature", kn, pub, "pss", h, d, sc.sig[1:], nil, false, "")
				g.add(p+"verified as pkcs1v15", kn, pub, "pkcs1v15", h, d, sc.sig, nil, false, "")
			}
			g.add(pre+"pss exact salt too long", kn, pub, "pss", h, d, saltMax, ip(maxSalt+1), false, "")
			g.add(pre+"pss signature = n", kn, pub, "pss", h, d, pub.N.FillBytes(make([]byte, k)), nil, false, "")
			for _, other := range hashes {
				if other.name == h.name {
					continue
				}
				g.add(pre+"pss verified as "+other.name, kn, pub, "pss", other, digestOf(other, msg), saltH, nil, false, "")
			}
		}
		g.crafted(kn, priv, msg)
	}

	// Small public exponent (e = 3); Go's verifier accepts any odd e >= 3.
	priv3 := exponent3Key(2048)
	g.addKey("rsa2048e3", &priv3.PublicKey)
	d := digestOf(hashes[0], msg)
	sig3 := pkcs1Sign(priv3, sha256Prefix, d)
	g.add("rsa2048e3 sha256 pkcs1v15 valid", "rsa2048e3", &priv3.PublicKey, "pkcs1v15", hashes[0], d, sig3, nil, true, "")
	g.add("rsa2048e3 sha256 pkcs1v15 flipped signature bit", "rsa2048e3", &priv3.PublicKey, "pkcs1v15", hashes[0], d, flip(sig3, 9), nil, false, "")
	pss3 := pssSignSalt(priv3, hashes[0], d, bytes.Repeat([]byte{7}, 32))
	g.add("rsa2048e3 sha256 pss salt hLen auto", "rsa2048e3", &priv3.PublicKey, "pss", hashes[0], d, pss3, nil, true, "")
	g.add("rsa2048e3 sha256 pss salt hLen exact", "rsa2048e3", &priv3.PublicKey, "pss", hashes[0], d, pss3, ip(32), true, "")

	// Minimum size Go accepts by default.
	priv1024 := must(rsa.GenerateKey(rand.Reader, 1024))
	g.addKey("rsa1024", &priv1024.PublicKey)
	d = digestOf(hashes[0], msg)
	g.add("rsa1024 sha256 pkcs1v15 valid", "rsa1024", &priv1024.PublicKey, "pkcs1v15", hashes[0], d,
		must(rsa.SignPKCS1v15(nil, priv1024, crypto.SHA256, d)), nil, true, "")

	writeJSON(dir, "rsa.json", rsaFile{
		Source: "scripts/cryptoextras-vectors (Go crypto/rsa VerifyPKCS1v15 / VerifyPSS)",
		Keys:   g.keys,
		Tests:  g.cases,
	})
	fmt.Printf("rsa.json: %d keys, %d vectors\n", len(g.keys), len(g.cases))
}

func main() {
	out := flag.String("out", "", "output directory (Tests/SigstoreCryptoExtrasTests/Vectors)")
	flag.Parse()
	if *out == "" {
		panic(errors.New("-out is required"))
	}
	genEd25519ph(*out)
	genRSA(*out)
}
