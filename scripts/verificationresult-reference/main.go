// Writes sigstore-go v1.4.1's VerificationResult JSON for the appitool test
// fixtures, as a reference for sigstore-swift's VerificationResult.jsonData().
//
//	cp main.go <sigstore-go v1.4.1 checkout>/cmd/vrref/ && cd <checkout> &&
//	TZ=UTC go run ./cmd/vrref <this repo>/Tests/SigstoreTests/Fixtures
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const digest = "b5eeec2e36db5cfbdda72707ac80b3c807cab76631a35cf618739e29d331f0ce"

func run(fixtures, bundlePath, rootPath, out string, opts []verify.VerifierOption, id verify.CertificateIdentity) {
	tr, err := root.NewTrustedRootFromPath(filepath.Join(fixtures, rootPath))
	check(err)
	b, err := bundle.LoadJSONFromPath(filepath.Join(fixtures, bundlePath))
	check(err)
	v, err := verify.NewVerifier(tr, opts...)
	check(err)
	d, _ := hex.DecodeString(digest)
	res, err := v.Verify(b, verify.NewPolicy(verify.WithArtifactDigest("sha256", d), verify.WithCertificateIdentity(id)))
	check(err)
	j, err := json.MarshalIndent(res, "", "  ")
	check(err)
	check(os.WriteFile(filepath.Join(fixtures, out), append(j, '\n'), 0o644))
	fmt.Println("wrote", out)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	fixtures := os.Args[1]
	prov, err := verify.NewShortCertificateIdentity("https://token.actions.githubusercontent.com", "",
		"", `^https://github\.com/appibara-ltd/appitool/\.github/workflows/release\.yml@`)
	check(err)
	run(fixtures, "appitool-v0.11.0/provenance.sigstore.json", "trusted_root.json", "verification-result-provenance.go.json",
		[]verify.VerifierOption{verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}, prov)
	rel, err := verify.NewShortCertificateIdentity("", ".*", "https://dotcom.releases.github.com", "")
	check(err)
	run(fixtures, "appitool-v0.11.0/release.sigstore.json", "github_trusted_root.json", "verification-result-release.go.json",
		[]verify.VerifierOption{verify.WithSignedTimestamps(1)}, rel)
}
