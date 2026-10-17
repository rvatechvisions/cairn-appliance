package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// WO-1017-N56 item 2. The appliance's verifier given an ed25519-sk signature,
// one it had never seen.
//
// The fixture in testdata/test-only-sk-dummy-release was made by OpenSSH
// 10.6p1's ssh-keygen with its regression-test software security key,
// regress/misc/sk-dummy. It was built in a throwaway container from OpenSSH's
// own release tarball, whose SHA256 matched the release notes. The key is TEST
// ONLY: its comment says so, it is in no trust list, and trustedReleaseKeys is
// untouched (WO-1017-N54 item 2, one key only). The same ssh-keygen verified
// the signature with -Y verify before it was copied here. Only the public line,
// the signed manifest and the signature are kept.
//
// The trusted list is passed to verifyRelease as an argument here, so this
// test trusts the test key and nothing else does.

const skFixtureDir = "testdata/test-only-sk-dummy-release"

func skFixture(t *testing.T) (pub string, manifest []byte, signature string) {
	t.Helper()
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(skFixtureDir, name))
		if err != nil {
			t.Fatalf("the fixture %s is not readable: %v", name, err)
		}
		return raw
	}
	pub = strings.TrimSpace(string(read("test-only-sk-dummy.pub")))
	if !strings.HasPrefix(pub, "sk-ssh-ed25519@openssh.com ") || !strings.Contains(pub, "TEST ONLY") {
		t.Fatalf("the fixture key is not the test-only ed25519-sk key: %q", pub)
	}
	return pub, read("manifest.json"), string(read("manifest.json.sig"))
}

var skFixtureNow = time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)

func TestAnEd25519SkReleaseSignatureVerifies(t *testing.T) {
	pub, manifest, signature := skFixture(t)
	served := &signedRelease{Manifest: base64.StdEncoding.EncodeToString(manifest), Signature: signature}
	got, err := verifyRelease(served, []string{pub}, skFixtureNow, 0)
	if err != nil {
		t.Fatalf("a signature made by OpenSSH's ed25519-sk path was refused: %v", err)
	}
	if got.Format != releaseFormat || got.Sequence != 1 {
		t.Fatalf("verified, but read the manifest as %+v", got)
	}
}

func TestAnEd25519SkSignatureAlteredByOneByteIsRefusedByName(t *testing.T) {
	pub, manifest, signature := skFixture(t)
	altered := []byte(manifest)
	altered = append([]byte{}, altered...)
	altered[len(altered)-3] ^= 0x01
	served := &signedRelease{Manifest: base64.StdEncoding.EncodeToString(altered), Signature: signature}
	_, err := verifyRelease(served, []string{pub}, skFixtureNow, 0)
	if err == nil || !strings.Contains(err.Error(), "REFUSED: mis-signed") {
		t.Fatalf("a manifest altered by one byte got %v; it must be refused as mis-signed", err)
	}
}

func TestTheTestKeyTrustsNothingOnItsOwn(t *testing.T) {
	_, manifest, signature := skFixture(t)
	served := &signedRelease{Manifest: base64.StdEncoding.EncodeToString(manifest), Signature: signature}
	if _, err := verifyRelease(served, trustedReleaseKeys, skFixtureNow, 0); err == nil {
		t.Fatal("the test-only key's signature verified against the box's own trust list")
	}
}
