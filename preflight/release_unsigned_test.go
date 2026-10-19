package main

// An unsigned release, taken only where the portal sent no signature and this
// box holds RVA's permit. Approved by Jackie Ramsey in Asana on 19 October 2026
// (card 1219663784344206), under his decision recorded in the portal's
// CLAUDE.md (card 1219642376207989): only the signature check is waived, only
// on RVA's box, and the published digest is still verified before anything
// runs. WO-1019-N81 item 1.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withPermit points the permit at a file in a temporary directory, present or
// absent, and puts the real path back afterwards.
func withPermit(t *testing.T, present bool) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "release-unsigned-permitted")
	if present {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	saved := unsignedReleasePermit
	unsignedReleasePermit = path
	t.Cleanup(func() { unsignedReleasePermit = saved })
}

func TestTakesAnUnsignedReleaseOnlyWithThePermit(t *testing.T) {
	_, public := fixtureKey(t)
	message := fixtureManifest(t, 4, releaseNow.Add(time.Hour), []byte("binary"))

	withPermit(t, true)
	manifest, err := verifyRelease(served(message, ""), []string{public}, releaseNow, 3)
	if err != nil {
		t.Fatalf("an unsigned release on a box holding the permit was refused: %v", err)
	}
	if manifest.Sequence != 4 || manifest.Binary.Digest != digestOf([]byte("binary")) {
		t.Fatalf("the unsigned manifest read back as %+v", manifest)
	}
	// The other checks still hold without a signature: a stale sequence is refused.
	if _, err := verifyRelease(served(message, ""), []string{public}, releaseNow, 5); err == nil || !strings.Contains(err.Error(), "REFUSED: stale") {
		t.Fatalf("a stale unsigned release gave %v, want REFUSED: stale", err)
	}
}

func TestRefusesAnUnsignedReleaseWithoutThePermit(t *testing.T) {
	_, public := fixtureKey(t)
	message := fixtureManifest(t, 4, releaseNow.Add(time.Hour), []byte("binary"))
	withPermit(t, false)
	_, err := verifyRelease(served(message, ""), []string{public}, releaseNow, 0)
	if err == nil || !strings.Contains(err.Error(), "REFUSED: unsigned") || !strings.Contains(err.Error(), "no permit") {
		t.Fatalf("an unsigned release on a box with no permit gave %v, want REFUSED: unsigned naming the permit", err)
	}
}

func TestStillVerifiesASignatureWhenThePermitIsPresent(t *testing.T) {
	private, public := fixtureKey(t)
	other, _ := fixtureKey(t)
	message := fixtureManifest(t, 4, releaseNow.Add(time.Hour), []byte("binary"))
	withPermit(t, true)
	if _, err := verifyRelease(served(message, fixtureSign(t, private, releaseNamespace, message)), []string{public}, releaseNow, 0); err != nil {
		t.Fatalf("a correctly signed release was refused on a box holding the permit: %v", err)
	}
	_, err := verifyRelease(served(message, fixtureSign(t, other, releaseNamespace, message)), []string{public}, releaseNow, 0)
	if err == nil || !strings.Contains(err.Error(), "a key this box does not trust") {
		t.Fatalf("a signature by an untrusted key gave %v with the permit present, want it refused, never taken as unsigned", err)
	}
}

// The whole -update path, unsigned and permitted: the bytes are still checked
// against the manifest's digest, so a portal serving other bytes of the same
// size installs nothing.
func TestAnUnsignedReleaseStillChecksTheDigestBeforeInstalling(t *testing.T) {
	_, appliance, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, public := fixtureKey(t)
	content := []byte("the new binary")
	message := fixtureManifest(t, 2, releaseNow.Add(time.Hour), content)
	body := content
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == binaryManifestPath {
			answer, _ := json.Marshal(servedManifest{Release: served(message, "")})
			_, _ = w.Write(answer)
			return
		}
		_, _ = w.Write(body)
	}))
	defer portal.Close()
	withPermit(t, true)

	dir := t.TempDir()
	target := filepath.Join(dir, "preflight")
	sequence := filepath.Join(dir, "release.sequence")
	if err := os.WriteFile(target, []byte("the old binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	body = []byte("THE NEW BINARY")
	err = runUpdateWith(portal.URL, "fp", appliance, target, []string{public}, sequence, releaseNow)
	if err == nil || !strings.Contains(err.Error(), "the bytes hash to") {
		t.Fatalf("other bytes of the same size gave %v, want a refusal naming the digest", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "the old binary" {
		t.Fatalf("bytes that did not match the digest replaced the installed binary with %q", got)
	}

	body = content
	if err := runUpdateWith(portal.URL, "fp", appliance, target, []string{public}, sequence, releaseNow); err != nil {
		t.Fatalf("the unsigned release's own bytes were refused: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "the new binary" {
		t.Fatalf("the installed binary is %q, want the release's", got)
	}
}
