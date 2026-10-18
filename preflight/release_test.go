package main

// Slice 3: the box installs only what a release manifest signed by a key it
// trusts names. WO-1017-N47 item 1.
//
// **THE KEYS IN THIS FILE ARE TEST FIXTURES.** Each is generated inside the test
// that uses it, in memory or in the test's own temporary directory, and is gone
// when the test ends. None is Jackie's release signing key, none is trusted by
// any built binary, and no private key is committed anywhere.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fixtureKey is a throwaway ed25519 key and its authorized_keys line.
func fixtureKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return private, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic)))
}

func wireString(value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(out, uint32(len(value)))
	copy(out[4:], value)
	return out
}

// fixtureSign makes an armored SSHSIG signature the way ssh-keygen -Y sign
// does, with sha512. TestVerifiesASignatureMadeByTheRealTool holds this
// helper's understanding of the format to the tool's own output, so the
// verifier is not proven only against a signer written by the same hand.
func fixtureSign(t *testing.T, private ed25519.PrivateKey, namespace string, message []byte) string {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha512.Sum512(message)
	var signed bytes.Buffer
	signed.WriteString("SSHSIG")
	signed.Write(wireString([]byte(namespace)))
	signed.Write(wireString(nil))
	signed.Write(wireString([]byte("sha512")))
	signed.Write(wireString(sum[:]))
	signature, err := signer.Sign(rand.Reader, signed.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var blob bytes.Buffer
	blob.WriteString("SSHSIG")
	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, 1)
	blob.Write(version)
	blob.Write(wireString(signer.PublicKey().Marshal()))
	blob.Write(wireString([]byte(namespace)))
	blob.Write(wireString(nil))
	blob.Write(wireString([]byte("sha512")))
	blob.Write(wireString(ssh.Marshal(signature)))
	return "-----BEGIN SSH SIGNATURE-----\n" + base64.StdEncoding.EncodeToString(blob.Bytes()) + "\n-----END SSH SIGNATURE-----\n"
}

var releaseNow = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func fixtureManifest(t *testing.T, sequence int64, expires time.Time, content []byte) []byte {
	t.Helper()
	manifest := releaseManifest{Format: releaseFormat, Sequence: sequence, SignedAt: releaseNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339)}
	manifest.Binary.Digest = digestOf(content)
	manifest.Binary.Size = int64(len(content))
	manifest.Binary.Commit = strings.Repeat("c", 40)
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func served(message []byte, signature string) *signedRelease {
	return &signedRelease{Manifest: base64.StdEncoding.EncodeToString(message), Signature: signature}
}

func TestAcceptsAManifestSignedByATrustedKey(t *testing.T) {
	private, public := fixtureKey(t)
	message := fixtureManifest(t, 7, releaseNow.Add(21*24*time.Hour), []byte("binary"))
	manifest, err := verifyRelease(served(message, fixtureSign(t, private, releaseNamespace, message)), []string{public}, releaseNow, 6)
	if err != nil {
		t.Fatalf("a correctly signed, current manifest was refused: %v", err)
	}
	if manifest.Sequence != 7 || manifest.Binary.Digest != digestOf([]byte("binary")) {
		t.Fatalf("the manifest read back as %+v", manifest)
	}
}

func TestRefusesAnUnsignedManifest(t *testing.T) {
	_, public := fixtureKey(t)
	for _, release := range []*signedRelease{nil, {Manifest: "e30=", Signature: ""}} {
		_, err := verifyRelease(release, []string{public}, releaseNow, 0)
		if err == nil || !strings.Contains(err.Error(), "REFUSED: unsigned") {
			t.Fatalf("an unsigned manifest gave %v, want REFUSED: unsigned", err)
		}
	}
}

func TestRefusesAMisSignedManifest(t *testing.T) {
	private, public := fixtureKey(t)
	message := fixtureManifest(t, 1, releaseNow.Add(time.Hour), []byte("binary"))
	signature := fixtureSign(t, private, releaseNamespace, message)
	tampered := bytes.Replace(message, []byte(`"sequence":1`), []byte(`"sequence":9`), 1)
	_, err := verifyRelease(served(tampered, signature), []string{public}, releaseNow, 0)
	if err == nil || !strings.Contains(err.Error(), "REFUSED: mis-signed") {
		t.Fatalf("a manifest changed after signing gave %v, want REFUSED: mis-signed", err)
	}
	other := fixtureSign(t, private, "git", message)
	_, err = verifyRelease(served(message, other), []string{public}, releaseNow, 0)
	if err == nil || !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("a signature under another namespace gave %v, want a refusal naming the namespace", err)
	}
}

func TestRefusesASignatureByAKeyThisBoxDoesNotTrust(t *testing.T) {
	private, _ := fixtureKey(t)
	_, trusted := fixtureKey(t)
	message := fixtureManifest(t, 1, releaseNow.Add(time.Hour), []byte("binary"))
	_, err := verifyRelease(served(message, fixtureSign(t, private, releaseNamespace, message)), []string{trusted}, releaseNow, 0)
	if err == nil || !strings.Contains(err.Error(), "a key this box does not trust") || !strings.Contains(err.Error(), "SHA256:") {
		t.Fatalf("an untrusted signer gave %v, want a refusal naming its fingerprint", err)
	}
}

func TestRefusesAStaleManifest(t *testing.T) {
	private, public := fixtureKey(t)
	expired := fixtureManifest(t, 5, releaseNow.Add(-time.Minute), []byte("binary"))
	_, err := verifyRelease(served(expired, fixtureSign(t, private, releaseNamespace, expired)), []string{public}, releaseNow, 0)
	if err == nil || !strings.Contains(err.Error(), "REFUSED: expired") {
		t.Fatalf("an expired manifest gave %v, want REFUSED: expired", err)
	}
	older := fixtureManifest(t, 4, releaseNow.Add(time.Hour), []byte("binary"))
	_, err = verifyRelease(served(older, fixtureSign(t, private, releaseNamespace, older)), []string{public}, releaseNow, 5)
	if err == nil || !strings.Contains(err.Error(), "REFUSED: stale") {
		t.Fatalf("a sequence below the applied one gave %v, want REFUSED: stale", err)
	}
}

// One key, and only one, ever signs a release. The order author's ruling,
// WO-1017-N54 item 2, 17 October 2026: the recovery keys sign key changes and
// never releases, and verifyRelease accepts a manifest signed by any key in
// this list, so a recovery key placed here could sign a release. They stay off
// the box until a key-change verifier with roles exists. This test outlives the
// placeholder: when the signing key replaces it, the list still holds one entry,
// and a second key cannot join it without this failing.
func TestTheTrustListHoldsOneKeyOnly(t *testing.T) {
	if len(trustedReleaseKeys) != 1 {
		t.Fatalf("trustedReleaseKeys holds %d entries; it holds the release signing key alone, and the recovery keys wait for a key-change verifier with roles", len(trustedReleaseKeys))
	}
}

// The binary as built trusts Jackie's release signing key, by the fingerprint
// he printed on the ACTION card (Asana 1219602126301657), and nothing else.
// WO-1018-N57 item 3a.
func TestTheBuiltTrustListIsJackiesSigningKey(t *testing.T) {
	keys, err := trustedKeys(trustedReleaseKeys)
	if err != nil || len(keys) != 1 {
		t.Fatalf("trustedReleaseKeys parsed to %d keys, %v; it holds the signing key alone", len(keys), err)
	}
	if got := ssh.FingerprintSHA256(keys[0]); got != "SHA256:OvIasXXdm5uM/TWOH2c+2loKCd+/IpU+SejcutHmuiA" {
		t.Fatalf("the trusted key is %s, not the fingerprint Jackie printed", got)
	}
	if keys[0].Type() != "ssh-ed25519" {
		t.Fatalf("the trusted key is %s; the signing key is an ed25519 key file, never a hardware recovery key", keys[0].Type())
	}
	private, _ := fixtureKey(t)
	message := fixtureManifest(t, 1, releaseNow.Add(time.Hour), []byte("binary"))
	_, err = verifyRelease(served(message, fixtureSign(t, private, releaseNamespace, message)), trustedReleaseKeys, releaseNow, 0)
	if err == nil || !strings.Contains(err.Error(), "a key this box does not trust") {
		t.Fatalf("a test key's manifest against the built trust list gave %v, want it refused as untrusted", err)
	}
}

// An empty trust list is said as that, never read as trusting anyone.
func TestAnEmptyTrustListAcceptsNoRelease(t *testing.T) {
	private, _ := fixtureKey(t)
	message := fixtureManifest(t, 1, releaseNow.Add(time.Hour), []byte("binary"))
	_, err := verifyRelease(served(message, fixtureSign(t, private, releaseNamespace, message)), nil, releaseNow, 0)
	if err == nil || !strings.Contains(err.Error(), "trusts no release signing key yet") {
		t.Fatalf("an empty trust list gave %v, want the refusal naming that it trusts no key", err)
	}
}

func TestVerifiesASignatureMadeByTheRealTool(t *testing.T) {
	tool, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Fatalf("ssh-keygen is not on PATH, so the verifier cannot be held to the real tool: %v", err)
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "fixture-release-key")
	if out, err := exec.Command(tool, "-q", "-t", "ed25519", "-N", "", "-C", "test fixture", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen could not make the fixture key: %v: %s", err, out)
	}
	message := fixtureManifest(t, 3, releaseNow.Add(time.Hour), []byte("binary"))
	manifestFile := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestFile, message, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(tool, "-Y", "sign", "-f", key, "-n", releaseNamespace, manifestFile).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y sign failed: %v: %s", err, out)
	}
	signature, err := os.ReadFile(manifestFile + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	public, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRelease(served(message, string(signature)), []string{strings.TrimSpace(string(public))}, releaseNow, 0); err != nil {
		t.Fatalf("a signature made by ssh-keygen itself was refused: %v", err)
	}
	if _, err := verifyRelease(served(append(message, ' '), string(signature)), []string{strings.TrimSpace(string(public))}, releaseNow, 0); err == nil {
		t.Fatal("ssh-keygen's signature verified over bytes it did not sign")
	}
}

// The whole -update path against a stand-in portal. The point of slice 3: a
// portal that serves a digest and bytes that match each other, with no
// signature, installs nothing.
func TestUpdateInstallsOnlyWhatTheSignedManifestNames(t *testing.T) {
	_, appliance, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	private, public := fixtureKey(t)
	content := []byte("the new binary")
	message := fixtureManifest(t, 2, releaseNow.Add(time.Hour), content)
	var answer []byte
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == binaryManifestPath {
			_, _ = w.Write(answer)
			return
		}
		_, _ = w.Write(content)
	}))
	defer portal.Close()

	dir := t.TempDir()
	target := filepath.Join(dir, "preflight")
	sequence := filepath.Join(dir, "release.sequence")
	if err := os.WriteFile(target, []byte("the old binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	unsigned, _ := json.Marshal(binaryManifest{Digest: digestOf(content), Size: int64(len(content)), Commit: "x"})
	answer = unsigned
	err = runUpdateWith(portal.URL, "fp", appliance, target, []string{public}, sequence, releaseNow)
	if err == nil || !strings.Contains(err.Error(), "REFUSED: unsigned") {
		t.Fatalf("an unsigned answer gave %v, want REFUSED: unsigned", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "the old binary" {
		t.Fatalf("an unsigned answer changed the installed binary to %q", got)
	}

	signed, _ := json.Marshal(servedManifest{Release: served(message, fixtureSign(t, private, releaseNamespace, message))})
	answer = signed
	if err := runUpdateWith(portal.URL, "fp", appliance, target, []string{public}, sequence, releaseNow); err != nil {
		t.Fatalf("a signed release was refused: %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != "the new binary" {
		t.Fatalf("the installed binary is %q, want the signed release's", got)
	}
	if got, _ := os.ReadFile(sequence); strings.TrimSpace(string(got)) != "2" {
		t.Fatalf("the applied sequence reads %q, want 2", got)
	}
}

func TestAnUnreadableAppliedSequenceRefusesRatherThanReadingZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.sequence")
	if err := os.WriteFile(path, []byte("not a number\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := highestApplied(path); err == nil {
		t.Fatal("a sequence file that is not a number read as a sequence")
	}
	if value, err := highestApplied(filepath.Join(t.TempDir(), "absent")); err != nil || value != 0 {
		t.Fatalf("no file gave %d, %v; want 0, a box that has applied nothing", value, err)
	}
}
