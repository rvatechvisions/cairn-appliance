package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// WO-1018-N57 item 3b. The fixture in testdata/test-only-key-change was made
// by OpenSSH 10.6p1's ssh-keygen with its regression-test software security
// key, sk-dummy, in a throwaway container, and that ssh-keygen verified the
// recovery key's signature with -Y verify before it was copied here. Every key
// in it is TEST ONLY, says so in its comment, and is passed to the verifier by
// argument: none is in a trust list the binary carries.

const keyChangeDir = "testdata/test-only-key-change"

type keyChangeFixture struct {
	recovery, oldSigning, newSigning string
	statement                        []byte
	byRecovery, bySigningKey         string
}

func loadKeyChangeFixture(t *testing.T) keyChangeFixture {
	t.Helper()
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(keyChangeDir, name))
		if err != nil {
			t.Fatalf("the fixture %s is not readable: %v", name, err)
		}
		return raw
	}
	f := keyChangeFixture{
		recovery:     strings.TrimSpace(string(read("test-only-recovery.pub"))),
		oldSigning:   strings.TrimSpace(string(read("test-only-old-signing.pub"))),
		newSigning:   strings.TrimSpace(string(read("test-only-new-signing.pub"))),
		statement:    read("key-change.json"),
		byRecovery:   string(read("key-change.json.sig")),
		bySigningKey: string(read("key-change.json.signed-by-signing-key.sig")),
	}
	for _, line := range []string{f.recovery, f.oldSigning, f.newSigning} {
		if !strings.Contains(line, "TEST ONLY") {
			t.Fatalf("a fixture key is not marked TEST ONLY: %q", line)
		}
	}
	if !strings.HasPrefix(f.recovery, "sk-ssh-ed25519@openssh.com ") {
		t.Fatalf("the fixture recovery key is not an ed25519-sk key: %q", f.recovery)
	}
	return f
}

func servedKeyChange(statement []byte, signature string) *signedRelease {
	return &signedRelease{Manifest: base64.StdEncoding.EncodeToString(statement), Signature: signature}
}

func TestARecoveryKeySignedKeyChangeVerifiesAndNamesTheNewKey(t *testing.T) {
	f := loadKeyChangeFixture(t)
	statement, next, err := verifyKeyChange(servedKeyChange(f.statement, f.byRecovery), []string{f.recovery}, []string{f.oldSigning}, 0)
	if err != nil {
		t.Fatalf("a key change signed by a trusted recovery key was refused: %v", err)
	}
	want, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(f.newSigning))
	if ssh.FingerprintSHA256(next) != ssh.FingerprintSHA256(want) || statement.Sequence != 1 {
		t.Fatalf("verified, but read %+v trusting %s", statement, ssh.FingerprintSHA256(next))
	}
}

func TestAKeyChangeAlteredByOneByteIsRefusedByName(t *testing.T) {
	f := loadKeyChangeFixture(t)
	altered := append([]byte{}, f.statement...)
	altered[len(altered)-3] ^= 0x01
	_, _, err := verifyKeyChange(servedKeyChange(altered, f.byRecovery), []string{f.recovery}, []string{f.oldSigning}, 0)
	if err == nil || !strings.Contains(err.Error(), "REFUSED: mis-signed") {
		t.Fatalf("a key change altered by one byte got %v; it must be refused as mis-signed", err)
	}
}

func TestAKeyChangeSignedByAKeyOutsideTheRecoveryListIsRefused(t *testing.T) {
	f := loadKeyChangeFixture(t)
	// The recovery list here holds the new signing key only, so the real signer is outside it.
	_, _, err := verifyKeyChange(servedKeyChange(f.statement, f.byRecovery), []string{f.newSigning}, []string{f.oldSigning}, 0)
	if err == nil || !strings.Contains(err.Error(), "a key this box does not trust for key changes") {
		t.Fatalf("a key change signed outside the recovery list got %v", err)
	}
}

func TestTheReleaseSigningKeyCannotSignAKeyChange(t *testing.T) {
	f := loadKeyChangeFixture(t)
	_, _, err := verifyKeyChange(servedKeyChange(f.statement, f.bySigningKey), []string{f.recovery}, []string{f.oldSigning}, 0)
	if err == nil || !strings.Contains(err.Error(), "the release signing key, which signs releases and never a key change") {
		t.Fatalf("a key change signed by the release signing key got %v", err)
	}
}

func TestAKeyChangeNeverVerifiesAsARelease(t *testing.T) {
	f := loadKeyChangeFixture(t)
	// Even trusting the recovery key for releases, the key-change namespace refuses it.
	_, err := verifyRelease(servedKeyChange(f.statement, f.byRecovery), []string{f.recovery}, releaseNow, 0)
	if err == nil || !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("a key change presented as a release got %v; the namespaces must keep them apart", err)
	}
}

func TestAReleaseNeverVerifiesAsAKeyChange(t *testing.T) {
	pub, manifest, signature := skFixture(t)
	_, _, err := verifyKeyChange(servedKeyChange(manifest, signature), []string{pub}, []string{pub}, 0)
	if err == nil || !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("a release presented as a key change got %v; the namespaces must keep them apart", err)
	}
}

func TestAStaleOrMisdirectedKeyChangeIsRefused(t *testing.T) {
	f := loadKeyChangeFixture(t)
	_, _, err := verifyKeyChange(servedKeyChange(f.statement, f.byRecovery), []string{f.recovery}, []string{f.oldSigning}, 1)
	if err == nil || !strings.Contains(err.Error(), "REFUSED: stale") {
		t.Fatalf("a key change at the applied sequence got %v", err)
	}
	_, _, err = verifyKeyChange(servedKeyChange(f.statement, f.byRecovery), []string{f.recovery}, []string{f.newSigning}, 0)
	if err == nil || !strings.Contains(err.Error(), "a key this box does not trust for releases") {
		t.Fatalf("a key change retiring a key this box does not trust got %v", err)
	}
}

func TestNoRecoveryKeyIsTrustedYet(t *testing.T) {
	if len(trustedRecoveryKeys) != 0 {
		t.Fatalf("trustedRecoveryKeys holds %d keys; none is placed until both FIDO2 keys exist", len(trustedRecoveryKeys))
	}
	f := loadKeyChangeFixture(t)
	_, _, err := verifyKeyChange(servedKeyChange(f.statement, f.byRecovery), trustedRecoveryKeys, trustedReleaseKeys, 0)
	if err == nil || !strings.Contains(err.Error(), "trusts no recovery key yet") {
		t.Fatalf("the built binary given a key change got %v", err)
	}
}
