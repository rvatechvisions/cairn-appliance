package main

// Receiving a new binary, verified before anything executes. WO-0928-C item 5.
//
// ## Why this exists
//
// "The appliance never runs a binary it cannot verify" was not true: the only
// check before the probe ran was its own self-reported commit stamp, which a
// binary can say about itself whatever it is. This is the verified path.
//
// ## The shape, each part answering one way it could go wrong
//
//   - The binary comes from the PORTAL, over TLS, with a signed request -- never
//     GitHub, a release host or a mirror. The fourth refusal.
//   - The portal names the digest in a SEPARATE response from the bytes, so no
//     single object vouches for itself: the manifest says what the bytes must
//     hash to, and the bytes are fetched by that digest.
//   - SHA-256 is computed here and compared before anything is written where
//     it could run. On a mismatch the update is REFUSED, by name, and the binary
//     already installed keeps running. A failed update is "could not run" --
//     never a silent fallback and never a partial write.
//   - The running binary is never overwritten until the replacement has
//     verified: written beside it, re-read from disk and hashed again, then
//     renamed over it. A rename replaces the name atomically; a process already
//     running keeps the file it opened.
//   - Nothing here compiles, acquires a compiler, or fetches code from anywhere
//     but the portal.
//
// ## One key, not two -- Jackie's ruling, 28 September 2026 (WO-0928-D item 4)
//
// The appliance's existing ed25519 key at /etc/cairn-appliance/appliance.key
// authenticates both directions of the conversation: it signs outbound
// submissions, and it signs the two fetches here. The portal serves the digest
// over that authenticated channel. There is no portal signing key and no
// second appliance key -- nothing new to keep anywhere.
//
// ## What that leaves, stated
//
// The manifest and the bytes both come from the portal. A portal that was
// itself compromised could serve a matching pair; the separate response defends
// against a corrupted or substituted object, not against the source. That is
// the residual of the one-key decision, and it is the same trust the appliance
// already places in the portal for its credential.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const binaryManifestPath = "/appliance/binary/manifest"

// binaryManifest is what the portal says the current binary is.
type binaryManifest struct {
	Digest string `json:"digest"`
	Commit string `json:"commit"`
	Size   int64  `json:"size"`
}

// signedFetch makes a signed request with no body and returns what came back.
func signedFetch(portal, path, fingerprint string, private ed25519.PrivateKey) ([]byte, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generating a nonce: %w", err)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	signature := ed25519.Sign(private, canonicalBytes(http.MethodPost, path, fingerprint, timestamp, nonce, bodyHash(nil)))

	request, err := http.NewRequest(http.MethodPost, strings.TrimRight(portal, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Cairn-Appliance", fingerprint)
	request.Header.Set("Cairn-Timestamp", timestamp)
	request.Header.Set("Cairn-Nonce", nonce)
	request.Header.Set("Cairn-Signature", base64.StdEncoding.EncodeToString(signature))

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("reaching the portal: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading the portal's answer: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		var refusal struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &refusal)
		if refusal.Error != "" {
			return nil, fmt.Errorf("refused (%d): %s", response.StatusCode, refusal.Error)
		}
		return nil, fmt.Errorf("refused (%d)", response.StatusCode)
	}
	return body, nil
}

func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// validManifest refuses a manifest that could not name a binary.
func validManifest(m binaryManifest) error {
	if len(m.Digest) != 64 || strings.Trim(strings.ToLower(m.Digest), "0123456789abcdef") != "" {
		return fmt.Errorf("the manifest names no SHA-256 digest (%q)", m.Digest)
	}
	if m.Size <= 0 {
		return fmt.Errorf("the manifest names no size")
	}
	return nil
}

// installVerified writes content over target only if it hashes to want.
//
// The order is the point: verify the bytes in hand, write them beside the
// target, read what landed back and verify THAT, and only then rename. On any
// failure the target is untouched and the staging file is removed.
func installVerified(target string, want binaryManifest, content []byte) error {
	if err := validManifest(want); err != nil {
		return err
	}
	if int64(len(content)) != want.Size {
		return fmt.Errorf("REFUSED: the portal sent %d bytes and its manifest names %d. Nothing was installed", len(content), want.Size)
	}
	if got := digestOf(content); got != strings.ToLower(want.Digest) {
		return fmt.Errorf("REFUSED: the bytes hash to %s and the manifest names %s. Nothing was installed", got, want.Digest)
	}

	staging := filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+".incoming")
	_ = os.Remove(staging)
	file, err := os.OpenFile(staging, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return fmt.Errorf("could not stage the new binary: %w", err)
	}
	if _, err := io.Copy(file, bytes.NewReader(content)); err != nil {
		file.Close()
		_ = os.Remove(staging)
		return fmt.Errorf("could not write the new binary: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(staging)
		return fmt.Errorf("could not flush the new binary: %w", err)
	}
	file.Close()

	landed, err := os.ReadFile(staging)
	if err != nil || digestOf(landed) != strings.ToLower(want.Digest) {
		_ = os.Remove(staging)
		return fmt.Errorf("REFUSED: what was written does not hash to the manifest. Nothing was installed")
	}

	if err := os.Rename(staging, target); err != nil {
		_ = os.Remove(staging)
		return fmt.Errorf("could not put the verified binary in place: %w", err)
	}
	return nil
}

// runUpdate is the -update mode.
func runUpdate(portal, fingerprint string, private ed25519.PrivateKey, target string) error {
	raw, err := signedFetch(portal, binaryManifestPath, fingerprint, private)
	if err != nil {
		return fmt.Errorf("could not read the manifest: %w", err)
	}
	var manifest binaryManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return fmt.Errorf("the manifest did not parse: %w", err)
	}
	if err := validManifest(manifest); err != nil {
		return err
	}

	if current, err := os.ReadFile(target); err == nil && digestOf(current) == strings.ToLower(manifest.Digest) {
		fmt.Printf("already current: %s (%s)\n", manifest.Digest, manifest.Commit)
		return nil
	}

	content, err := signedFetch(portal, "/appliance/binary/"+strings.ToLower(manifest.Digest), fingerprint, private)
	if err != nil {
		return fmt.Errorf("could not fetch the binary: %w", err)
	}
	if err := installVerified(target, manifest, content); err != nil {
		return err
	}
	fmt.Printf("installed %s (%s), verified before it was put in place\n", manifest.Digest, manifest.Commit)
	return nil
}
