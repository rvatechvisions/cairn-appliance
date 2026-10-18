package main

// The signed release manifest. Slice 3 of APPLIANCE-SELF-UPDATE-DESIGN.md in
// the portal repository, as the order author ruled in WO-1017-N46 item 5b:
// slice 3 publishes the first signed manifest, listing the binary alone, and
// slice 6 extends the same format to the scripts.
//
// ## What it changes
//
// Until this, -update checked the binary against the digest the portal served,
// so a portal that lied about both passed. Now the digest the box installs comes
// only from a manifest signed by a release signing key the box trusts, made with
// `ssh-keygen -Y sign` under its own namespace on Jackie's workstation. The
// portal carries the manifest and its signature and cannot write either.
//
// ## What it refuses, each by name
//
//   - a manifest the portal served unsigned;
//   - a signature that does not verify, or one made under another namespace;
//   - a signature by a key this box does not trust, named by its fingerprint;
//   - a manifest past its expiry, by this box's clock;
//   - a sequence lower than the highest this box has applied, which is a
//     downgrade. Our own rollback is a new, higher sequence carrying older
//     content, so nothing legitimate is lower.
//
// ## The trusted key
//
// ~~The trusted keys do not exist yet.~~ *Corrected where it stands by
// WO-1018-N57 item 3a:* Jackie made the release signing key on his
// workstation and pasted its public line to the ACTION card (Asana
// 1219602126301657, 23:48:35 UTC on 17 October 2026), with its fingerprint,
// SHA256:OvIasXXdm5uM/TWOH2c+2loKCd+/IpU+SejcutHmuiA. That line is the one
// entry in trustedReleaseKeys. The placeholder is gone: the portal's publish
// refuses a binary that carries it, so it cannot stay anywhere in the binary.
// The two recovery keys stay off the box until both tokens exist and the
// key-change verifier with roles is wired (keychange.go).

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// releaseNamespace is the -n given to ssh-keygen -Y sign. A signature made
// for anything else, a git commit or a file, never verifies as a release.
const releaseNamespace = "cairn-release@rvatechvisions.com"

// releaseFormat is the manifest's format name. Slice 6 adds the scripts under
// a new format name, so a box that understands only this one refuses that one
// rather than reading half of it.
const releaseFormat = "cairn-release/1"

// releaseFormatScripts is slice 6's format: everything cairn-release/1 carries,
// and the scripts beside the binary (release_scripts.go). WO-1018-N60 item 1a.
// The format name is the field that marks the change, so release 1, signed as
// cairn-release/1, is read exactly as it was: its bytes carry no scripts
// field, and a cairn-release/1 manifest that names scripts is refused rather
// than half-read.
const releaseFormatScripts = "cairn-release/2"

// trustedReleaseKeys are the public keys, in authorized_keys form, whose
// signature this box accepts on a release manifest. One entry only: the
// release signing key, and never a recovery key, because any key here can
// sign a release. The order author's ruling, WO-1017-N54 item 2; held by
// TestTheTrustListHoldsOneKeyOnly and, by fingerprint,
// TestTheBuiltTrustListIsJackiesSigningKey.
var trustedReleaseKeys = []string{
	"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGcySIkpXxJEP67cr7/G8bpyeCWimHPWX2a0GBk9IU41 Cairn release signing",
}

// releaseManifest is the signed document.
type releaseManifest struct {
	Format    string `json:"format"`
	Sequence  int64  `json:"sequence"`
	SignedAt  string `json:"signedAt"`
	ExpiresAt string `json:"expiresAt"`
	Binary    struct {
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
		Commit string `json:"commit"`
	} `json:"binary"`
	// Scripts is carried by cairn-release/2 only. Absent from cairn-release/1,
	// release 1 among them.
	Scripts *releaseScripts `json:"scripts,omitempty"`
	// OldestBinary is the lowest binaryReleaseLevel a release runs on
	// (release_apply.go). Absent reads as zero, which every binary meets, so
	// release 1 reads exactly as it did. WO-1018-N62 item 1.
	OldestBinary int64 `json:"oldestBinary,omitempty"`
}

// signedRelease is what the portal serves: the manifest's exact bytes, base64,
// and the armored signature over them.
type signedRelease struct {
	Manifest  string `json:"manifest"`
	Signature string `json:"signature"`
}

// readSSHString reads one SSH wire-format string.
func readSSHString(in []byte) ([]byte, []byte, error) {
	if len(in) < 4 {
		return nil, nil, errors.New("the signature ends in the middle of a field")
	}
	length := binary.BigEndian.Uint32(in)
	if uint64(len(in)-4) < uint64(length) {
		return nil, nil, errors.New("the signature names a field longer than itself")
	}
	return in[4 : 4+length], in[4+length:], nil
}

func sshString(value []byte) []byte {
	out := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(out, uint32(len(value)))
	copy(out[4:], value)
	return out
}

// verifySSHSig checks an armored `ssh-keygen -Y sign` signature over message,
// under namespace, and returns the public key that made it. It is the
// SSHSIG format of OpenSSH's PROTOCOL.sshsig: the magic, version 1, the
// public key, the namespace, a reserved field, the hash algorithm and the
// signature, the signature being over the magic, namespace, reserved, hash
// algorithm and the hash of the message.
func verifySSHSig(armored string, namespace string, message []byte) (ssh.PublicKey, error) {
	text := strings.TrimSpace(armored)
	const begin, end = "-----BEGIN SSH SIGNATURE-----", "-----END SSH SIGNATURE-----"
	if !strings.HasPrefix(text, begin) || !strings.HasSuffix(text, end) {
		return nil, errors.New("the signature is not an armored SSH signature")
	}
	body := strings.Join(strings.Fields(strings.TrimSuffix(strings.TrimPrefix(text, begin), end)), "")
	blob, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("the signature is not base64: %w", err)
	}
	if !bytes.HasPrefix(blob, []byte("SSHSIG")) || len(blob) < 10 {
		return nil, errors.New("the signature does not begin SSHSIG")
	}
	rest := blob[6:]
	if version := binary.BigEndian.Uint32(rest); version != 1 {
		return nil, fmt.Errorf("the signature is version %d, and only version 1 is read", version)
	}
	rest = rest[4:]
	keyBytes, rest, err := readSSHString(rest)
	if err != nil {
		return nil, err
	}
	signedNamespace, rest, err := readSSHString(rest)
	if err != nil {
		return nil, err
	}
	reserved, rest, err := readSSHString(rest)
	if err != nil {
		return nil, err
	}
	hashName, rest, err := readSSHString(rest)
	if err != nil {
		return nil, err
	}
	signatureBytes, _, err := readSSHString(rest)
	if err != nil {
		return nil, err
	}
	if string(signedNamespace) != namespace {
		return nil, fmt.Errorf("the signature was made under the namespace %q, not %q", signedNamespace, namespace)
	}
	var digest []byte
	switch string(hashName) {
	case "sha512":
		sum := sha512.Sum512(message)
		digest = sum[:]
	case "sha256":
		sum := sha256.Sum256(message)
		digest = sum[:]
	default:
		return nil, fmt.Errorf("the signature names the hash %q, which is not read", hashName)
	}
	key, err := ssh.ParsePublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("the signature carries a public key that does not parse: %w", err)
	}
	signature := new(ssh.Signature)
	if err := ssh.Unmarshal(signatureBytes, signature); err != nil {
		return nil, fmt.Errorf("the signature's own signature does not parse: %w", err)
	}
	var signed bytes.Buffer
	signed.WriteString("SSHSIG")
	signed.Write(sshString(signedNamespace))
	signed.Write(sshString(reserved))
	signed.Write(sshString(hashName))
	signed.Write(sshString(digest))
	if err := key.Verify(signed.Bytes(), signature); err != nil {
		return nil, fmt.Errorf("the signature does not verify against the key it names: %w", err)
	}
	return key, nil
}

// trustedKeys parses the trusted list. An unparseable line is never a key,
// and an empty result is said as that.
func trustedKeys(lines []string) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	for _, line := range lines {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("a trusted release key does not parse: %w", err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("REFUSED: this binary trusts no release signing key yet, so it accepts no release. Nothing was installed")
	}
	return keys, nil
}

// verifyRelease is the whole check, before any byte of a binary is fetched.
func verifyRelease(served *signedRelease, trusted []string, now time.Time, highestApplied int64) (releaseManifest, error) {
	var manifest releaseManifest
	if served == nil || served.Manifest == "" || served.Signature == "" {
		return manifest, errors.New("REFUSED: unsigned: the portal served no signed release manifest. Nothing was installed")
	}
	keys, err := trustedKeys(trusted)
	if err != nil {
		return manifest, err
	}
	message, err := base64.StdEncoding.DecodeString(served.Manifest)
	if err != nil {
		return manifest, fmt.Errorf("REFUSED: the release manifest is not base64. Nothing was installed")
	}
	signer, err := verifySSHSig(served.Signature, releaseNamespace, message)
	if err != nil {
		return manifest, fmt.Errorf("REFUSED: mis-signed: %v. Nothing was installed", err)
	}
	trustedSigner := false
	for _, key := range keys {
		if bytes.Equal(key.Marshal(), signer.Marshal()) {
			trustedSigner = true
		}
	}
	if !trustedSigner {
		return manifest, fmt.Errorf("REFUSED: signed by %s, a key this box does not trust. Nothing was installed", ssh.FingerprintSHA256(signer))
	}
	if err := json.Unmarshal(message, &manifest); err != nil {
		return manifest, fmt.Errorf("REFUSED: the signed manifest does not parse: %v. Nothing was installed", err)
	}
	switch manifest.Format {
	case releaseFormat:
		if manifest.Scripts != nil {
			return manifest, fmt.Errorf("REFUSED: the signed manifest is format %q and names scripts, which only %q carries. Nothing was installed", releaseFormat, releaseFormatScripts)
		}
	case releaseFormatScripts:
		if err := validScripts(manifest.Scripts); err != nil {
			return manifest, fmt.Errorf("REFUSED: the signed manifest's scripts %v. Nothing was installed", err)
		}
	default:
		return manifest, fmt.Errorf("REFUSED: the signed manifest is format %q, and this binary reads %q and %q. Nothing was installed", manifest.Format, releaseFormat, releaseFormatScripts)
	}
	expires, err := time.Parse(time.RFC3339, manifest.ExpiresAt)
	if err != nil {
		return manifest, fmt.Errorf("REFUSED: the signed manifest names no expiry it can read (%q). Nothing was installed", manifest.ExpiresAt)
	}
	if !now.Before(expires) {
		return manifest, fmt.Errorf("REFUSED: expired: the signed manifest expired at %s, and this box reads %s. Nothing was installed", expires.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if manifest.Sequence < highestApplied {
		return manifest, fmt.Errorf("REFUSED: stale: the signed manifest is sequence %d, and this box has applied %d. Nothing was installed", manifest.Sequence, highestApplied)
	}
	if manifest.OldestBinary < 0 {
		return manifest, fmt.Errorf("REFUSED: the signed manifest names an oldest binary of %d, which is not a level. Nothing was installed", manifest.OldestBinary)
	}
	return manifest, nil
}

// binaryTooOld refuses a release's scripts where they need a newer binary than
// this one. Only the scripts: the binary path (-update) installs the release's
// own binary, which is how a box gets the newer binary a release asks for, so a
// check there would stop the one update that answers it.
func binaryTooOld(manifest releaseManifest, outcome string) error {
	if manifest.OldestBinary > binaryReleaseLevel {
		return fmt.Errorf("REFUSED: binary too old: signed release %d's scripts run on a binary of level %d or newer, and this binary is level %d. Update the binary first. Nothing was %s", manifest.Sequence, manifest.OldestBinary, binaryReleaseLevel, outcome)
	}
	return nil
}

// sequencePath is where the box keeps the highest sequence it has applied,
// beside its key. A box that has applied none reads zero.
func sequencePath() string {
	return filepath.Join(filepath.Dir(keyPath), "release.sequence")
}

// highestApplied reads the stored sequence. A file that is present and does
// not read as a number is an error, never zero: zero would let any old
// release in.
func highestApplied(path string) (int64, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("could not read the applied sequence at %s: %w", path, err)
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("the applied sequence at %s is %q, which is not a sequence", path, strings.TrimSpace(string(raw)))
	}
	return value, nil
}

func recordApplied(path string, sequence int64) error {
	staging := path + ".incoming"
	if err := os.WriteFile(staging, []byte(strconv.FormatInt(sequence, 10)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(staging, path)
}
