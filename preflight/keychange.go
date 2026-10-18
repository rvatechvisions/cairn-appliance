package main

// The key-change verifier, with roles. WO-1018-N57 item 3b, building the
// later slice WO-1017-N54 item 2 named: a recovery key signs a key change and
// never a release, and the release signing key signs a release and never a
// key change. Its precondition was met at the held branch's ed25519-sk test:
// an sk-ssh-ed25519@openssh.com signature, as OpenSSH makes it, verifies in
// verifySSHSig.
//
// ## What a key change is
//
// One signed statement, cairn-key-change/1, under its own namespace, so a key
// change never verifies as a release and a release never verifies as a key
// change:
//
//	{"format":"cairn-key-change/1","sequence":1,"signedAt":"...",
//	 "retire":"SHA256:<fingerprint of the signing key it stops trusting>",
//	 "trust":"<the new signing key, in authorized_keys form>"}
//
// The design is APPLIANCE-SELF-UPDATE-DESIGN.md in the portal repository,
// *The keys*: stop trusting this signing key, trust this one.
//
// ## What it refuses, each by name
//
//   - a statement served unsigned;
//   - a binary that trusts no recovery key yet, which is every binary until
//     both FIDO2 keys exist (Part B of the key card);
//   - a signature that does not verify, or one made under another namespace;
//   - a statement signed by the release signing key, a role it does not have;
//   - a statement signed by any other key this box does not trust for key
//     changes, named by its fingerprint;
//   - a format it does not read;
//   - a sequence not above the highest key change this box has applied;
//   - a retire naming a key this box does not trust for releases;
//   - a trust line that does not parse, or that names a recovery key.
//
// ## What it does not do yet
//
// It verifies. Nothing serves a key change, and nothing applies one. Applying
// means keeping the trusted signing key on the box rather than in the binary,
// and saying loudly that it happened (the design's *Using a recovery key is
// the loudest event this system produces*). That is the next slice, and it is
// wired when the recovery keys exist.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// keyChangeNamespace is the -n given to ssh-keygen -Y sign for a key change.
const keyChangeNamespace = "cairn-key-change@rvatechvisions.com"

const keyChangeFormat = "cairn-key-change/1"

// trustedRecoveryKeys are the recovery keys whose signature this box accepts
// on a key change, and on nothing else. Empty until both FIDO2 keys exist:
// Part B of the key card waits for the hardware. Held by
// TestNoRecoveryKeyIsTrustedYet.
var trustedRecoveryKeys = []string{}

// keyChange is the signed statement.
type keyChange struct {
	Format   string `json:"format"`
	Sequence int64  `json:"sequence"`
	SignedAt string `json:"signedAt"`
	Retire   string `json:"retire"`
	Trust    string `json:"trust"`
}

func parseKeys(lines []string) ([]ssh.PublicKey, error) {
	keys := make([]ssh.PublicKey, 0, len(lines))
	for _, line := range lines {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("a trusted key does not parse: %w", err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func holds(keys []ssh.PublicKey, key ssh.PublicKey) bool {
	for _, each := range keys {
		if bytes.Equal(each.Marshal(), key.Marshal()) {
			return true
		}
	}
	return false
}

// verifyKeyChange is the whole check. It returns the statement and the new
// signing key it trusts, or a refusal that names why and says nothing changed.
func verifyKeyChange(served *signedRelease, recovery, release []string, highestApplied int64) (keyChange, ssh.PublicKey, error) {
	var statement keyChange
	if served == nil || served.Manifest == "" || served.Signature == "" {
		return statement, nil, errors.New("REFUSED: unsigned: the portal served no signed key change. Nothing was changed")
	}
	recoveryKeys, err := parseKeys(recovery)
	if err != nil {
		return statement, nil, fmt.Errorf("REFUSED: %v. Nothing was changed", err)
	}
	if len(recoveryKeys) == 0 {
		return statement, nil, errors.New("REFUSED: this binary trusts no recovery key yet, so it accepts no key change. Nothing was changed")
	}
	releaseKeys, err := parseKeys(release)
	if err != nil {
		return statement, nil, fmt.Errorf("REFUSED: %v. Nothing was changed", err)
	}
	message, err := base64.StdEncoding.DecodeString(served.Manifest)
	if err != nil {
		return statement, nil, errors.New("REFUSED: the key change is not base64. Nothing was changed")
	}
	signer, err := verifySSHSig(served.Signature, keyChangeNamespace, message)
	if err != nil {
		return statement, nil, fmt.Errorf("REFUSED: mis-signed: %v. Nothing was changed", err)
	}
	if !holds(recoveryKeys, signer) {
		if holds(releaseKeys, signer) {
			return statement, nil, fmt.Errorf("REFUSED: signed by %s, the release signing key, which signs releases and never a key change. Nothing was changed", ssh.FingerprintSHA256(signer))
		}
		return statement, nil, fmt.Errorf("REFUSED: signed by %s, a key this box does not trust for key changes. Nothing was changed", ssh.FingerprintSHA256(signer))
	}
	if err := json.Unmarshal(message, &statement); err != nil {
		return statement, nil, fmt.Errorf("REFUSED: the signed key change does not parse: %v. Nothing was changed", err)
	}
	if statement.Format != keyChangeFormat {
		return statement, nil, fmt.Errorf("REFUSED: the signed key change is format %q, and this binary reads %q. Nothing was changed", statement.Format, keyChangeFormat)
	}
	if statement.Sequence <= highestApplied {
		return statement, nil, fmt.Errorf("REFUSED: stale: the signed key change is sequence %d, and this box has applied %d. Nothing was changed", statement.Sequence, highestApplied)
	}
	retiring := false
	for _, key := range releaseKeys {
		if ssh.FingerprintSHA256(key) == statement.Retire {
			retiring = true
		}
	}
	if !retiring {
		return statement, nil, fmt.Errorf("REFUSED: the key change retires %s, a key this box does not trust for releases. Nothing was changed", statement.Retire)
	}
	next, _, _, _, err := ssh.ParseAuthorizedKey([]byte(statement.Trust))
	if err != nil {
		return statement, nil, fmt.Errorf("REFUSED: the key the change would trust does not parse: %v. Nothing was changed", err)
	}
	if holds(recoveryKeys, next) {
		return statement, nil, errors.New("REFUSED: the key change would make a recovery key a release signing key, and a recovery key never signs a release. Nothing was changed")
	}
	return statement, next, nil
}
