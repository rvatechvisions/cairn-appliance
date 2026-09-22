package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Talking to the portal: enrolment, and the signed credential fetch.
//
// THE BINARY SIGNS AND SENDS. Never a shell. The bytes that must be identical
// on both ends are assembled here, once, from the same values that go on the
// wire -- a shell pipeline assembling them is how `\s` becomes `s` and a
// signature fails for a reason nobody can see.
//
// The canonicalisation is APPLIANCE-STAGE-3.md and the portal's verifier is
// src/collector/signed-request.ts. This file is the other half of that, and
// the two are meant to be read side by side.

// signingDomain is line one, and it carries a version.
//
// Without a domain separator a signature over some other protocol's bytes
// could be replayed here. The version means a later change to the line list
// cannot be confused with this one.
const signingDomain = "CAIRN-APPLIANCE-v1"

// keyPath is where the appliance's private half lives.
//
// A variable rather than a constant so the binary can be exercised from a
// workstation. The DEFAULT is the appliance path and nothing changes it in
// normal use -- the flag exists so the cross-implementation check can run
// somewhere that is not an appliance, which is the only place it can run
// before there is an appliance.
var keyPath = "/etc/cairn-appliance/appliance.key"

// fingerprintPath is where the box remembers what it enrolled as.
//
// **Not a secret.** It is a hash of the public half, and it is the value a
// person compares against the card. Writing it means a later run does not
// have to be told again -- and a run that has to be told a thing it already
// established is a run somebody can get wrong.
func fingerprintPath() string {
	return filepath.Join(filepath.Dir(keyPath), "appliance.fingerprint")
}

// storedFingerprint returns what this box enrolled as, if it has.
func storedFingerprint() string {
	value, err := os.ReadFile(fingerprintPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(value))
}

// canonicalBytes builds the seven lines, joined with a newline, no trailing
// newline.
//
// SEVEN ALWAYS. A field that disappears when it is empty is a
// canonicalisation ambiguity, and it is the classic way two implementations of
// one spec disagree: the sender writes six lines, the verifier expects seven,
// and the mismatch presents as a bad key.
func canonicalBytes(method, path, fingerprint, timestamp, nonce, bodySHA string) []byte {
	return []byte(strings.Join([]string{
		signingDomain,
		method,
		path,
		fingerprint,
		timestamp,
		nonce,
		bodySHA,
	}, "\n"))
}

// bodyHash is the SHA-256 of the body, hex, always.
//
// An empty body hashes the empty string rather than being omitted or standing
// as a placeholder.
func bodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// loadOrCreateKey returns the appliance's private key, generating one the
// first time.
//
// THE PRIVATE HALF NEVER LEAVES THE BOX and the portal has never held it. It
// is written 0600 under a directory this binary does not create with looser
// permissions.
func loadOrCreateKey() (ed25519.PrivateKey, error) {
	existing, err := os.ReadFile(keyPath)
	if err == nil {
		block, _ := pem.Decode(existing)
		if block == nil {
			return nil, fmt.Errorf("%s holds no PEM block", keyPath)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", keyPath, err)
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s is not an ed25519 key", keyPath)
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", keyPath, err)
	}

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating a key: %w", err)
	}

	encoded, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, fmt.Errorf("encoding the key: %w", err)
	}

	if err := os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}),
		0o600); err != nil {
		return nil, fmt.Errorf("writing %s: %w", keyPath, err)
	}

	return private, nil
}

// publicPEM is the SPKI form the portal stores and verifies against.
func publicPEM(private ed25519.PrivateKey) (string, error) {
	encoded, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		return "", fmt.Errorf("encoding the public half: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})), nil
}

// enrol redeems a registration key and returns the fingerprint the portal
// bound.
//
// The registration key is passed as an argument and is never written to disk,
// never logged, and never put in a file this binary leaves behind.
func enrol(portal, registrationKey string, private ed25519.PrivateKey) (string, error) {
	public, err := publicPEM(private)
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(map[string]string{
		"key":       registrationKey,
		"publicKey": public,
	})
	if err != nil {
		return "", err
	}

	response, err := http.Post(
		strings.TrimRight(portal, "/")+"/appliance/enrol",
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil {
		return "", fmt.Errorf("reaching the portal: %w", err)
	}
	defer response.Body.Close()

	body, _ := io.ReadAll(response.Body)

	if response.StatusCode != http.StatusOK {
		// The portal does not distinguish unknown, already-redeemed and
		// revoked, deliberately. Neither does this.
		return "", fmt.Errorf("enrolment refused (%d): %s", response.StatusCode, strings.TrimSpace(string(body)))
	}

	var answer struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return "", fmt.Errorf("the portal's answer did not parse: %w", err)
	}
	if answer.Fingerprint == "" {
		return "", fmt.Errorf("the portal returned no fingerprint")
	}

	// Remembered beside the key, 0644: it is a hash of a public key and the
	// thing a person is asked to compare. A failure to write it is reported
	// rather than swallowed -- a later run would otherwise ask for a value
	// this one already had.
	if err := os.WriteFile(fingerprintPath(), []byte(answer.Fingerprint+"\n"), 0o644); err != nil {
		return answer.Fingerprint, fmt.Errorf("enrolled, but could not record the fingerprint: %w", err)
	}

	return answer.Fingerprint, nil
}

// fetchCredential signs the seven lines and asks for the connection's
// credential.
//
// THIS REQUEST CARRIES NO BODY. The signed bytes hash an empty one, so a body
// on the wire would be something added after signing -- and the portal refuses
// it before verification for exactly that reason.
// directoryCredential is everything the portal knows about how to reach a
// customer's directory, and it is ALL OF IT.
//
// **The portal is the only source of these four.** They travel together
// because they are one fact: a principal and a password are unusable without
// knowing which realm they belong to and which host to present them to, and
// splitting them puts half the answer in a settings file on the box -- the
// half nobody updates when a client renames a domain controller.
//
// Realm and Controller are EMPTY rather than absent when the portal has none.
// A connection saved before those columns existed answers without them, and an
// empty string here is what lets the caller tell "the portal did not say" from
// "the portal said this".
type directoryCredential struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Realm      string `json:"realm"`
	Controller string `json:"controller"`
}

func fetchCredential(portal, fingerprint string, private ed25519.PrivateKey) (directoryCredential, error) {
	const path = "/appliance/credential"

	var empty directoryCredential

	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return empty, fmt.Errorf("generating a nonce: %w", err)
	}

	// RFC 3339 in UTC, second precision, which is what the verifier parses.
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	signature := ed25519.Sign(private, canonicalBytes(
		http.MethodPost, path, fingerprint, timestamp, nonce, bodyHash(nil),
	))

	request, err := http.NewRequest(http.MethodPost, strings.TrimRight(portal, "/")+path, nil)
	if err != nil {
		return empty, err
	}
	request.Header.Set("Cairn-Appliance", fingerprint)
	request.Header.Set("Cairn-Timestamp", timestamp)
	request.Header.Set("Cairn-Nonce", nonce)
	request.Header.Set("Cairn-Signature", base64.StdEncoding.EncodeToString(signature))

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return empty, fmt.Errorf("reaching the portal: %w", err)
	}
	defer response.Body.Close()

	body, _ := io.ReadAll(response.Body)

	if response.StatusCode != http.StatusOK {
		// The clock-skew refusal is the one that names its cause, and it is
		// passed through verbatim: a misconfigured clock presenting as a
		// crypto failure is a support call nobody can solve.
		var refusal struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &refusal)
		if refusal.Error != "" {
			return empty, fmt.Errorf("refused (%d): %s", response.StatusCode, refusal.Error)
		}
		return empty, fmt.Errorf("refused (%d)", response.StatusCode)
	}

	var credential directoryCredential
	if err := json.Unmarshal(body, &credential); err != nil {
		return empty, fmt.Errorf("the portal's answer did not parse: %w", err)
	}

	return credential, nil
}

// runReportPath and runReportContentType name the other door.
//
// **The media type is not decoration.** The portal registers a parser for this
// one string so that one route sees the bytes as they arrived; everything else
// goes on being parsed as it was. A report sent as application/json reaches a
// handler that has an object and not the bytes the signature covers, and the
// portal refuses it rather than hashing a re-serialisation -- which is exactly
// where two implementations of one spec diverge.
const runReportPath = "/appliance/run"
const runReportContentType = "application/vnd.cairn.run+json"

// reportRun posts what a run reached.
//
// **The bytes are sent exactly as they were signed.** The report arrives here
// already serialised, from the caller, and is neither parsed nor re-encoded on
// the way through: a report this binary re-serialised would be signed over one
// spelling and sent as another.
func reportRun(portal, fingerprint string, private ed25519.PrivateKey, report []byte) error {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("generating a nonce: %w", err)
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	signature := ed25519.Sign(private, canonicalBytes(
		http.MethodPost, runReportPath, fingerprint, timestamp, nonce, bodyHash(report),
	))

	request, err := http.NewRequest(
		http.MethodPost,
		strings.TrimRight(portal, "/")+runReportPath,
		bytes.NewReader(report),
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", runReportContentType)
	request.Header.Set("Cairn-Appliance", fingerprint)
	request.Header.Set("Cairn-Timestamp", timestamp)
	request.Header.Set("Cairn-Nonce", nonce)
	request.Header.Set("Cairn-Signature", base64.StdEncoding.EncodeToString(signature))

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("reaching the portal: %w", err)
	}
	defer response.Body.Close()

	body, _ := io.ReadAll(response.Body)

	if response.StatusCode != http.StatusAccepted {
		var refusal struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &refusal)
		if refusal.Error != "" {
			return fmt.Errorf("refused (%d): %s", response.StatusCode, refusal.Error)
		}
		return fmt.Errorf("refused (%d)", response.StatusCode)
	}

	return nil
}

// assertSigningKey is the guard that would catch a signature this binary
// cannot verify against its own public half.
//
// It is here rather than in a test because the failure it catches is a build
// that produced a binary whose crypto does not round-trip -- and a test on the
// workstation proves that about the workstation.
func assertSigningKey(private ed25519.PrivateKey) error {
	sample := canonicalBytes("POST", "/x", "f", "t", "n", bodyHash(nil))
	signature := ed25519.Sign(private, sample)

	public, ok := private.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("the key's public half is not ed25519")
	}
	if !ed25519.Verify(public, sample, signature) {
		return fmt.Errorf("this binary cannot verify what it just signed")
	}

	// Named so the signature is over the same hash the portal uses.
	_ = crypto.Hash(0)
	return nil
}

// emitAgreementFixture prints, as JSON, everything the portal needs to
// verify a signature this binary produced.
//
// **It exists because the sender and the verifier are two implementations of
// one spec, and that is the thing two implementations get wrong.** The
// portal's tests prove its verifier against Node's ed25519; they cannot
// prove it against THIS, which assembles the same seven lines in another
// language with its own idea of string joining and its own base64.
//
// The output is committed as a fixture and asserted by the portal suite, so
// the agreement is checked on every run rather than the day an appliance is
// first plugged in. **The bytes come from the thing being tested**, never
// retyped: a fixture written by hand agrees with the author's recollection.
func emitAgreementFixture(private ed25519.PrivateKey) error {
	public, err := publicPEM(private)
	if err != nil {
		return err
	}

	// Fixed values, so the fixture is reproducible and a change to it is a
	// change somebody made rather than a new random run.
	const (
		method      = "POST"
		path        = "/appliance/credential?tenant=lab&x=%20a"
		fingerprint = "0123456789abcdef0123456789abcdef"
		timestamp   = "2026-09-21T12:00:00Z"
		nonce       = "YWJjZGVmZ2hpamtsbW5vcA=="
	)

	body := []byte("")
	canonical := canonicalBytes(method, path, fingerprint, timestamp, nonce, bodyHash(body))
	signature := ed25519.Sign(private, canonical)

	out, err := json.MarshalIndent(map[string]any{
		"note": "emitted by the appliance binary; never retyped",
		"method": method,
		"path": path,
		"fingerprint": fingerprint,
		"timestamp": timestamp,
		"nonce": nonce,
		"bodySha256": bodyHash(body),
		"canonical": string(canonical),
		"signatureBase64": base64.StdEncoding.EncodeToString(signature),
		"publicKeyPem": public,
	}, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(out))
	return nil
}
