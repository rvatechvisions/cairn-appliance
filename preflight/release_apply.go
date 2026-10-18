package main

// Slice 6, box side, the parts WO-1018-N62 item 1 adds to WO-1018-N60's
// stage, apply and settle (release_scripts.go): the portal as the source a
// release is staged from, the check the apply step makes just before it moves
// `current`, the ledger the run report carries, and the oldest binary a
// release declares it runs on.
//
// ## The apply asks the portal first, and then asks it again
//
// The order author's ruling, WO-1018-N62 item 0c, 18 October 2026, on the
// builder's option (a): **the apply step asks the portal's signed manifest
// route again just before it moves `current`.** It is one signed request:
//
//   - it declares *about to apply* in its query, which the signature covers, so
//     the portal records the attempt before it answers. That is slice 1's rule,
//     *every applied update writes an audit row before the files move*;
//   - its answer is what the portal offers now. A hold set after the release
//     was staged is *held, not applied*; a different release now offered is
//     *superseded*; a portal this box cannot reach, or one that did not record
//     the attempt, means do not apply.
//
// A hold, an unreachable portal and an unrecorded attempt leave the release
// staged, to be tried again at the start of the next run. A superseded release
// is removed from staging, because the newer one is staged at the end of the
// same run. **Nothing here can move `current` without the portal having said
// yes, and the portal can never make a box run what the trusted key did not
// sign**: what it offers is verified with verifyRelease like anything else.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// binaryReleaseLevel is the reader level of this binary: what a release can
// ask of the binary that applies it. A release names the oldest it runs on as
// oldestBinary, and this binary refuses one that asks for more. WO-1018-N62
// item 1, the design's *a release declares the oldest binary it runs on, and a
// box whose binary is older refuses it and says why*.
//
// It is a number in the source, raised by hand in the commit that gives a
// binary something a release may come to rely on, because a commit stamp has
// no order a box could compare. **Its limit, stated:** a binary built before
// this field ignores it, so the declaration binds only binaries from this one
// on.
const binaryReleaseLevel = 1

// Outcomes the apply step adds, as the box prints them and as it records them.
const (
	applyHeld        = "held, not applied"
	applySuperseded  = "superseded"
	applyNotApplied  = "not applied"
	attemptHeld      = "held-not-applied"
	attemptSupersede = "superseded"
)

// aboutToApply is what the apply step declares to the portal.
type aboutToApply struct {
	AttemptID  string
	Sequence   int64
	FromCommit string
	ToCommit   string
}

// gateAnswer is the portal's answer to that declaration: whether it recorded
// the attempt, a hold's sentence if the organization holds its updates, and the
// signed release it offers now, if any.
type gateAnswer struct {
	Recorded bool
	Said     string
	Held     string
	Offered  *signedRelease
}

// applyGate is the portal, as the apply step sees it.
type applyGate interface {
	AboutToApply(attempt aboutToApply) (gateAnswer, error)
}

// gateApply is the check of WO-1018-N62 item 0c, between a staged release
// verifying on disk and `current` moving. It returns a result only where the
// release must not be applied; the zero result means go ahead.
func gateApply(store releaseStore, gate applyGate, trusted []string, now time.Time, staged int64, highest int64, toCommit string) (releaseResult, bool, error) {
	id, err := newAttemptID()
	if err != nil {
		return releaseResult{}, false, err
	}
	fromCommit := store.currentCommit()
	answer, err := gate.AboutToApply(aboutToApply{AttemptID: id, Sequence: staged, FromCommit: fromCommit, ToCommit: toCommit})
	keep := fmt.Sprintf("signed release %d was not applied and stays staged", staged)
	if err != nil {
		reason := fmt.Sprintf("could not reach the portal to declare the apply: %v, so %s", err, keep)
		return releaseResult{Outcome: applyNotApplied, Sequence: staged, Reason: reason}, true,
			store.record(updateAttempt{Outcome: attemptUnreachable, Sequence: staged, Reason: reason, FromCommit: fromCommit, ToCommit: toCommit}, now)
	}
	if !answer.Recorded {
		said := answer.Said
		if said == "" {
			said = "the portal did not say it recorded the attempt"
		}
		reason := fmt.Sprintf("%s, so %s", strings.TrimSuffix(said, "."), keep)
		return releaseResult{Outcome: applyNotApplied, Sequence: staged, Reason: reason}, true,
			store.record(updateAttempt{Outcome: attemptRefused, Sequence: staged, Reason: reason, FromCommit: fromCommit, ToCommit: toCommit}, now)
	}
	if answer.Held != "" {
		reason := fmt.Sprintf("%s So %s", answer.Held, keep)
		return releaseResult{Outcome: applyHeld, Sequence: staged, Reason: reason}, true,
			store.record(updateAttempt{Outcome: attemptHeld, Sequence: staged, Reason: reason, FromCommit: fromCommit, ToCommit: toCommit}, now)
	}
	offered := int64(0)
	if answer.Offered != nil {
		manifest, err := verifyRelease(answer.Offered, trusted, now, highest)
		if err != nil {
			reason := fmt.Sprintf("the portal now offers a release this box cannot verify (%s), so %s", strings.TrimSuffix(err.Error(), ". Nothing was installed"), keep)
			return releaseResult{Outcome: applyNotApplied, Sequence: staged, Reason: reason}, true,
				store.record(updateAttempt{Outcome: attemptRefused, Sequence: staged, Reason: reason, FromCommit: fromCommit, ToCommit: toCommit}, now)
		}
		offered = manifest.Sequence
	}
	if offered != staged {
		instead := "no signed release"
		if offered > 0 {
			instead = fmt.Sprintf("signed release %d", offered)
		}
		reason := fmt.Sprintf("the portal now offers %s in place of staged release %d, so it was not applied and is no longer staged", instead, staged)
		if err := removePointer(store.pointer("staged")); err != nil {
			return releaseResult{}, true, err
		}
		return releaseResult{Outcome: applySuperseded, Sequence: staged, Reason: reason}, true,
			store.record(updateAttempt{Outcome: attemptSupersede, Sequence: staged, Reason: reason, FromCommit: fromCommit, ToCommit: toCommit}, now)
	}
	return releaseResult{}, false, nil
}

// signedRequest makes a signed POST with no body and returns the status and
// what came back, so a caller can tell a hold (409) and nothing published
// (404) from a fault. signedFetch is this with every status but 200 an error.
func signedRequest(portal, path, fingerprint string, private ed25519.PrivateKey) (int, []byte, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return 0, nil, fmt.Errorf("generating a nonce: %w", err)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	signature := ed25519.Sign(private, canonicalBytes(http.MethodPost, path, fingerprint, timestamp, nonce, bodyHash(nil)))

	request, err := http.NewRequest(http.MethodPost, strings.TrimRight(portal, "/")+path, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Cairn-Appliance", fingerprint)
	request.Header.Set("Cairn-Timestamp", timestamp)
	request.Header.Set("Cairn-Nonce", nonce)
	request.Header.Set("Cairn-Signature", base64.StdEncoding.EncodeToString(signature))

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("reaching the portal: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return response.StatusCode, nil, fmt.Errorf("reading the portal's answer: %w", err)
	}
	return response.StatusCode, body, nil
}

// refusalWords is the portal's own sentence in a refusal body, or nothing.
func refusalWords(body []byte) string {
	var refusal struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &refusal)
	return refusal.Error
}

// portalRelease is the portal as stageRelease and applyStaged see it, over the
// signed channel the box already uses.
type portalRelease struct {
	portal      string
	fingerprint string
	private     ed25519.PrivateKey
}

// Release asks for the newest offered release. A hold is the portal's 409 and
// its sentence; nothing published, a 404, is no release offered. Anything else
// that is not a 200 is a fault, said with the portal's words where it gave any.
func (p portalRelease) Release() (string, *signedRelease, error) {
	status, body, err := signedRequest(p.portal, binaryManifestPath, p.fingerprint, p.private)
	if err != nil {
		return "", nil, err
	}
	switch status {
	case http.StatusOK:
		var served servedManifest
		if err := json.Unmarshal(body, &served); err != nil {
			return "", nil, fmt.Errorf("the manifest did not parse: %w", err)
		}
		return "", served.Release, nil
	case http.StatusConflict:
		return heldSentence(body), nil, nil
	case http.StatusNotFound:
		return "", nil, nil
	default:
		return "", nil, portalRefused(fmt.Errorf("refused (%d): %s", status, refusalWords(body)))
	}
}

func heldSentence(body []byte) string {
	if words := refusalWords(body); words != "" {
		return words
	}
	return "The portal says this appliance's organization holds its updates."
}

// Binary fetches the release's binary by its SHA-256, from the door -update
// already uses. Slice 7.
func (p portalRelease) Binary(digest string) ([]byte, error) {
	return signedFetch(p.portal, "/appliance/binary/"+digest, p.fingerprint, p.private)
}

// File fetches one listed file by its SHA-256.
func (p portalRelease) File(digest string) ([]byte, error) {
	status, body, err := signedRequest(p.portal, "/appliance/release/file/"+digest, p.fingerprint, p.private)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, portalRefused(fmt.Errorf("refused (%d): %s", status, refusalWords(body)))
	}
	return body, nil
}

// AboutToApply declares the apply in the manifest request's query and reads
// back whether the portal recorded it and what it offers now.
func (p portalRelease) AboutToApply(attempt aboutToApply) (gateAnswer, error) {
	query := url.Values{}
	query.Set("update-attempt", attempt.AttemptID)
	query.Set("sequence", strconv.FormatInt(attempt.Sequence, 10))
	if attempt.ToCommit != "" {
		query.Set("to", attempt.ToCommit)
	}
	if attempt.FromCommit != "" {
		query.Set("from", attempt.FromCommit)
	}
	status, body, err := signedRequest(p.portal, binaryManifestPath+"?"+query.Encode(), p.fingerprint, p.private)
	if err != nil {
		return gateAnswer{}, err
	}
	return readGateAnswer(status, body)
}

// readGateAnswer reads the portal's answer to a declared apply. An answer with
// no updateAttempt field comes from a portal that did not read the declaration,
// so it was not recorded, and is said as that rather than taken as a yes.
func readGateAnswer(status int, body []byte) (gateAnswer, error) {
	var answer struct {
		Error         string         `json:"error"`
		Release       *signedRelease `json:"release"`
		UpdateAttempt *struct {
			Recorded bool   `json:"recorded"`
			Said     string `json:"said"`
		} `json:"updateAttempt"`
	}
	if status == http.StatusOK || status == http.StatusConflict || status == http.StatusNotFound {
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&answer); err != nil {
			return gateAnswer{}, fmt.Errorf("the portal's answer did not parse: %w", err)
		}
	} else {
		return gateAnswer{}, portalRefused(fmt.Errorf("refused (%d): %s", status, refusalWords(body)))
	}
	result := gateAnswer{}
	if answer.UpdateAttempt == nil {
		result.Said = "the portal did not read the declaration, so it recorded no attempt"
	} else {
		result.Recorded = answer.UpdateAttempt.Recorded
		result.Said = answer.UpdateAttempt.Said
	}
	switch status {
	case http.StatusConflict:
		result.Held = heldSentence(body)
	case http.StatusOK:
		result.Offered = answer.Release
	}
	return result, nil
}

// updateAttemptsJSON is the newest entries of the ledger as the run report's
// updateAttempts list, oldest first, at most the fifty the portal reads. The
// portal keeps each attempt id once, so a report carrying an entry a previous
// report carried writes nothing twice; that is why every report may carry the
// newest fifty rather than tracking which were sent.
func updateAttemptsJSON(store releaseStore) (string, error) {
	attempts, err := store.ledger()
	if err != nil {
		return "", err
	}
	if len(attempts) > 50 {
		attempts = attempts[len(attempts)-50:]
	}
	if attempts == nil {
		attempts = []updateAttempt{}
	}
	out, err := json.Marshal(attempts)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// printRelease prints one step's result for whoever is reading the run.
func printRelease(step string, result releaseResult) {
	line := fmt.Sprintf("%s: %s", step, result.Outcome)
	if result.Reason != "" {
		line += ": " + result.Reason
	}
	fmt.Fprintln(os.Stdout, line)
}
