package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// WO-1018-N62 item 1: the apply step's check of item 0c, the oldest-binary
// declaration, the ledger for the run report, and the portal as a source.
//
// Every case is driven through applyStaged or stageRelease on fixtures signed
// with a fixture key, as WO-1018-N60's were. Whether each fixture can express
// its case is said beside it.

// fakeGate is the portal at the moment before `current` moves.
type fakeGate struct {
	answer gateAnswer
	err    error
	calls  []aboutToApply
}

func (g *fakeGate) AboutToApply(attempt aboutToApply) (gateAnswer, error) {
	g.calls = append(g.calls, attempt)
	return g.answer, g.err
}

// offering is a portal that records the attempt and still offers served.
func offering(served *signedRelease) *fakeGate {
	return &fakeGate{answer: gateAnswer{Recorded: true, Offered: served}}
}

// stagedRelease stages sequence 2 and returns its source and key.
func stagedRelease(t *testing.T, store releaseStore) (*fakeSource, string) {
	t.Helper()
	source, public := scriptsRelease(t, 2, inThreeWeeks, map[string]string{"preflight.sh": "#!/bin/sh\necho two\n"})
	if staged, err := stageRelease(store, source, []string{public}, releaseNow); err != nil || staged.Outcome != stageStaged {
		t.Fatalf("stage gave %+v, %v", staged, err)
	}
	return source, public
}

func assertNotApplied(t *testing.T, store releaseStore, stillStaged bool) {
	t.Helper()
	if _, ok := pointerValue(t, store, "current"); ok {
		t.Fatal("current moved, and the portal had not said yes")
	}
	if _, ok := pointerValue(t, store, "trial"); ok {
		t.Fatal("a release went on trial without being applied")
	}
	if _, ok := pointerValue(t, store, "staged"); ok != stillStaged {
		t.Fatalf("staged is present %v, want %v", ok, stillStaged)
	}
}

// Capable: the gate answers held, the state a hold set between the end of one
// run and the start of the next leaves.
func TestAHoldSetAfterStagingStopsTheApply(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	_, public := stagedRelease(t, store)
	gate := &fakeGate{answer: gateAnswer{Recorded: true, Held: "This organization holds its appliance's updates."}}
	result, err := applyStaged(store, []string{public}, releaseNow.Add(24*time.Hour), gate)
	if err != nil || result.Outcome != applyHeld || !strings.Contains(result.Reason, "holds its appliance's updates") {
		t.Fatalf("a hold set after staging gave %+v, %v; want held, not applied", result, err)
	}
	assertNotApplied(t, store, true)
	if got := ledgerOutcomes(t, store); strings.Join(got, ",") != attemptHeld {
		t.Fatalf("the ledger holds %v, want %s", got, attemptHeld)
	}
	if len(gate.calls) != 1 || gate.calls[0].Sequence != 2 || len(gate.calls[0].AttemptID) != 36 {
		t.Fatalf("the apply declared %+v, want one declaration of release 2 with an attempt id", gate.calls)
	}
}

// Capable: the gate answers with a transport error, which is what a portal
// this box cannot reach gives signedRequest.
func TestAPortalUnreachableAtApplyAppliesNothing(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	_, public := stagedRelease(t, store)
	gate := &fakeGate{err: errors.New("reaching the portal: dial tcp: no route to host")}
	result, err := applyStaged(store, []string{public}, releaseNow.Add(24*time.Hour), gate)
	if err != nil || result.Outcome != applyNotApplied || !strings.Contains(result.Reason, "no route to host") {
		t.Fatalf("an unreachable portal at apply gave %+v, %v; want not applied", result, err)
	}
	assertNotApplied(t, store, true)
	if got := ledgerOutcomes(t, store); strings.Join(got, ",") != attemptUnreachable {
		t.Fatalf("the ledger holds %v, want %s", got, attemptUnreachable)
	}
}

// Capable: slice 1's rule that a box told the attempt was not recorded does
// not apply, with the portal's own sentence.
func TestAnAttemptThePortalDidNotRecordAppliesNothing(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	source, public := stagedRelease(t, store)
	gate := &fakeGate{answer: gateAnswer{Recorded: false, Said: "Cairn could not record the update attempt, so it must not be applied.", Offered: source.served}}
	result, err := applyStaged(store, []string{public}, releaseNow.Add(24*time.Hour), gate)
	if err != nil || result.Outcome != applyNotApplied || !strings.Contains(result.Reason, "could not record") {
		t.Fatalf("an unrecorded attempt gave %+v, %v; want not applied", result, err)
	}
	assertNotApplied(t, store, true)
}

// Capable: two signed releases, the staged one and a newer one the portal
// offers in its place.
func TestANewerOfferSupersedesTheStagedRelease(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	_, public := stagedRelease(t, store)
	newer, newerKey := scriptsRelease(t, 3, inThreeWeeks, map[string]string{"preflight.sh": "three"})
	result, err := applyStaged(store, []string{public, newerKey}, releaseNow.Add(24*time.Hour), offering(newer.served))
	if err != nil || result.Outcome != applySuperseded || !strings.Contains(result.Reason, "offers signed release 3 in place of staged release 2") {
		t.Fatalf("a newer offer gave %+v, %v; want superseded", result, err)
	}
	assertNotApplied(t, store, false)
	if got := ledgerOutcomes(t, store); strings.Join(got, ",") != attemptSupersede {
		t.Fatalf("the ledger holds %v, want %s", got, attemptSupersede)
	}
}

// Capable: the portal offering nothing at all is a different release from the
// one staged.
func TestAPortalOfferingNothingSupersedesTheStagedRelease(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	_, public := stagedRelease(t, store)
	result, err := applyStaged(store, []string{public}, releaseNow.Add(24*time.Hour), offering(nil))
	if err != nil || result.Outcome != applySuperseded || !strings.Contains(result.Reason, "offers no signed release") {
		t.Fatalf("a portal offering nothing gave %+v, %v; want superseded", result, err)
	}
	assertNotApplied(t, store, false)
}

// Capable: an offer signed by a key this box does not trust is the portal
// offering something it cannot prove, and changes nothing about the staged one.
func TestAnOfferThisBoxCannotVerifyAppliesNothing(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	_, public := stagedRelease(t, store)
	untrusted, _ := scriptsRelease(t, 3, inThreeWeeks, map[string]string{"preflight.sh": "three"})
	result, err := applyStaged(store, []string{public}, releaseNow.Add(24*time.Hour), offering(untrusted.served))
	if err != nil || result.Outcome != applyNotApplied || !strings.Contains(result.Reason, "cannot verify") {
		t.Fatalf("an unverifiable offer gave %+v, %v; want not applied", result, err)
	}
	assertNotApplied(t, store, true)
}

// Capable: a signed manifest naming an oldest binary above this binary's level.
func TestAReleaseNeedingANewerBinaryIsNotStaged(t *testing.T) {
	private, public := fixtureKey(t)
	manifest := releaseManifest{Format: releaseFormatScripts, Sequence: 2, SignedAt: releaseNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: inThreeWeeks.Format(time.RFC3339), OldestBinary: binaryReleaseLevel + 1}
	manifest.Binary.Digest = digestOf([]byte("binary"))
	manifest.Binary.Size = 6
	manifest.Binary.Commit = strings.Repeat("b", 40)
	content := []byte("needs more")
	manifest.Scripts = &releaseScripts{Commit: strings.Repeat("2", 40), Files: []releaseScript{{Path: "preflight.sh", Digest: digestOf(content), Size: int64(len(content))}}}
	message, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeSource{served: served(message, fixtureSign(t, private, releaseNamespace, message)), files: map[string][]byte{digestOf(content): content}}
	store := releaseStore{root: t.TempDir()}
	result, err := stageRelease(store, source, []string{public}, releaseNow)
	if err != nil || result.Outcome != stageRefused || !strings.Contains(result.Reason, "binary too old") {
		t.Fatalf("a release needing a newer binary gave %+v, %v; want refused, binary too old", result, err)
	}
	if _, ok := pointerValue(t, store, "staged"); ok {
		t.Fatal("a release needing a newer binary was staged")
	}
	// The binary path reads the same manifest without the check, because
	// installing the release's own binary is how a box meets it.
	if _, err := verifyRelease(source.served, []string{public}, releaseNow, 0); err != nil {
		t.Fatalf("the binary path refused a release for asking for a newer binary: %v", err)
	}
}

// Capable: the portal before its first signed release answers with no release
// field at all.
func TestNoSignedReleaseOfferedStagesNothingAndRecordsNothing(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	result, err := stageRelease(store, &fakeSource{}, nil, releaseNow)
	if err != nil || result.Outcome != stageNothingNewer || !strings.Contains(result.Reason, "offers no signed release") {
		t.Fatalf("no release offered gave %+v, %v; want nothing newer", result, err)
	}
	if got := ledgerOutcomes(t, store); len(got) != 0 {
		t.Fatalf("no release offered wrote attempts %v", got)
	}
}

func TestTheLedgerIsTheRunReportsList(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	empty, err := updateAttemptsJSON(store)
	if err != nil || empty != "[]" {
		t.Fatalf("an empty ledger printed %q, %v; want []", empty, err)
	}
	for i := 0; i < 55; i++ {
		if err := store.record(updateAttempt{Outcome: attemptRefused, Sequence: int64(i + 1), Reason: "fixture"}, releaseNow); err != nil {
			t.Fatal(err)
		}
	}
	listed, err := updateAttemptsJSON(store)
	if err != nil {
		t.Fatal(err)
	}
	var attempts []updateAttempt
	if err := json.Unmarshal([]byte(listed), &attempts); err != nil {
		t.Fatalf("the list did not parse: %v", err)
	}
	if len(attempts) != 50 || attempts[0].Sequence != 6 || attempts[49].Sequence != 55 {
		t.Fatalf("the list held %d entries from %d to %d, want the newest fifty, 6 to 55", len(attempts), attempts[0].Sequence, attempts[len(attempts)-1].Sequence)
	}
}

// The portal client against a server answering as the portal does: a hold is
// a 409 and its sentence, an offer is a 200 with the release, and the
// declaration travels in the signed query.
func TestThePortalClientReadsAHoldAnOfferAndTheDeclaration(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	offer := &signedRelease{Manifest: "bWFuaWZlc3Q=", Signature: "-----BEGIN SSH SIGNATURE-----"}
	var lastQuery string
	hold := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.RawQuery
		if r.Header.Get("Cairn-Signature") == "" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("content-type", "application/json")
		recorded := map[string]any{"recorded": true}
		if hold {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "This organization holds its appliance's updates.", "updateAttempt": recorded})
			return
		}
		body := map[string]any{"digest": strings.Repeat("a", 64), "commit": strings.Repeat("b", 40), "size": 6, "release": offer}
		if r.URL.Query().Get("update-attempt") != "" {
			body["updateAttempt"] = recorded
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	portal := portalRelease{portal: server.URL, fingerprint: "SHA256:fixture", private: private}

	answer, err := portal.AboutToApply(aboutToApply{AttemptID: "11111111-1111-4111-8111-111111111111", Sequence: 2, ToCommit: strings.Repeat("2", 40)})
	if err != nil || !answer.Recorded || answer.Offered == nil || answer.Offered.Manifest != offer.Manifest || answer.Held != "" {
		t.Fatalf("an offer read as %+v, %v", answer, err)
	}
	if !strings.Contains(lastQuery, "update-attempt=11111111-1111-4111-8111-111111111111") || !strings.Contains(lastQuery, "sequence=2") {
		t.Fatalf("the declaration was not in the query: %q", lastQuery)
	}

	hold = true
	answer, err = portal.AboutToApply(aboutToApply{AttemptID: "22222222-2222-4222-8222-222222222222", Sequence: 2})
	if err != nil || answer.Held != "This organization holds its appliance's updates." || !answer.Recorded {
		t.Fatalf("a hold read as %+v, %v", answer, err)
	}
	held, servedRelease, err := portal.Release()
	if err != nil || held == "" || servedRelease != nil {
		t.Fatalf("the stage step read a hold as %q, %+v, %v", held, servedRelease, err)
	}
}

// A portal that does not read the declaration answers with no updateAttempt,
// and that is not a yes.
func TestAnAnswerWithNoDeclarationIsNotRecorded(t *testing.T) {
	answer, err := readGateAnswer(http.StatusOK, []byte(`{"digest":"x","release":{"manifest":"bQ==","signature":"s"}}`))
	if err != nil || answer.Recorded || !strings.Contains(answer.Said, "did not read the declaration") {
		t.Fatalf("an answer with no updateAttempt read as %+v, %v; want not recorded", answer, err)
	}
	if _, err := readGateAnswer(http.StatusInternalServerError, []byte(`{"error":"down"}`)); err == nil {
		t.Fatal("a 500 read as an answer")
	}
}
