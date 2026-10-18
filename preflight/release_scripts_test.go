package main

// Slice 6, first half: scripts by signed manifest, on fixtures. WO-1018-N60
// item 1.
//
// **THE KEYS IN THIS FILE ARE TEST FIXTURES**, made by fixtureKey in
// release_test.go inside each test and gone when it ends. None is Jackie's.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// releaseOne is release-1.json as Jackie is signing it, byte for byte: 273
// bytes, no trailing newline, sha256 65fcf213…a36fe9e, the digest posted on
// the signing card (WO-1018-N58 item 3).
const releaseOne = `{"format":"cairn-release/1","sequence":1,"signedAt":"2026-10-18T02:29:09.600Z","expiresAt":"2026-11-08T00:00:00.000Z","binary":{"digest":"e325f1ccaa532aa07de287fa36e83550d8933405b68edde4b7e360e065373d59","size":19801334,"commit":"38910a02fc5963567e2d366f7f99cf703708b2b5"}}`

const releaseOneDigest = "65fcf21376887a704e0739e9a0389f9cedc4cfe8848108b99c5287476a36fe9e"

// portalReleaseTwo is testdata/release-2-from-portal.json, written by the
// portal's own src/cli/write-release-manifest.ts (WO-1018-N61 item 4a). Its
// digest is pinned here and in the portal's release-manifest-format2.test.ts,
// so the two repositories hold one set of bytes between them.
const portalReleaseTwoDigest = "384d14f6a67dd018625c8daa5f4668daa18e3952ce9c99f6e87a6c6b66c3766c"

func TestReadsAScriptsManifestThePortalWrote(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "release-2-from-portal.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != portalReleaseTwoDigest {
		t.Fatalf("the fixture is not the bytes the portal wrote: sha256 %x", sum)
	}
	private, public := fixtureKey(t)
	manifest, err := verifyRelease(served(raw, fixtureSign(t, private, releaseNamespace, raw)), []string{public}, releaseNow, 1)
	if err != nil {
		t.Fatalf("the box refused a manifest the portal wrote: %v", err)
	}
	if manifest.Format != releaseFormatScripts || manifest.Sequence != 2 || manifest.Scripts == nil {
		t.Fatalf("the portal's manifest read as %+v", manifest)
	}
	if manifest.Scripts.Commit != "170a0fe000000000000000000000000000000000" || len(manifest.Scripts.Files) != 2 {
		t.Fatalf("the scripts entry read as %+v", manifest.Scripts)
	}
	consent, preflight := manifest.Scripts.Files[0], manifest.Scripts.Files[1]
	if consent.Path != "lib/consent.sh" || consent.Size != 8 || consent.Digest != digestOf([]byte("consent\n")) {
		t.Fatalf("lib/consent.sh read as %+v", consent)
	}
	if preflight.Path != "preflight.sh" || preflight.Size != 33 || preflight.Digest != digestOf([]byte("#!/usr/bin/env bash\necho fixture\n")) {
		t.Fatalf("preflight.sh read as %+v", preflight)
	}
	if manifest.Binary.Digest != "e325f1ccaa532aa07de287fa36e83550d8933405b68edde4b7e360e065373d59" || manifest.Binary.Size != 19801334 {
		t.Fatalf("the binary entry read as %+v", manifest.Binary)
	}
}

type fakeSource struct {
	held         string
	served       *signedRelease
	files        map[string][]byte
	err          error
	releaseCalls int
}

func (f *fakeSource) Release() (string, *signedRelease, error) {
	f.releaseCalls++
	return f.held, f.served, f.err
}

func (f *fakeSource) File(digest string) ([]byte, error) {
	content, ok := f.files[digest]
	if !ok {
		return nil, errors.New("not served")
	}
	return content, nil
}

// scriptsRelease builds a signed cairn-release/2 manifest listing files, and a
// source serving it and them.
func scriptsRelease(t *testing.T, sequence int64, expires time.Time, files map[string]string) (*fakeSource, string) {
	t.Helper()
	private, public := fixtureKey(t)
	manifest := releaseManifest{Format: releaseFormatScripts, Sequence: sequence, SignedAt: releaseNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339)}
	manifest.Binary.Digest = digestOf([]byte("binary"))
	manifest.Binary.Size = 6
	manifest.Binary.Commit = strings.Repeat("b", 40)
	manifest.Scripts = &releaseScripts{Commit: strings.Repeat(strconv.FormatInt(sequence%10, 10), 40)}
	source := &fakeSource{files: map[string][]byte{}}
	for _, name := range sortedKeys(files) {
		content := []byte(files[name])
		manifest.Scripts.Files = append(manifest.Scripts.Files, releaseScript{Path: name, Digest: digestOf(content), Size: int64(len(content))})
		source.files[digestOf(content)] = content
	}
	message, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	source.served = served(message, fixtureSign(t, private, releaseNamespace, message))
	return source, public
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func ledgerOutcomes(t *testing.T, store releaseStore) []string {
	t.Helper()
	attempts, err := store.ledger()
	if err != nil {
		t.Fatal(err)
	}
	var outcomes []string
	for _, attempt := range attempts {
		if len(attempt.AttemptID) != 36 || attempt.BoxTime == "" {
			t.Fatalf("a ledger entry is not in the portal's shape: %+v", attempt)
		}
		outcomes = append(outcomes, attempt.Outcome)
	}
	return outcomes
}

func pointerValue(t *testing.T, store releaseStore, name string) (int64, bool) {
	t.Helper()
	value, ok, err := readPointer(store.pointer(name))
	if err != nil {
		t.Fatal(err)
	}
	return value, ok
}

var inThreeWeeks = releaseNow.Add(21 * 24 * time.Hour)

func TestReleaseOneReadsAsItDidBeforeSlice6(t *testing.T) {
	sum := sha256.Sum256([]byte(releaseOne))
	if hex.EncodeToString(sum[:]) != releaseOneDigest || len(releaseOne) != 273 {
		t.Fatalf("the literal is not release-1.json: %d bytes, sha256 %x", len(releaseOne), sum)
	}
	private, public := fixtureKey(t)
	release := served([]byte(releaseOne), fixtureSign(t, private, releaseNamespace, []byte(releaseOne)))
	manifest, err := verifyRelease(release, []string{public}, releaseNow, 0)
	if err != nil {
		t.Fatalf("release 1's bytes no longer verify: %v", err)
	}
	if manifest.Format != releaseFormat || manifest.Scripts != nil || manifest.Sequence != 1 || manifest.Binary.Digest != "e325f1ccaa532aa07de287fa36e83550d8933405b68edde4b7e360e065373d59" || manifest.Binary.Size != 19801334 {
		t.Fatalf("release 1 reads differently: %+v", manifest)
	}
	store := releaseStore{root: t.TempDir()}
	result, err := stageRelease(store, &fakeSource{served: release}, []string{public}, releaseNow)
	if err != nil || result.Outcome != stageBinaryOnly {
		t.Fatalf("release 1 at the stage step gave %+v, %v; want binary only", result, err)
	}
	if _, ok := pointerValue(t, store, "staged"); ok {
		t.Fatal("release 1 staged something")
	}
}

func TestStagesAppliesAndConfirmsAScriptsRelease(t *testing.T) {
	source, public := scriptsRelease(t, 2, inThreeWeeks, map[string]string{"preflight.sh": "#!/bin/sh\necho two\n", "lib/consent.sh": "consent\n"})
	store := releaseStore{root: t.TempDir()}
	staged, err := stageRelease(store, source, []string{public}, releaseNow)
	if err != nil || staged.Outcome != stageStaged || staged.Sequence != 2 {
		t.Fatalf("stage gave %+v, %v", staged, err)
	}
	if _, ok := pointerValue(t, store, "current"); ok {
		t.Fatal("staging moved current; only the next run's apply may")
	}
	content, err := os.ReadFile(filepath.Join(store.dir(2), "lib", "consent.sh"))
	if err != nil || string(content) != "consent\n" {
		t.Fatalf("the staged file reads %q, %v", content, err)
	}
	applied, err := applyStaged(store, []string{public}, releaseNow.Add(24*time.Hour))
	if err != nil || applied.Outcome != applyOnTrial {
		t.Fatalf("apply gave %+v, %v", applied, err)
	}
	if current, _ := pointerValue(t, store, "current"); current != 2 {
		t.Fatalf("current names %d, want 2", current)
	}
	settled, err := settleRun(store, false, "", releaseNow.Add(25*time.Hour))
	if err != nil || settled.Outcome != settleApplied {
		t.Fatalf("settle gave %+v, %v", settled, err)
	}
	if applied, _ := pointerValue(t, store, "applied"); applied != 2 {
		t.Fatalf("applied names %d, want 2", applied)
	}
	if got := ledgerOutcomes(t, store); strings.Join(got, ",") != "applied" {
		t.Fatalf("the ledger holds %v, want applied", got)
	}
}

func TestRefusesABadSignature(t *testing.T) {
	source, _ := scriptsRelease(t, 2, inThreeWeeks, map[string]string{"preflight.sh": "x"})
	_, someoneElse := fixtureKey(t)
	store := releaseStore{root: t.TempDir()}
	result, err := stageRelease(store, source, []string{someoneElse}, releaseNow)
	if err != nil || result.Outcome != stageRefused || !strings.Contains(result.Reason, "a key this box does not trust") {
		t.Fatalf("a release signed by an untrusted key gave %+v, %v", result, err)
	}
	if _, ok := pointerValue(t, store, "staged"); ok {
		t.Fatal("a refused release was staged")
	}
	if got := ledgerOutcomes(t, store); strings.Join(got, ",") != "refused" {
		t.Fatalf("the ledger holds %v, want refused", got)
	}
}

func TestRefusesAScriptWhoseDigestDiffers(t *testing.T) {
	source, public := scriptsRelease(t, 2, inThreeWeeks, map[string]string{"preflight.sh": "the signed bytes"})
	for digest := range source.files {
		source.files[digest] = []byte("other bytes, same len")[:len("the signed bytes")]
	}
	store := releaseStore{root: t.TempDir()}
	result, err := stageRelease(store, source, []string{public}, releaseNow)
	if err != nil || result.Outcome != stageRefused || !strings.Contains(result.Reason, "hashes to") {
		t.Fatalf("a script that differs from its manifest gave %+v, %v", result, err)
	}
	if _, err := os.Stat(store.dir(2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused release left a directory: %v", err)
	}
	if _, err := os.Stat(store.dir(2) + ".incoming"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused release left its staging directory: %v", err)
	}
	if got := ledgerOutcomes(t, store); strings.Join(got, ",") != "refused" {
		t.Fatalf("the ledger holds %v, want refused", got)
	}
}

func TestRefusesADowngrade(t *testing.T) {
	source, public := scriptsRelease(t, 4, inThreeWeeks, map[string]string{"preflight.sh": "x"})
	store := releaseStore{root: t.TempDir()}
	if err := writePointer(store.pointer("applied"), 5); err != nil {
		t.Fatal(err)
	}
	result, err := stageRelease(store, source, []string{public}, releaseNow)
	if err != nil || result.Outcome != stageRefused || !strings.Contains(result.Reason, "REFUSED: stale") {
		t.Fatalf("sequence 4 on a box at 5 gave %+v, %v; want REFUSED: stale", result, err)
	}
	if _, ok := pointerValue(t, store, "staged"); ok {
		t.Fatal("a downgrade was staged")
	}
}

func TestRefusesAnExpiredManifest(t *testing.T) {
	source, public := scriptsRelease(t, 2, releaseNow.Add(-time.Minute), map[string]string{"preflight.sh": "x"})
	store := releaseStore{root: t.TempDir()}
	result, err := stageRelease(store, source, []string{public}, releaseNow)
	if err != nil || result.Outcome != stageRefused || !strings.Contains(result.Reason, "REFUSED: expired") {
		t.Fatalf("an expired manifest gave %+v, %v; want REFUSED: expired", result, err)
	}
	if got := ledgerOutcomes(t, store); strings.Join(got, ",") != "refused" {
		t.Fatalf("the ledger holds %v, want refused", got)
	}
}

func TestRollsBackWhenTheRunFailsOnNewScripts(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	first, public := scriptsRelease(t, 2, inThreeWeeks, map[string]string{"preflight.sh": "two"})
	if _, err := stageRelease(store, first, []string{public}, releaseNow); err != nil {
		t.Fatal(err)
	}
	if _, err := applyStaged(store, []string{public}, releaseNow); err != nil {
		t.Fatal(err)
	}
	if _, err := settleRun(store, false, "", releaseNow); err != nil {
		t.Fatal(err)
	}
	second, secondKey := scriptsRelease(t, 3, inThreeWeeks, map[string]string{"preflight.sh": "three, broken"})
	trusted := []string{public, secondKey}
	if _, err := stageRelease(store, second, trusted, releaseNow); err != nil {
		t.Fatal(err)
	}
	if result, err := applyStaged(store, trusted, releaseNow); err != nil || result.Outcome != applyOnTrial {
		t.Fatalf("apply of 3 gave %+v, %v", result, err)
	}
	result, err := settleRun(store, true, "preflight.sh exited before its first capability", releaseNow)
	if err != nil || result.Outcome != settleRolledBack || !strings.Contains(result.Reason, "moved back to signed release 2") {
		t.Fatalf("a failed run on 3 gave %+v, %v", result, err)
	}
	if current, _ := pointerValue(t, store, "current"); current != 2 {
		t.Fatalf("current names %d after the move back, want 2", current)
	}
	if applied, _ := pointerValue(t, store, "applied"); applied != 2 {
		t.Fatalf("applied names %d after the move back, want 2", applied)
	}
	again, err := stageRelease(store, second, trusted, releaseNow)
	if err != nil || again.Outcome != stageNothingNewer || !strings.Contains(again.Reason, "rolled back here") {
		t.Fatalf("staging the rolled-back release again gave %+v, %v", again, err)
	}
	if got := ledgerOutcomes(t, store); strings.Join(got, ",") != "applied,rolled-back" {
		t.Fatalf("the ledger holds %v, want applied,rolled-back", got)
	}
}

func TestAnUnsettledTrialIsMovedBackAtTheNextApply(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	source, public := scriptsRelease(t, 2, inThreeWeeks, map[string]string{"preflight.sh": "two"})
	if _, err := stageRelease(store, source, []string{public}, releaseNow); err != nil {
		t.Fatal(err)
	}
	if _, err := applyStaged(store, []string{public}, releaseNow); err != nil {
		t.Fatal(err)
	}
	result, err := applyStaged(store, []string{public}, releaseNow.Add(24*time.Hour))
	if err != nil || result.Outcome != applyNothing {
		t.Fatalf("the next apply gave %+v, %v", result, err)
	}
	if _, ok := pointerValue(t, store, "current"); ok {
		t.Fatal("a trial whose run never finished is still current")
	}
	if got := ledgerOutcomes(t, store); strings.Join(got, ",") != "rolled-back" {
		t.Fatalf("the ledger holds %v, want rolled-back", got)
	}
}

func TestAHeldBoxChecksAndAppliesNothing(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	source, public := scriptsRelease(t, 2, inThreeWeeks, map[string]string{"preflight.sh": "two"})
	source.held = "This organization holds its appliance's updates."
	result, err := stageRelease(store, source, []string{public}, releaseNow)
	if err != nil || result.Outcome != stageHeld || result.Reason != source.held {
		t.Fatalf("a held box gave %+v, %v; want held with the portal's sentence", result, err)
	}
	if source.releaseCalls != 1 {
		t.Fatalf("a held box asked the portal %d times, want once: it still checks", source.releaseCalls)
	}
	if _, ok := pointerValue(t, store, "staged"); ok {
		t.Fatal("a held box staged a release")
	}
	if applied, err := applyStaged(store, []string{public}, releaseNow); err != nil || applied.Outcome != applyNothing {
		t.Fatalf("a held box's apply gave %+v, %v", applied, err)
	}
	if got := ledgerOutcomes(t, store); len(got) != 0 {
		t.Fatalf("a hold wrote attempts %v, and none of the five outcomes is a hold", got)
	}
}

func TestRefusesAStagedFileChangedBeforeApply(t *testing.T) {
	store := releaseStore{root: t.TempDir()}
	source, public := scriptsRelease(t, 2, inThreeWeeks, map[string]string{"preflight.sh": "two"})
	if _, err := stageRelease(store, source, []string{public}, releaseNow); err != nil {
		t.Fatal(err)
	}
	// The same length as the staged "two", so only its digest says it changed.
	// A tamper of another length would pass a check that needed both to
	// differ, which the first plant of this case showed.
	if err := os.WriteFile(filepath.Join(store.dir(2), "preflight.sh"), []byte("owt"), 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := applyStaged(store, []string{public}, releaseNow)
	if err != nil || result.Outcome != applyRefused || !strings.Contains(result.Reason, "changed after it was staged") {
		t.Fatalf("a staged file changed overnight gave %+v, %v", result, err)
	}
	if _, ok := pointerValue(t, store, "current"); ok {
		t.Fatal("a changed staged release became current")
	}
}

func TestRefusesAPathThatIsNotPlainlyRelative(t *testing.T) {
	for _, bad := range []string{"../escape.sh", "/etc/passwd", "a/../../b", "a\\b.sh", "./x.sh"} {
		err := validScripts(&releaseScripts{Commit: strings.Repeat("a", 40), Files: []releaseScript{{Path: bad, Digest: strings.Repeat("0", 64), Size: 1}}})
		if err == nil || !strings.Contains(err.Error(), "not plainly relative") {
			t.Fatalf("the path %q gave %v, want a refusal", bad, err)
		}
	}
}

func TestRefusesFormatOneNamingScripts(t *testing.T) {
	private, public := fixtureKey(t)
	manifest := releaseManifest{Format: releaseFormat, Sequence: 2, ExpiresAt: inThreeWeeks.Format(time.RFC3339), Scripts: &releaseScripts{Commit: strings.Repeat("a", 40), Files: []releaseScript{{Path: "x.sh", Digest: strings.Repeat("0", 64)}}}}
	message, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyRelease(served(message, fixtureSign(t, private, releaseNamespace, message)), []string{public}, releaseNow, 0)
	if err == nil || !strings.Contains(err.Error(), "names scripts") {
		t.Fatalf("a cairn-release/1 manifest naming scripts gave %v, want a refusal", err)
	}
}
