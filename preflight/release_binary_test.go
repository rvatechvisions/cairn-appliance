package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Slice 7, WO-1018-N63 item 1: the binary onto the same signed path. A release
// lists a binary and scripts, the box stages both into the release's own
// directory, and one move of `current` changes both, forward or back.
//
// Whether each fixture can express its case is said beside it.

// storeWithInstalled is a release store whose installed binary is content.
func storeWithInstalled(t *testing.T, content []byte) releaseStore {
	t.Helper()
	dir := t.TempDir()
	installed := filepath.Join(dir, "installed-preflight")
	if err := os.WriteFile(installed, content, 0o700); err != nil {
		t.Fatal(err)
	}
	return releaseStore{root: filepath.Join(dir, "releases"), installed: installed}
}

// releaseWith builds a signed cairn-release/2 manifest listing binary and
// files, with oldest as its oldestBinary, and a source serving all of them.
func releaseWith(t *testing.T, sequence int64, binary []byte, oldest int64, files map[string]string) (*fakeSource, string) {
	t.Helper()
	private, public := fixtureKey(t)
	manifest := releaseManifest{Format: releaseFormatScripts, Sequence: sequence, SignedAt: releaseNow.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: inThreeWeeks.Format(time.RFC3339), OldestBinary: oldest}
	manifest.Binary.Digest = digestOf(binary)
	manifest.Binary.Size = int64(len(binary))
	manifest.Binary.Commit = strings.Repeat("c", 40)
	manifest.Scripts = &releaseScripts{Commit: strings.Repeat(strconv.FormatInt(sequence%10, 10), 40)}
	source := &fakeSource{files: map[string][]byte{}, binaries: map[string][]byte{digestOf(binary): binary}}
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

func stagedBinary(t *testing.T, store releaseStore, sequence int64) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(store.dir(sequence), filepath.FromSlash(releaseBinaryPath)))
	if err != nil {
		t.Fatalf("release %d holds no binary: %v", sequence, err)
	}
	return content
}

// Capable: a release whose binary differs from the installed one, so the box
// must fetch it, stage it beside the scripts, and move both together.
func TestABinaryAndItsScriptsApplyAsOneRelease(t *testing.T) {
	store := storeWithInstalled(t, []byte("the binary a person installed"))
	source, public := releaseWith(t, 2, []byte("release two's binary"), 0, map[string]string{"preflight.sh": "#!/bin/sh\necho two\n"})
	staged, err := stageRelease(store, source, []string{public}, releaseNow)
	if err != nil || staged.Outcome != stageStaged || !strings.Contains(staged.Reason, "its own binary") {
		t.Fatalf("stage gave %+v, %v", staged, err)
	}
	if source.binaryCalls != 1 || string(stagedBinary(t, store, 2)) != "release two's binary" {
		t.Fatalf("the binary was fetched %d times and staged as %q", source.binaryCalls, stagedBinary(t, store, 2))
	}
	applied, err := applyStaged(store, []string{public}, releaseNow.Add(24*time.Hour), offering(source.served))
	if err != nil || applied.Outcome != applyOnTrial {
		t.Fatalf("apply gave %+v, %v", applied, err)
	}
	dir, err := store.currentDir()
	if err != nil || dir != store.dir(2) {
		t.Fatalf("current names %q, %v; want release 2's directory", dir, err)
	}
	if settled, err := settleRun(store, false, "", releaseNow.Add(25*time.Hour)); err != nil || settled.Outcome != settleApplied {
		t.Fatalf("settle gave %+v, %v", settled, err)
	}
}

// Capable: the source serves bytes of the right length that hash differently.
func TestABinaryWhoseDigestDiffersStagesNothing(t *testing.T) {
	store := storeWithInstalled(t, []byte("installed"))
	source, public := releaseWith(t, 2, []byte("the signed binary"), 0, map[string]string{"preflight.sh": "two"})
	for digest := range source.binaries {
		source.binaries[digest] = []byte("a swapped binary!")
	}
	result, err := stageRelease(store, source, []string{public}, releaseNow)
	if err != nil || result.Outcome != stageRefused || !strings.Contains(result.Reason, "the binary hashes to") {
		t.Fatalf("a binary that differs from its manifest gave %+v, %v", result, err)
	}
	for _, path := range []string{store.dir(2), store.dir(2) + ".incoming"} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused binary left %s: %v", path, err)
		}
	}
	if _, ok := pointerValue(t, store, "staged"); ok {
		t.Fatal("a release whose binary was refused was staged")
	}
}

// Capable: a script that differs, with the binary served correctly, so the
// only reason nothing is staged is the script.
func TestAScriptWhoseDigestDiffersStagesNoBinary(t *testing.T) {
	store := storeWithInstalled(t, []byte("installed"))
	source, public := releaseWith(t, 2, []byte("a good binary"), 0, map[string]string{"preflight.sh": "the signed script"})
	for digest := range source.files {
		source.files[digest] = []byte("a swapped script!")
	}
	result, err := stageRelease(store, source, []string{public}, releaseNow)
	if err != nil || result.Outcome != stageRefused || !strings.Contains(result.Reason, "preflight.sh hashes to") {
		t.Fatalf("a script that differs gave %+v, %v", result, err)
	}
	if source.binaryCalls != 0 {
		t.Fatalf("the binary was fetched %d times for a release already refused", source.binaryCalls)
	}
	if _, err := os.Stat(store.dir(2)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused release left a directory: %v", err)
	}
}

// Capable: two releases with different binaries, the second applied and then
// failed, so `current` has somewhere to go back to with a binary of its own.
func TestAFailedRunMovesTheBinaryBackWithTheScripts(t *testing.T) {
	store := storeWithInstalled(t, []byte("installed"))
	first, firstKey := releaseWith(t, 2, []byte("binary two"), 0, map[string]string{"preflight.sh": "two"})
	if _, err := stageRelease(store, first, []string{firstKey}, releaseNow); err != nil {
		t.Fatal(err)
	}
	if _, err := applyStaged(store, []string{firstKey}, releaseNow, offering(first.served)); err != nil {
		t.Fatal(err)
	}
	if _, err := settleRun(store, false, "", releaseNow); err != nil {
		t.Fatal(err)
	}
	second, secondKey := releaseWith(t, 3, []byte("binary three, broken"), 0, map[string]string{"preflight.sh": "three"})
	trusted := []string{firstKey, secondKey}
	if _, err := stageRelease(store, second, trusted, releaseNow); err != nil {
		t.Fatal(err)
	}
	if result, err := applyStaged(store, trusted, releaseNow, offering(second.served)); err != nil || result.Outcome != applyOnTrial {
		t.Fatalf("apply of 3 gave %+v, %v", result, err)
	}
	if _, err := settleRun(store, true, "preflight.sh of release 3 did not reach its end", releaseNow); err != nil {
		t.Fatal(err)
	}
	dir, err := store.currentDir()
	if err != nil || dir != store.dir(2) {
		t.Fatalf("current names %q after the move back, want release 2's directory", dir)
	}
	if string(stagedBinary(t, store, 2)) != "binary two" {
		t.Fatalf("the binary current names is %q, want release 2's", stagedBinary(t, store, 2))
	}
}

// Capable: the release's binary is the installed one, the state of a release
// that changes only scripts, so nothing is fetched and the copy is the
// installed bytes.
func TestAReleaseOfScriptsAloneCopiesTheInstalledBinary(t *testing.T) {
	installed := []byte("the binary a person installed")
	store := storeWithInstalled(t, installed)
	source, public := releaseWith(t, 2, installed, 0, map[string]string{"preflight.sh": "two"})
	staged, err := stageRelease(store, source, []string{public}, releaseNow)
	if err != nil || staged.Outcome != stageStaged || !strings.Contains(staged.Reason, "the installed binary") {
		t.Fatalf("stage gave %+v, %v", staged, err)
	}
	if source.binaryCalls != 0 || string(stagedBinary(t, store, 2)) != string(installed) {
		t.Fatalf("a scripts-only release fetched the binary %d times and staged %q", source.binaryCalls, stagedBinary(t, store, 2))
	}
}

// Capable: oldestBinary one above this binary's level, on a release that
// brings its own binary, which is the update that meets the level.
func TestAReleaseBringingItsOwnBinaryIsNotBlockedByItsLevel(t *testing.T) {
	store := storeWithInstalled(t, []byte("installed"))
	source, public := releaseWith(t, 2, []byte("a newer binary"), binaryReleaseLevel+1, map[string]string{"preflight.sh": "two"})
	staged, err := stageRelease(store, source, []string{public}, releaseNow)
	if err != nil || staged.Outcome != stageStaged {
		t.Fatalf("a release raising the binary's level gave %+v, %v; want staged", staged, err)
	}
	if applied, err := applyStaged(store, []string{public}, releaseNow, offering(source.served)); err != nil || applied.Outcome != applyOnTrial {
		t.Fatalf("its apply gave %+v, %v; want on trial", applied, err)
	}
}

// Capable: the staged binary rewritten on disk between staging and apply.
func TestAStagedBinaryChangedBeforeApplyIsRefused(t *testing.T) {
	store := storeWithInstalled(t, []byte("installed"))
	source, public := releaseWith(t, 2, []byte("binary two"), 0, map[string]string{"preflight.sh": "two"})
	if _, err := stageRelease(store, source, []string{public}, releaseNow); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.dir(2), filepath.FromSlash(releaseBinaryPath)), []byte("binary owt"), 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := applyStaged(store, []string{public}, releaseNow, offering(source.served))
	if err != nil || result.Outcome != applyRefused || !strings.Contains(result.Reason, "the binary changed after it was staged") {
		t.Fatalf("a staged binary changed overnight gave %+v, %v", result, err)
	}
	if dir, _ := store.currentDir(); dir != "" {
		t.Fatalf("a changed binary became current: %s", dir)
	}
}

func TestAScriptMayNotTakeTheBinarysPath(t *testing.T) {
	err := validScripts(&releaseScripts{Commit: strings.Repeat("a", 40), Files: []releaseScript{{Path: releaseBinaryPath, Digest: strings.Repeat("0", 64), Size: 1}}})
	if err == nil || !strings.Contains(err.Error(), "where the release's binary goes") {
		t.Fatalf("a script at the binary's path gave %v, want a refusal", err)
	}
}
