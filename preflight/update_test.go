package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The verified install. WO-0928-C item 5: a binary is put in place only once
// it hashes to what the portal's manifest names, and the running one is never
// touched by an update that failed.

func setup(t *testing.T) (target string, old []byte) {
	t.Helper()
	dir := t.TempDir()
	target = filepath.Join(dir, "preflight")
	old = []byte("the binary already installed")
	if err := os.WriteFile(target, old, 0o700); err != nil {
		t.Fatal(err)
	}
	return target, old
}

func TestInstallsOnlyWhatVerifies(t *testing.T) {
	target, _ := setup(t)
	next := []byte("the replacement binary")

	if err := installVerified(target, binaryManifest{Digest: digestOf(next), Size: int64(len(next))}, next); err != nil {
		t.Fatalf("a verified binary was refused: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(next) {
		t.Fatalf("the target holds %q", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(target))
	if len(entries) != 1 {
		t.Fatalf("staging left behind: %d entries", len(entries))
	}
}

func TestRefusesAMismatchAndKeepsTheRunningBinary(t *testing.T) {
	target, old := setup(t)
	next := []byte("the replacement binary")
	other := []byte("a different binary")

	err := installVerified(target, binaryManifest{Digest: digestOf(other), Size: int64(len(next))}, next)
	if err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("a mismatch was not refused by name: %v", err)
	}
	// Refused before anything was written, naming both digests. The re-check of
	// what landed on disk would refuse too, but only after writing bytes nobody
	// had verified -- so the first check is proven by what its refusal says.
	if !strings.Contains(err.Error(), digestOf(next)) || !strings.Contains(err.Error(), digestOf(other)) {
		t.Fatalf("the refusal does not name what arrived and what was expected: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(old) {
		t.Fatalf("the running binary was touched by a failed update: %q", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(target))
	if len(entries) != 1 {
		t.Fatalf("a failed update left a file behind: %d entries", len(entries))
	}
}

func TestRefusesASizeTheManifestDoesNotName(t *testing.T) {
	target, old := setup(t)
	next := []byte("the replacement binary")

	err := installVerified(target, binaryManifest{Digest: digestOf(next), Size: int64(len(next)) + 1}, next)
	if err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("a size mismatch was not refused: %v", err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(old) {
		t.Fatal("the running binary was touched")
	}
}

func TestRefusesAManifestNamingNoDigest(t *testing.T) {
	target, old := setup(t)
	next := []byte("x")
	for _, digest := range []string{"", "abc", strings.Repeat("z", 64)} {
		if err := installVerified(target, binaryManifest{Digest: digest, Size: 1}, next); err == nil {
			t.Fatalf("a manifest naming %q was accepted", digest)
		}
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(old) {
		t.Fatal("the running binary was touched")
	}
}

func TestIgnoresAStagingFileLeftByAnEarlierAttempt(t *testing.T) {
	target, _ := setup(t)
	stale := filepath.Join(filepath.Dir(target), ".preflight.incoming")
	if err := os.WriteFile(stale, []byte("left over, never verified"), 0o700); err != nil {
		t.Fatal(err)
	}
	next := []byte("the replacement binary")
	if err := installVerified(target, binaryManifest{Digest: digestOf(next), Size: int64(len(next))}, next); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != string(next) {
		t.Fatalf("a stale staging file was installed: %q", got)
	}
}
