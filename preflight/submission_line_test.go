package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The line the box keeps names the exact bytes it signs and sends: their size
// and their SHA-256, which the portal records over the body as it arrived.
// WO-1001-C item 3.
func TestSubmissionLineNamesTheBytesSent(t *testing.T) {
	body := []byte(`{"envelope":{"source":"dhcp"},"items":[]}`)
	sum := sha256.Sum256(body)
	want := "sending 41 bytes, body SHA-256 " + hex.EncodeToString(sum[:])
	if got := submissionLine(body); got != want {
		t.Fatalf("submissionLine = %q, want %q", got, want)
	}
	if !strings.Contains(submissionLine([]byte("x")), "body SHA-256 2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881") {
		t.Fatal("the digest is not the SHA-256 of the bytes")
	}
}
