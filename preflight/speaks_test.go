package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// -speaks names every line -emit-credential can print, and the consent list
// among them. WO-1001-D item 2: the script refuses a binary that does not
// declare the consent list rather than reading its silence as the portal's.
func TestSpeaksNamesEveryLineTheCredentialBlockPrints(t *testing.T) {
	answer := speaks()
	if !strings.HasPrefix(answer, "credential-block: ") {
		t.Fatalf("speaks() = %q, want a credential-block: line", answer)
	}
	declared := map[string]bool{}
	for _, name := range strings.Fields(strings.TrimPrefix(answer, "credential-block: ")) {
		declared[name] = true
	}
	if !declared["capabilities"] {
		t.Fatalf("speaks() = %q does not name the consent list", answer)
	}

	// Read the printer rather than trusting the list: every header the
	// -emit-credential block prints must be declared, or the declaration is a
	// second description of the block free to drift from it.
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("could not read main.go: %v", err)
	}
	printed := regexp.MustCompile(`fmt\.Printf\("([a-z-]+)=%s\\n"`).FindAllStringSubmatch(string(source), -1)
	if len(printed) < 4 {
		t.Fatalf("found %d header printers in main.go; the pattern has stopped matching its subject", len(printed))
	}
	for _, m := range printed {
		if !declared[m[1]] {
			t.Errorf("-emit-credential prints %s= and -speaks does not declare it", m[1])
		}
	}
}
