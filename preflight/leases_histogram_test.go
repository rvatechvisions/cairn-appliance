package main

import (
	"strings"
	"testing"
)

// The ClientUID length histogram, on fixtures. WO-1030-N137, 00-i item 6,
// under section 00a: built from the specification and proven on fixtures,
// because which shape a real server sends is a fact about somebody's DHCP
// server and no fixture can settle it.
//
// **What was and was not already proven.** `TestHardwareAddressShapes` drives
// `hardwareAddress` with the three documented shapes and proves the function.
// It does not prove that anything records what came back: the probe said the
// histogram was "still unrecorded" because no lease had arrived, and nothing
// would have recorded it if one had. That is the half this covers.

// The specification's worked example, 192.168.1.10/24, as leases_test.go uses.
func uidOfEachShape() (mac []byte, ofType1 []byte, unique []byte) {
	mac = []byte{0x00, 0x1c, 0x25, 0x80, 0xa0, 0x43}
	ofType1 = append([]byte{0x01}, mac...)
	unique = append([]byte{0x00, 0x01, 0xa8, 0xc0, 0x01}, mac...)
	return mac, ofType1, unique
}

func TestHistogramCountsEachShapeAndWhetherItParsed(t *testing.T) {
	mac, ofType1, unique := uidOfEachShape()

	tally := map[int]uidTally{}
	for _, uid := range [][]byte{mac, ofType1, unique} {
		tallyUID(tally, uid, exampleIP, exampleMask)
	}
	// A prefix naming another subnet: the right length and not the shape it
	// looks like, so it is refused rather than trimmed.
	tallyUID(tally, append([]byte{0x00, 0x02, 0xa8, 0xc0, 0x01}, mac...), exampleIP, exampleMask)
	// A client-identifier that is text, which is a length none of the three cover.
	tallyUID(tally, []byte("host1.contoso.com"), exampleIP, exampleMask)
	// A lease carrying no ClientUID at all.
	tallyUID(tally, nil, exampleIP, exampleMask)

	if got := tally[6]; got.Keyed != 1 || got.Refused != 0 {
		t.Errorf("6 bytes: got %+v, want one parsed", got)
	}
	if got := tally[7]; got.Keyed != 1 || got.Refused != 0 {
		t.Errorf("7 bytes: got %+v, want one parsed", got)
	}
	// **The one that matters: 11 bytes is both, and the length alone cannot say
	// which.** One parsed and one was refused at the same length, which is the
	// whole reason the tally counts the outcome rather than the shape.
	if got := tally[11]; got.Keyed != 1 || got.Refused != 1 {
		t.Errorf("11 bytes: got %+v, want one parsed and one refused", got)
	}
	if got := tally[17]; got.Keyed != 0 || got.Refused != 1 {
		t.Errorf("a text client-identifier: got %+v, want one refused", got)
	}
	if got := tally[0]; got.Keyed != 0 || got.Refused != 1 {
		t.Errorf("no ClientUID: got %+v, want one refused", got)
	}
}

func TestHistogramLinesNameTheShapeAndTheRefusals(t *testing.T) {
	mac, _, unique := uidOfEachShape()
	tally := map[int]uidTally{}
	tallyUID(tally, mac, exampleIP, exampleMask)
	tallyUID(tally, unique, exampleIP, exampleMask)
	tallyUID(tally, append([]byte{0x00, 0x02, 0xa8, 0xc0, 0x01}, mac...), exampleIP, exampleMask)

	lines := uidHistogramLines(tally)
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want one per length observed: %v", len(lines), lines)
	}
	// Shortest first, so two runs of the same estate read the same way.
	if !strings.Contains(lines[0], " 6 bytes") || !strings.Contains(lines[0], "bare hardware address") {
		t.Errorf("first line: %q", lines[0])
	}
	if strings.Contains(lines[0], "REFUSED") {
		t.Errorf("six bytes all parsed, so nothing is refused: %q", lines[0])
	}
	if !strings.Contains(lines[1], "11 bytes") || !strings.Contains(lines[1], "1 REFUSED") {
		t.Errorf("second line must carry the refusal: %q", lines[1])
	}
	if !strings.Contains(lines[1], "subnet prefix") {
		t.Errorf("second line must name the shape: %q", lines[1])
	}
}

// Nothing observed prints nothing, so the caller's own sentence about an
// unproven parse is the only thing a reader sees. A histogram of nothing and a
// histogram nobody computed must not look the same.
func TestHistogramOfNothingIsEmpty(t *testing.T) {
	if lines := uidHistogramLines(map[int]uidTally{}); len(lines) != 0 {
		t.Errorf("got %v, want no lines", lines)
	}
}

// A length outside the three documented shapes is named as that rather than
// given a name it has not earned: the probe reports what arrived, and whoever
// reads it decides whether the reader should learn that shape.
func TestAnUndocumentedLengthSaysSo(t *testing.T) {
	if got := uidShape(9); !strings.Contains(got, "none of the three documented shapes") {
		t.Errorf("got %q", got)
	}
	if got := uidShape(0); got != "no ClientUID at all" {
		t.Errorf("got %q", got)
	}
}
