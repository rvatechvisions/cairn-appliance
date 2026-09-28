package main

import (
	"encoding/json"
	"testing"
	"time"
)

// What leaves the box is read back from the bytes buildSubmission produces,
// so a field added later is caught however it is spelled. WO-0928-B item 7, R20.
func TestSubmissionCarriesCountsAndDerivedItemsOnly(t *testing.T) {
	items := []DerivedItem{{MacAddress: "00:01:02:03:04:05", HostName: "LAB-PC-01"}, {}}
	body, err := buildSubmission(items, scopeCoverage{Attempted: 3, Unreadable: 0, Empty: 1},
		time.Date(2026, 9, 28, 5, 44, 0, 0, time.UTC), "cairn", "svc-cairn", "abc")
	if err != nil {
		t.Fatal(err)
	}

	var parsed struct {
		Envelope struct {
			Source string `json:"source"`
		} `json:"envelope"`
		Declared int `json:"declared"`
		Part     struct {
			Pages         int `json:"pages"`
			TotalDeclared int `json:"totalDeclared"`
		} `json:"part"`
		Findings []map[string]any `json:"findings"`
		Items    []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Envelope.Source != "dhcp" || parsed.Declared != 2 || parsed.Part.TotalDeclared != 2 || parsed.Part.Pages != 1 {
		t.Fatalf("envelope or counts wrong: %s", body)
	}

	// Coverage travels as counts. A scope identifier would be the structure of
	// the lease list leaving the box.
	for _, finding := range parsed.Findings {
		for key := range finding {
			if key != "id" && key != "state" && key != "count" {
				t.Errorf("coverage finding %v carries %q", finding["id"], key)
			}
		}
	}
	for _, item := range parsed.Items {
		for key := range item {
			if key != "macAddress" && key != "hostName" {
				t.Errorf("an item carries %q, which R20 does not permit to leave", key)
			}
		}
	}
}
