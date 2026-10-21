package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Queue item 8, WO-1021-N113 item 1: the two DHCP authorization findings, on
// fixtures. A shared address, an unresolvable registration and a clean read
// each give their own answer; a read that failed is could-not-answer with
// Cairn's own reason; and a read never handed over sends neither finding.

// fakeResolver answers from two tables, and reports a name it does not hold as
// not found, the way a resolver reports an NXDOMAIN.
type fakeResolver struct {
	forward map[string][]string
	reverse map[string][]string
	broken  map[string]bool
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if f.broken[host] {
		return nil, &net.DNSError{Err: "server misbehaving", Name: host, Server: "10.0.0.53:53"}
	}
	if addresses, ok := f.forward[host]; ok {
		return addresses, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if names, ok := f.reverse[addr]; ok {
		return names, nil
	}
	return nil, errors.New("no PTR")
}

const authorizedLDIF = `dn: CN=DhcpRoot,CN=NetServices,CN=Services,CN=Configuration,DC=example,DC=test
name: DhcpRoot

dn: CN=dhcp-a.example.test,CN=NetServices,CN=Services,CN=Configuration,DC=example,DC=test
name: dhcp-a.example.test
dhcpServers: i10.9.0.2$rcn=dhcp-a.example.test$

dn: CN=dhcp-b.example.test,CN=NetServices,CN=Services,CN=Configuration,DC=example,DC=test
name: dhcp-b.example.test
dhcpServers: i10.9.0.2$rcn=dhcp-b.example.test$

dn: CN=dhcp-c.example.test,CN=NetServices,CN=Services,CN=Configuration,DC=example,DC=test
name: dhcp-c.example.test
dhcpServers: i10.9.0.3$rcn=dhcp-c.example.test$
`

const cleanLDIF = `dn: CN=DhcpRoot,CN=NetServices,CN=Services,CN=Configuration,DC=example,DC=test
name: DhcpRoot

dn: CN=dhcp-a.example.test,CN=NetServices,CN=Services,CN=Configuration,DC=example,DC=test
name: dhcp-a.example.test
dhcpServers: i10.9.0.2$rcn=dhcp-a.example.test$
`

func TestAuthorizationsFindASharedAddressAndAnUnresolvableRegistration(t *testing.T) {
	resolver := fakeResolver{
		forward: map[string][]string{"dhcp-a.example.test": {"10.9.0.2"}, "dhcp-c.example.test": {"10.9.0.8"}},
		reverse: map[string][]string{"10.9.0.2": {"dhcp-a.example.test."}},
	}
	checks := byID(authorizationChecks(context.Background(), adRead{Text: authorizedLDIF, Status: 0}, true, resolver, map[string]bool{}))

	shared := checks[sharedAddressID]
	if shared.State != "found" || shared.Count != 1 || *shared.Examined != 2 {
		t.Fatalf("shared address = %+v, want found, 1, examined 2 distinct addresses", shared)
	}
	item := shared.Items[0]
	if item["ipAddress"] != "10.9.0.2" || item["anyNameResolvesHere"] != true || item["isThisHost"] != false || item["reverseName"] != "dhcp-a.example.test" {
		t.Errorf("shared item = %v", item)
	}
	if names, _ := item["names"].([]string); strings.Join(names, ",") != "dhcp-a.example.test,dhcp-b.example.test" {
		t.Errorf("shared names = %v", item["names"])
	}

	unresolvable := checks[unresolvableID]
	if unresolvable.State != "found" || unresolvable.Count != 2 || *unresolvable.Examined != 3 {
		t.Fatalf("unresolvable = %+v, want found, 2 (b does not resolve, c resolves elsewhere), examined 3", unresolvable)
	}
	resolutions := map[string]string{}
	for _, row := range unresolvable.Items {
		resolutions[row["dnsName"].(string)] = row["resolution"].(string)
	}
	if resolutions["dhcp-b.example.test"] != "nxdomain" || resolutions["dhcp-c.example.test"] != "resolves-elsewhere" || len(resolutions) != 2 {
		t.Errorf("resolutions = %v", resolutions)
	}
}

func TestAuthorizationsAnsweredAndFoundNothingIsNotFoundWithExamined(t *testing.T) {
	resolver := fakeResolver{forward: map[string][]string{"dhcp-a.example.test": {"10.9.0.2"}}}
	checks := byID(authorizationChecks(context.Background(), adRead{Text: cleanLDIF, Status: 0}, true, resolver, map[string]bool{}))
	for _, id := range []string{unresolvableID, sharedAddressID} {
		check := checks[id]
		if check.State != "not-found" || check.Count != 0 || check.Examined == nil || *check.Examined != 1 || len(check.Items) != 0 {
			t.Errorf("%s = %+v, want not-found with examined 1 and no items", id, check)
		}
		if check.Reason != "" {
			t.Errorf("%s carries a reason on an answer: %q", id, check.Reason)
		}
	}
}

func TestAuthorizationsCouldNotLookIsItsOwnOutcomeWithCairnsReason(t *testing.T) {
	failed := adRead{Status: 255, Said: "ldap_sasl_interactive_bind: Can't contact LDAP server dc1.example.test"}
	checks := authorizationChecks(context.Background(), failed, true, fakeResolver{}, map[string]bool{})
	if len(checks) != 2 {
		t.Fatalf("got %d checks, want both", len(checks))
	}
	for _, check := range checks {
		if check.State != "could-not-answer" || check.Reason == "" || check.Examined != nil {
			t.Errorf("%s = %+v, want could-not-answer with a reason and no examined", check.ID, check)
		}
		if strings.Contains(check.Reason, "dc1") || strings.Contains(check.Reason, "ldap_") {
			t.Errorf("%s quotes the tool's words, which name a host: %q", check.ID, check.Reason)
		}
	}
}

func TestAuthorizationsALookupThatFailedIsNotReadAsClean(t *testing.T) {
	resolver := fakeResolver{broken: map[string]bool{"dhcp-a.example.test": true}}
	checks := byID(authorizationChecks(context.Background(), adRead{Text: cleanLDIF, Status: 0}, true, resolver, map[string]bool{}))
	check := checks[unresolvableID]
	if check.State != "could-not-answer" || len(check.Items) != 1 || check.Items[0]["resolution"] != "lookup-failed" {
		t.Fatalf("unresolvable = %+v, want could-not-answer listing the lookup that failed", check)
	}
	if reason, _ := check.Items[0]["reason"].(string); strings.Contains(reason, "10.0.0.53") {
		t.Errorf("the item quotes the resolver's address: %q", reason)
	}
}

func TestAuthorizationsAReadNeverHandedOverSendsNeither(t *testing.T) {
	if checks := authorizationChecks(context.Background(), adRead{}, false, fakeResolver{}, nil); checks != nil {
		t.Errorf("got %v, want no findings where the step was not asked", checks)
	}
}

// The portal's DHCP_FINDING_ITEM_FIELDS, as of WO-1021-N113: an item field the
// box sends that is not here would be dropped at the door, so the box sends none.
var portalItemFields = map[string][]string{
	unresolvableID:  {"dnsName", "resolution", "reverseName", "isThisHost", "reason", "ipAddress"},
	sharedAddressID: {"ipAddress", "names", "isThisHost", "anyNameResolvesHere", "reverseName"},
}

func TestAuthorizationsSendOnlyTheItemFieldsThePortalNames(t *testing.T) {
	resolver := fakeResolver{
		forward: map[string][]string{"dhcp-a.example.test": {"10.9.0.2"}},
		reverse: map[string][]string{"10.9.0.2": {"dhcp-a.example.test."}, "10.9.0.3": {"dhcp-c.example.test."}},
		broken:  map[string]bool{"dhcp-c.example.test": true},
	}
	checks := authorizationChecks(context.Background(), adRead{Text: authorizedLDIF, Status: 0}, true, resolver, map[string]bool{})
	body, err := buildSubmissionWith([]DerivedItem{{}}, scopeCoverage{Attempted: 1}, checks, time.Date(2026, 10, 21, 9, 20, 0, 0, time.UTC), "box", "svc", "id")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Findings []struct {
			ID    string           `json:"id"`
			Items []map[string]any `json:"items"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, finding := range parsed.Findings {
		allowed, ok := portalItemFields[finding.ID]
		if !ok {
			continue
		}
		for _, item := range finding.Items {
			for field := range item {
				seen++
				if !strings.Contains(" "+strings.Join(allowed, " ")+" ", " "+field+" ") {
					t.Errorf("%s sends %s, which the portal does not name", finding.ID, field)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("no item field was read, so this proves nothing")
	}
}

func TestParseRegistrationReadsTheDirectorysShapeAndRefusesOthers(t *testing.T) {
	if r, ok := parseRegistration("i10.200.2.4$rcn=dc.example.test$"); !ok || r.Address != "10.200.2.4" || r.Name != "dc.example.test" {
		t.Errorf("parsed %+v, %v", r, ok)
	}
	for _, bad := range []string{"", "10.0.0.1$rcn=x$", "inot-an-address$rcn=x$", "i10.0.0.1$"} {
		if _, ok := parseRegistration(bad); ok {
			t.Errorf("parsed %q, which is not the directory's shape", bad)
		}
	}
}
