package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// WO-1016-N39 item 3. Every value below is invented for the test, under the
// rule that a change is proven on fixtures and never on a client's data.

var adNow = time.Date(2026, 10, 16, 5, 30, 0, 0, time.UTC)

// fileTimeOf writes t as the directory's FILETIME.
func fileTimeOf(t time.Time) string {
	const epochDelta = 116444736000000000
	return strconv.FormatInt(t.UnixNano()/100+epochDelta, 10)
}

func writeRead(t *testing.T, dir, name, ldif string, status int, said string) {
	t.Helper()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(dir, name+".ldif"), []byte(ldif), 0o600))
	must(os.WriteFile(filepath.Join(dir, name+".status"), []byte(strconv.Itoa(status)+"\n"), 0o600))
	must(os.WriteFile(filepath.Join(dir, name+".said"), []byte(said), 0o600))
}

const adBase = "DC=example,DC=test"

func fixtureDir(t *testing.T) string {
	dir := t.TempDir()
	recent := fileTimeOf(adNow.AddDate(0, 0, -3))
	old := fileTimeOf(adNow.AddDate(0, 0, -400))
	writeRead(t, dir, "users", strings.Join([]string{
		"dn: CN=Recent Person,OU=Staff," + adBase,
		"sAMAccountName: recent", "name: Recent Person", "userAccountControl: 512",
		"lastLogonTimestamp: " + recent, "whenCreated: 20250101120000.0Z", "",
		"dn: CN=Old Person,OU=Staff," + adBase,
		"sAMAccountName: old", "name: Old Person", "userAccountControl: 512",
		"lastLogonTimestamp: " + old, "whenCreated: 20200101120000.0Z", "",
		"dn: CN=Gone Person,OU=Staff," + adBase,
		"sAMAccountName: gone", "name: Gone Person", "userAccountControl: 514",
		"whenCreated: 20190101120000.0Z", "",
		// A name with a character LDIF must base64, and a value folded across lines.
		"dn:: " + base64.StdEncoding.EncodeToString([]byte("CN=Zoë Example,OU=Staff,"+adBase)),
		"sAMAccountName: zoe", "name:: " + base64.StdEncoding.EncodeToString([]byte("Zoë Example")),
		"userAccountControl: 512", "lastLogonTimestamp: " + old[:8], " " + old[8:], "", "",
	}, "\n"), 0, "")
	writeRead(t, dir, "groups", strings.Join([]string{
		"dn: CN=Empty Security,OU=Groups," + adBase,
		"name: Empty Security", "groupType: -2147483646", "whenCreated: 20210101000000.0Z", "",
		"dn: CN=Owned,OU=Groups," + adBase,
		"name: Owned", "groupType: -2147483646", "managedBy: CN=Recent Person,OU=Staff," + adBase,
		"member: CN=Recent Person,OU=Staff," + adBase, "",
		"dn: CN=Unowned,OU=Groups," + adBase,
		"name: Unowned", "groupType: 4",
		"member: CN=Recent Person,OU=Staff," + adBase, "member: CN=Old Person,OU=Staff," + adBase, "",
		"dn: CN=Huge,OU=Groups," + adBase,
		"name: Huge", "groupType: -2147483640", "member;range=0-1499: CN=Recent Person,OU=Staff," + adBase, "",
	}, "\n"), 0, "")
	writeRead(t, dir, "gpos", strings.Join([]string{
		"dn: CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System," + adBase,
		"cn: {31B2F340-016D-11D2-945F-00C04FB984F9}", "displayName: Default Domain Policy", "flags: 0",
		"whenCreated: 20190101000000.0Z", "whenChanged: 20260901000000.0Z", "",
		"dn: CN={0A1B2C3D-0000-0000-0000-000000000001},CN=Policies,CN=System," + adBase,
		"cn: {0A1B2C3D-0000-0000-0000-000000000001}", "displayName: Unlinked users off", "flags: 1",
		"whenCreated: 20220101000000.0Z", "whenChanged: 20220101000000.0Z", "",
	}, "\n"), 0, "")
	writeRead(t, dir, "gplinks", strings.Join([]string{
		"dn: " + adBase,
		"gPLink: [LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system," + adBase + ";0]", "",
	}, "\n"), 0, "")
	writeRead(t, dir, "dcs", strings.Join([]string{
		"dn: CN=NTDS Settings,CN=DC1,CN=Servers,CN=Main-Site,CN=Sites,CN=Configuration," + adBase,
		"msDS-hasDomainNCs: " + adBase, "",
		"dn: CN=NTDS Settings,CN=OTHERDC,CN=Servers,CN=Main-Site,CN=Sites,CN=Configuration," + adBase,
		"msDS-hasDomainNCs: DC=child," + adBase, "",
	}, "\n"), 0, "")
	writeRead(t, dir, "dns-domain", strings.Join([]string{
		"dn: DC=example.test,CN=MicrosoftDNS,DC=DomainDnsZones," + adBase, "dc: example.test", "",
		"dn: DC=0.168.192.in-addr.arpa,CN=MicrosoftDNS,DC=DomainDnsZones," + adBase, "dc: 0.168.192.in-addr.arpa", "",
	}, "\n"), 0, "")
	writeRead(t, dir, "dns-system", "", 32, "No such object")
	writeRead(t, dir, "dns-forest", strings.Join([]string{
		"dn: DC=_msdcs.example.test,CN=MicrosoftDNS,DC=ForestDnsZones," + adBase, "dc: _msdcs.example.test", "",
	}, "\n"), 0, "")
	secondSliceFixture(t, dir)
	return dir
}

func byID(checks []adCheck) map[string]adCheck {
	out := map[string]adCheck{}
	for _, c := range checks {
		out[c.ID] = c
	}
	return out
}

func TestEveryDeclaredCheckIsSentInTheScriptsOrder(t *testing.T) {
	checks := buildAdChecks(fixtureDir(t), adBase, adNow)
	if len(checks) != len(adCheckIDs) {
		t.Fatalf("sent %d checks, the script declares %d", len(checks), len(adCheckIDs))
	}
	for i, id := range adCheckIDs {
		if checks[i].ID != id {
			t.Fatalf("check %d is %s, want %s", i, checks[i].ID, id)
		}
	}
	for _, id := range []string{"ou-delegation", "gpo-settings"} {
		c := byID(checks)[id]
		if c.State != "could-not-answer" || c.Reason == "" {
			t.Fatalf("%s is %q with reason %q; a check not read must say why", id, c.State, c.Reason)
		}
	}
}

func TestStaleAccountsKeepDisabledAndNeverSignedInApart(t *testing.T) {
	c := byID(buildAdChecks(fixtureDir(t), adBase, adNow))["stale-accounts"]
	if c.State != "found" || c.Count != 3 || *c.Examined != 4 || *c.ThresholdDays != 180 {
		t.Fatalf("got state %s count %d examined %d", c.State, c.Count, *c.Examined)
	}
	names := []string{}
	for _, item := range c.Items {
		names = append(names, item["samAccountName"].(string))
	}
	if strings.Join(names, ",") != "old,zoe,gone" {
		t.Fatalf("order %v: enabled first, then by name", names)
	}
	gone := c.Items[2]
	if gone["enabled"] != false || gone["neverSignedIn"] != true || gone["lastLogonDate"] != nil {
		t.Fatalf("a disabled account that never signed in: %v", gone)
	}
	if c.Items[1]["name"] != "Zoë Example" {
		t.Fatalf("base64 and folded values: %v", c.Items[1])
	}
}

func TestGroupsCountEmptyAndUnownedAsTheScriptDoes(t *testing.T) {
	checks := byID(buildAdChecks(fixtureDir(t), adBase, adNow))
	empty, unowned := checks["empty-groups"], checks["unowned-groups"]
	if empty.Count != 1 || empty.Items[0]["name"] != "Empty Security" || empty.Items[0]["groupCategory"] != "Security" || empty.Items[0]["groupScope"] != "Global" {
		t.Fatalf("empty groups: %+v", empty)
	}
	if *empty.Examined != 4 {
		t.Fatalf("examined %d", *empty.Examined)
	}
	if unowned.Count != 2 || unowned.Items[0]["name"] != "Unowned" || unowned.Items[0]["memberCount"] != 2 || *unowned.Examined != 3 {
		t.Fatalf("unowned groups: %+v", unowned)
	}
	if !strings.Contains(unowned.Note, "lower bound") {
		t.Fatalf("a ranged member list must say its count is a lower bound: %q", unowned.Note)
	}
}

func TestGpoInventoryReadsFlagsAndLinks(t *testing.T) {
	c := byID(buildAdChecks(fixtureDir(t), adBase, adNow))["gpo-inventory"]
	if c.Count != 2 {
		t.Fatalf("count %d", c.Count)
	}
	def, unlinked := c.Items[0], c.Items[1]
	if def["linkCount"] != 1 || def["userEnabled"] != true || def["computerEnabled"] != true {
		t.Fatalf("default domain policy: %v", def)
	}
	if unlinked["linkCount"] != 0 || unlinked["userEnabled"] != false || unlinked["computerEnabled"] != true {
		t.Fatalf("flags 1 turns off user policy only, and no link is zero links: %v", unlinked)
	}
}

func TestGpoLinksThatCouldNotBeReadAreAbsentNotEmpty(t *testing.T) {
	dir := fixtureDir(t)
	writeRead(t, dir, "gplinks", "", 50, "ldap_search_ext: Insufficient access (50)")
	c := byID(buildAdChecks(dir, adBase, adNow))["gpo-inventory"]
	if c.Items[0]["linkedTo"] != nil || c.Items[0]["linkCount"] != nil || !strings.Contains(c.Note, "absent rather than empty") {
		t.Fatalf("links unread must not read as unlinked: %v %q", c.Items[0], c.Note)
	}
}

func TestDomainControllersAreThisDomainsOnly(t *testing.T) {
	c := byID(buildAdChecks(fixtureDir(t), adBase, adNow))["domain-controllers"]
	if c.Count != 1 || c.Items[0]["name"] != "DC1" || c.Items[0]["site"] != "Main-Site" || c.Items[0]["domain"] != "example.test" {
		t.Fatalf("got %+v", c)
	}
}

func TestDnsZonesFromEveryContainerThatExists(t *testing.T) {
	c := byID(buildAdChecks(fixtureDir(t), adBase, adNow))["dns-zones"]
	if c.Count != 3 {
		t.Fatalf("count %d: %+v", c.Count, c.Items)
	}
	if c.Items[0]["zoneName"] != "0.168.192.in-addr.arpa" || c.Items[0]["isReverseLookupZone"] != true {
		t.Fatalf("got %v", c.Items[0])
	}
}

func TestAReadThatFailedIsCouldNotAnswerNamingWhy(t *testing.T) {
	dir := fixtureDir(t)
	writeRead(t, dir, "users", "", 50, "ldap_search_ext: Insufficient access (50)")
	writeRead(t, dir, "dns-system", "", 255, "ldap_result: Can't contact LDAP server (-1)")
	checks := byID(buildAdChecks(dir, adBase, adNow))
	for _, id := range []string{"stale-accounts", "dns-zones"} {
		c := checks[id]
		if c.State != "could-not-answer" || !strings.Contains(c.Reason, "ldapsearch exited") || len(c.Items) != 0 {
			t.Fatalf("%s: %+v", id, c)
		}
	}
}

func TestAReadTheShellNeverMadeIsNotAnEmptyAnswer(t *testing.T) {
	dir := fixtureDir(t)
	if err := os.Remove(filepath.Join(dir, "groups.ldif")); err != nil {
		t.Fatal(err)
	}
	c := byID(buildAdChecks(dir, adBase, adNow))["empty-groups"]
	if c.State != "could-not-answer" || !strings.Contains(c.Reason, "was not made") {
		t.Fatalf("got %+v", c)
	}
}

func TestTheSubmissionIsSourceAdWithTheControllersAsItems(t *testing.T) {
	checks := buildAdChecks(fixtureDir(t), adBase, adNow)
	body, err := buildAdSubmission(checks, adNow, "cairn-box", "svc-reader", "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
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
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Envelope.Source != "ad" || got.Declared != 1 || len(got.Items) != 1 || got.Part.Pages != 1 || got.Part.TotalDeclared != 1 || len(got.Findings) != len(adCheckIDs) {
		t.Fatalf("got %+v", got)
	}
	for _, word := range []string{"compliant", "non-compliant", "pass", "fail", "risk", "severity"} {
		for _, f := range got.Findings {
			if strings.Contains(strings.ToLower(f["state"].(string)), word) {
				t.Fatalf("a verdict word in a state: %v", f)
			}
		}
	}
}
