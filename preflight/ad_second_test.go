package main

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// WO-1016-N40 item 2. Every value below is invented for the test, under the
// rule that a change is proven on fixtures and never on a client's data.

// sidBytes builds the directory's binary objectSid, base64 for LDIF.
func sidBytes(authority byte, subs ...uint32) string {
	b := []byte{1, byte(len(subs)), 0, 0, 0, 0, 0, authority}
	for _, s := range subs {
		b = binary.LittleEndian.AppendUint32(b, s)
	}
	return base64.StdEncoding.EncodeToString(b)
}

const (
	adConfig  = "CN=Configuration," + adBase
	dc1Server = "CN=DC1,CN=Servers,CN=Main-Site,CN=Sites," + adConfig
)

// Days and minutes as the directory stores them: negative 100-nanosecond units.
func days(n int64) string    { return strconv.FormatInt(-n*864000000000, 10) }
func minutes(n int64) string { return strconv.FormatInt(-n*600000000, 10) }

func neighbor(nc, source, address string, failures int, result string) string {
	xml := "<DS_REPL_NEIGHBOR><pszNamingContext>" + nc + "</pszNamingContext>" +
		"<pszSourceDsaDN>" + source + "</pszSourceDsaDN>" +
		"<pszSourceDsaAddress>" + address + "</pszSourceDsaAddress>" +
		"<ftimeLastSyncSuccess>2026-10-10T04:00:00Z</ftimeLastSyncSuccess>" +
		"<ftimeLastSyncAttempt>2026-10-16T05:00:00Z</ftimeLastSyncAttempt>" +
		"<dwLastSyncResult>" + result + "</dwLastSyncResult>" +
		"<cNumConsecutiveSyncFailures>" + strconv.Itoa(failures) + "</cNumConsecutiveSyncFailures>" +
		"</DS_REPL_NEIGHBOR>"
	return "msDS-ReplAllInboundNeighbors:: " + base64.StdEncoding.EncodeToString([]byte(xml))
}

func secondSliceFixture(t *testing.T, dir string) {
	t.Helper()
	writeRead(t, dir, "domain", strings.Join([]string{
		"dn: " + adBase,
		"objectSid:: " + sidBytes(5, 21, 111, 222, 333),
		"minPwdLength: 12", "pwdHistoryLength: 24", "pwdProperties: 1",
		"maxPwdAge: " + days(42), "minPwdAge: " + days(1),
		"lockoutThreshold: 5", "lockoutDuration: " + minutes(30), "lockOutObservationWindow: " + minutes(30), "",
	}, "\n"), 0, "")
	writeRead(t, dir, "psos", strings.Join([]string{
		"dn: CN=Admins PSO,CN=Password Settings Container,CN=System," + adBase,
		"name: Admins PSO", "msDS-PasswordSettingsPrecedence: 10",
		"msDS-PSOAppliesTo: CN=Domain Admins,CN=Users," + adBase,
		"msDS-MinimumPasswordLength: 16", "msDS-PasswordHistoryLength: 24",
		"msDS-PasswordComplexityEnabled: TRUE", "msDS-PasswordReversibleEncryptionEnabled: FALSE",
		"msDS-MaximumPasswordAge: " + days(90), "msDS-MinimumPasswordAge: " + days(1),
		"msDS-LockoutThreshold: 3", "msDS-LockoutDuration: " + minutes(60), "msDS-LockoutObservationWindow: " + minutes(60), "",
	}, "\n"), 0, "")
	writeRead(t, dir, "servers", strings.Join([]string{
		"dn: " + dc1Server, "dNSHostName: dc1.example.test", "",
		"dn: CN=OTHERDC,CN=Servers,CN=Main-Site,CN=Sites," + adConfig, "dNSHostName: otherdc.child.example.test", "",
	}, "\n"), 0, "")
	writeRead(t, dir, "repl-1", strings.Join([]string{
		"dn:",
		neighbor(adBase, "CN=NTDS Settings,CN=DC2,CN=Servers,CN=Branch,CN=Sites,"+adConfig, "dc2._msdcs.example.test", 3, "8524"),
		neighbor(adConfig, "CN=NTDS Settings,CN=DC2,CN=Servers,CN=Branch,CN=Sites,"+adConfig, "dc2._msdcs.example.test", 0, "0"), "",
	}, "\n"), 0, "")
	if err := os.WriteFile(filepath.Join(dir, "repl-1.host"), []byte("dc1.example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordPolicyReadsTheDomainAndEveryPasswordSettingsObject(t *testing.T) {
	c := byID(buildAdChecks(fixtureDir(t), adBase, adNow))["password-policy"]
	if c.State != "found" || c.Count != 2 {
		t.Fatalf("got %+v", c)
	}
	head, fine := c.Items[0], c.Items[1]
	want := map[string]any{
		"scope": "domain-default", "minPasswordLength": 12, "passwordHistoryCount": 24,
		"complexityEnabled": true, "reversibleEncryptionEnabled": false,
		"maxPasswordAgeDays": 42, "minPasswordAgeDays": 1, "lockoutThreshold": 5,
		"lockoutDurationMinutes": 30, "lockoutObservationMinutes": 30,
	}
	for key, value := range want {
		if head[key] != value {
			t.Fatalf("domain-default %s is %v, want %v", key, head[key], value)
		}
	}
	if fine["scope"] != "fine-grained" || fine["name"] != "Admins PSO" || fine["precedence"] != 10 ||
		fine["minPasswordLength"] != 16 || fine["complexityEnabled"] != true || fine["maxPasswordAgeDays"] != 90 ||
		fine["lockoutThreshold"] != 3 || fine["lockoutDurationMinutes"] != 60 {
		t.Fatalf("fine-grained: %v", fine)
	}
	if applies := fine["appliesTo"].([]string); len(applies) != 1 || !strings.HasPrefix(applies[0], "CN=Domain Admins,") {
		t.Fatalf("appliesTo: %v", fine["appliesTo"])
	}
}

func TestAnAbsentPolicyValueIsNullAndNamedNotZero(t *testing.T) {
	dir := fixtureDir(t)
	writeRead(t, dir, "domain", "dn: "+adBase+"\nobjectSid:: "+sidBytes(5, 21, 111, 222, 333)+"\nminPwdLength: 0\n", 0, "")
	c := byID(buildAdChecks(dir, adBase, adNow))["password-policy"]
	head := c.Items[0]
	if head["minPasswordLength"] != 0 || head["maxPasswordAgeDays"] != nil || head["complexityEnabled"] != nil {
		t.Fatalf("a zero read is zero and a value not returned is null: %v", head)
	}
	if !strings.Contains(c.Note, "maxPwdAge") || !strings.Contains(c.Note, "absent rather than zero") {
		t.Fatalf("the note must name what was not returned: %q", c.Note)
	}
}

func TestPasswordSettingsThatCouldNotBeReadAreSaidAsTheScriptSaysThem(t *testing.T) {
	dir := fixtureDir(t)
	writeRead(t, dir, "psos", "", 50, "ldap_search_ext: Insufficient access (50)")
	c := byID(buildAdChecks(dir, adBase, adNow))["password-policy"]
	if c.State != "found" || c.Count != 2 || c.Items[1]["scope"] != "fine-grained" ||
		!strings.Contains(c.Items[1]["error"].(string), "Could not read fine-grained policies") ||
		!strings.Contains(c.Items[1]["error"].(string), "Insufficient access") {
		t.Fatalf("got %+v", c)
	}
}

func TestADomainObjectThatCouldNotBeReadIsNoPolicyAndNoPrivilegedGroups(t *testing.T) {
	dir := fixtureDir(t)
	writeRead(t, dir, "domain", "", 255, "ldap_result: Can't contact LDAP server (-1)")
	checks := byID(buildAdChecks(dir, adBase, adNow))
	for _, id := range []string{"password-policy", "privileged-groups"} {
		if checks[id].State != "could-not-answer" || !strings.Contains(checks[id].Reason, "ldapsearch exited 255") {
			t.Fatalf("%s: %+v", id, checks[id])
		}
	}
}

func TestSidStringReadsTheDirectorysBinaryForm(t *testing.T) {
	raw, _ := base64.StdEncoding.DecodeString(sidBytes(5, 32, 544))
	if got, ok := sidString(string(raw)); !ok || got != "S-1-5-32-544" {
		t.Fatalf("got %q %v", got, ok)
	}
	if _, ok := sidString("short"); ok {
		t.Fatal("a value too short to be a SID must not read as one")
	}
}

func privilegedFixture(t *testing.T) string {
	dir := fixtureDir(t)
	users := "CN=Users," + adBase
	writeRead(t, dir, "groups", strings.Join([]string{
		"dn: CN=Domain Admins," + users, "name: Domain Admins", "groupType: -2147483646",
		"objectSid:: " + sidBytes(5, 21, 111, 222, 333, 512),
		"member: CN=Alice Admin,OU=Admins," + adBase, "member: CN=Tier0,OU=Groups," + adBase, "",
		"dn: CN=Tier0,OU=Groups," + adBase, "name: Tier0", "groupType: -2147483646",
		"objectSid:: " + sidBytes(5, 21, 111, 222, 333, 1201),
		"member: CN=Bob Ops,OU=Admins," + adBase, "member: CN=Domain Admins," + users,
		"member: CN=BUILD01,OU=Servers," + adBase, "",
		"dn: CN=Administrators,CN=Builtin," + adBase, "name: Administrators", "groupType: -2147483643",
		"objectSid:: " + sidBytes(5, 32, 544),
		"member: CN=Domain Admins," + users, "member: CN=Alice Admin,OU=Admins," + adBase, "",
		"dn: CN=Ordinary,OU=Groups," + adBase, "name: Ordinary", "groupType: -2147483646",
		"objectSid:: " + sidBytes(5, 21, 111, 222, 333, 1300), "member: CN=Daily Alice,OU=Staff," + adBase, "",
	}, "\n"), 0, "")
	writeRead(t, dir, "users", strings.Join([]string{
		"dn: CN=Alice Admin,OU=Admins," + adBase, "sAMAccountName: alice.admin", "name: Alice Admin",
		"userAccountControl: 512", "givenName: Alice", "sn: Example",
		"lastLogonTimestamp: " + fileTimeOf(adNow.AddDate(0, 0, -2)), "",
		"dn: CN=Daily Alice,OU=Staff," + adBase, "sAMAccountName: alice", "name: Daily Alice",
		"userAccountControl: 512", "givenName: Alice", "sn: Example", "mail: alice@example.test", "",
		"dn: CN=Bob Ops,OU=Admins," + adBase, "sAMAccountName: bob.ops", "name: Bob Ops",
		"userAccountControl: 514", "givenName: Bob", "sn: Ops", "",
	}, "\n"), 0, "")
	return dir
}

func TestPrivilegedGroupsWalkNestedGroupsOnceEach(t *testing.T) {
	c := byID(buildAdChecks(privilegedFixture(t), adBase, adNow))["privileged-groups"]
	if c.State != "found" || *c.Examined != 2 {
		t.Fatalf("got %+v", c)
	}
	byGroup := map[string][]string{}
	for _, row := range c.Items {
		byGroup[row["group"].(string)] = append(byGroup[row["group"].(string)], row["name"].(string))
	}
	if got := strings.Join(byGroup["Domain Admins"], ","); got != "Alice Admin,Bob Ops,BUILD01" {
		t.Fatalf("Domain Admins, through Tier0 and its loop back: %s", got)
	}
	if got := strings.Join(byGroup["Administrators"], ","); got != "Alice Admin,Bob Ops,BUILD01" {
		t.Fatalf("Administrators, each member once however many routes reach it: %s", got)
	}
	if strings.Contains(strings.Join(byGroup["Domain Admins"], ","), "Tier0") {
		t.Fatal("a nested group is walked, never listed as a member")
	}
	for _, row := range c.Items {
		switch row["name"] {
		case "Alice Admin":
			if row["otherEnabledAccountSameName"] != "alice" || row["enabled"] != true || row["hasMailbox"] != false || row["lastLogonDate"] == nil {
				t.Fatalf("alice.admin: %v", row)
			}
		case "Bob Ops":
			if row["enabled"] != false || row["otherEnabledAccountSameName"] != nil {
				t.Fatalf("bob.ops: %v", row)
			}
		case "BUILD01":
			if row["objectClass"] != nil || row["enabled"] != nil || row["hasMailbox"] != nil {
				t.Fatalf("a member that is not a user read here says nothing it was not told: %v", row)
			}
		}
	}
	if !strings.Contains(c.Note, "primary group") || !strings.Contains(c.Note, "not user accounts this reader read") {
		t.Fatalf("note: %q", c.Note)
	}
}

func TestNoPrivilegedGroupAmongTheGroupsReadIsNotAnEmptyAnswer(t *testing.T) {
	c := byID(buildAdChecks(fixtureDir(t), adBase, adNow))["privileged-groups"]
	if c.State != "could-not-answer" || !strings.Contains(c.Reason, "None of the privileged groups") {
		t.Fatalf("got %+v", c)
	}
}

func TestReplicationFailuresAreReadFromThisDomainsControllersOnly(t *testing.T) {
	c := byID(buildAdChecks(fixtureDir(t), adBase, adNow))["replication-failures"]
	if c.State != "found" || c.Count != 1 || *c.Examined != 1 {
		t.Fatalf("got %+v", c)
	}
	row := c.Items[0]
	if row["server"] != "dc1.example.test" || row["failureCount"] != 3 || row["lastError"] != "8524" ||
		row["namingContext"] != adBase || row["failureType"] != nil || row["firstFailureTime"] != nil ||
		row["lastSuccessTime"] != "2026-10-10T04:00:00Z" {
		t.Fatalf("row: %v", row)
	}
	if strings.Contains(c.Note, "otherdc") {
		t.Fatalf("a controller of another domain is not this domain's to read: %q", c.Note)
	}
}

func TestAControllerThatCouldNotBeAskedIsNamedNotSkipped(t *testing.T) {
	dir := fixtureDir(t)
	writeRead(t, dir, "repl-1", "", 49, "ldap_sasl_interactive_bind: Invalid credentials (49)")
	c := byID(buildAdChecks(dir, adBase, adNow))["replication-failures"]
	if c.State != "could-not-answer" || !strings.Contains(c.Reason, "dc1.example.test") || !strings.Contains(c.Reason, "Invalid credentials") {
		t.Fatalf("got %+v", c)
	}
}

func TestAControllerTheDirectoryNamesNoHostForIsSaid(t *testing.T) {
	dir := fixtureDir(t)
	writeRead(t, dir, "servers", "dn: "+dc1Server+"\n", 0, "")
	c := byID(buildAdChecks(dir, adBase, adNow))["replication-failures"]
	if c.State != "could-not-answer" || !strings.Contains(c.Reason, "names no host for DC1") {
		t.Fatalf("got %+v", c)
	}
}
