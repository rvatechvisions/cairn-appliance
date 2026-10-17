package main

// The Active Directory assessment, read over LDAP by the appliance rather than
// by a script on a domain controller. WO-1016-N39 item 3, option A of
// AD-COLLECTION-DESIGN.md in the portal repository, approved by Jackie Ramsey in
// Asana on 16 October 2026.
//
// The shell does the reading: preflight.sh's ad-assessment step runs
// ldapsearch over the Kerberos session it already holds and writes each read to
// a file, with ldapsearch's exit status beside it. This file does the judging of
// shape and nothing else: it turns those LDIF files into the same CheckResult
// list the script assess-ad.ps1 produces, and sends it signed, as source ad.
//
// No verdict is made here. Whether 40 stale accounts is too many is a rule's to
// say, in the portal. A read that did not happen is a could-not-answer that
// names why, never an empty list.
//
// The box is not joined to the domain, and nothing here writes to it: every
// read is an ldapsearch the shell made.

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// What the script sets as its defaults, so the two readers count alike.
// scripts/assess-ad.ps1 1.4: StaleAfterDays 180, MaxItems 500.
const (
	adStaleAfterDays = 180
	adMaxItems       = 500
)

// The checks the script 1.4 declares, in its order (AD_CHECKS in the portal's
// src/assessment/ad-envelope.ts). Every one is sent: those this reader does not
// read are could-not-answer with the reason, so a missing check reads as a gap
// and never as a check that passed.
var adCheckIDs = []string{
	"stale-accounts", "password-policy", "privileged-groups", "empty-groups", "unowned-groups",
	"ou-delegation", "gpo-inventory", "gpo-settings", "domain-controllers", "replication-failures", "dns-zones",
}

// Why each check this reader does not yet read is not read. Stated per check.
var adNotRead = map[string]string{
	"ou-delegation": "This version of the appliance's directory reader does not read permissions on organizational units: they are security descriptors, which it does not parse yet.",
	"gpo-settings":  "Group Policy setting values are kept in files on SYSVOL, not in the directory, and reading them is its own permission, asked separately from the directory reads.",
}

type adCheck struct {
	ID            string           `json:"id"`
	State         string           `json:"state"`
	Count         int              `json:"count"`
	Items         []map[string]any `json:"items"`
	Reason        string           `json:"reason,omitempty"`
	Truncated     bool             `json:"truncated,omitempty"`
	Examined      *int             `json:"examined,omitempty"`
	Note          string           `json:"note,omitempty"`
	ThresholdDays *int             `json:"thresholdDays,omitempty"`
}

func intp(n int) *int { return &n }

// newAdCheck mirrors the script's New-CheckResult: count is the whole list,
// items the first adMaxItems, and truncated says when they differ.
func newAdCheck(id string, items []map[string]any) adCheck {
	state := "not-found"
	if len(items) > 0 {
		state = "found"
	}
	check := adCheck{ID: id, State: state, Count: len(items), Items: items}
	if len(items) > adMaxItems {
		check.Items = items[:adMaxItems]
		check.Truncated = true
	}
	if check.Items == nil {
		check.Items = []map[string]any{}
	}
	return check
}

func couldNotAnswer(id, reason string) adCheck {
	return adCheck{ID: id, State: "could-not-answer", Items: []map[string]any{}, Reason: reason}
}

// ldifEntry is one object: its DN and every attribute's values, in order.
type ldifEntry struct {
	DN    string
	Attrs map[string][]string
}

func (e ldifEntry) first(name string) string {
	for key, values := range e.Attrs {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func (e ldifEntry) all(name string) []string {
	for key, values := range e.Attrs {
		if strings.EqualFold(key, name) {
			return values
		}
	}
	return nil
}

// members counts member values, and says when the directory answered with a
// ranged member attribute (more than it returns at once, 1,500 by default),
// so a count can be a lower bound rather than a total.
func (e ldifEntry) members() (count int, ranged bool) {
	for key, values := range e.Attrs {
		lower := strings.ToLower(key)
		if lower == "member" {
			count += len(values)
		} else if strings.HasPrefix(lower, "member;range=") {
			count += len(values)
			ranged = true
		}
	}
	return count, ranged
}

// parseLDIF reads ldapsearch -LLL output: entries separated by blank lines,
// continuation lines beginning with one space, "attr:: " for base64 values,
// and "#" comments. A line it cannot read is an error, never skipped.
func parseLDIF(text string) ([]ldifEntry, error) {
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(strings.ReplaceAll(text, "\r\n", "\n")))
	scanner.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, " ") && len(lines) > 0 && lines[len(lines)-1] != "" {
			lines[len(lines)-1] += line[1:]
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	var entries []ldifEntry
	var current *ldifEntry
	for n, line := range lines {
		if line == "" {
			if current != nil {
				entries = append(entries, *current)
				current = nil
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		colon := strings.Index(line, ":")
		if colon <= 0 {
			return nil, fmt.Errorf("LDIF line %d is not an attribute: %q", n+1, line)
		}
		name := line[:colon]
		value := line[colon+1:]
		if strings.HasPrefix(value, ":") {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[1:]))
			if err != nil {
				return nil, fmt.Errorf("LDIF line %d has a base64 value that does not decode: %v", n+1, err)
			}
			value = string(decoded)
		} else {
			value = strings.TrimPrefix(value, " ")
		}
		if strings.EqualFold(name, "dn") {
			if current != nil {
				entries = append(entries, *current)
			}
			current = &ldifEntry{DN: value, Attrs: map[string][]string{}}
			continue
		}
		if current == nil {
			return nil, fmt.Errorf("LDIF line %d has an attribute before any dn", n+1)
		}
		current.Attrs[name] = append(current.Attrs[name], value)
	}
	if current != nil {
		entries = append(entries, *current)
	}
	return entries, nil
}

// A FILETIME is 100-nanosecond intervals since 1 January 1601 UTC.
func fileTime(value string) (time.Time, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || n <= 0 || n == 9223372036854775807 {
		return time.Time{}, false
	}
	const epochDelta = 116444736000000000
	return time.Unix(0, (n-epochDelta)*100).UTC(), true
}

// Generalized time as the directory writes it: 20240101120000.0Z.
func generalizedTime(value string) (time.Time, bool) {
	t, err := time.Parse("20060102150405.0Z", strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func isoOrNil(t time.Time, ok bool) any {
	if !ok {
		return nil
	}
	return t.Format(time.RFC3339)
}

// adRead is one read the shell made: what ldapsearch printed and its exit status.
type adRead struct {
	Text   string
	Status int
	Said   string
}

// readFailed says why a read can stand for no answer, in ldapsearch's words.
func readFailed(r adRead, what string) string {
	said := strings.TrimSpace(r.Said)
	if said == "" {
		said = "it printed nothing to say why"
	}
	return fmt.Sprintf("The directory read of %s did not complete: ldapsearch exited %d, and said: %s", what, r.Status, said)
}

func uacDisabled(e ldifEntry) bool {
	n, err := strconv.ParseInt(e.first("userAccountControl"), 10, 64)
	return err == nil && n&0x2 != 0
}

func staleAccountsCheck(r adRead, collectedAt time.Time) adCheck {
	if r.Status != 0 {
		return couldNotAnswer("stale-accounts", readFailed(r, "user accounts"))
	}
	entries, err := parseLDIF(r.Text)
	if err != nil {
		return couldNotAnswer("stale-accounts", "The user accounts read could not be parsed: "+err.Error())
	}
	cutoff := collectedAt.AddDate(0, 0, -adStaleAfterDays)
	var stale []map[string]any
	for _, e := range entries {
		last, ok := fileTime(e.first("lastLogonTimestamp"))
		if ok && !last.Before(cutoff) {
			continue
		}
		created, cok := generalizedTime(e.first("whenCreated"))
		stale = append(stale, map[string]any{
			"samAccountName":    e.first("sAMAccountName"),
			"name":              e.first("name"),
			"enabled":           !uacDisabled(e),
			"lastLogonDate":     isoOrNil(last, ok),
			"neverSignedIn":     !ok,
			"createdAt":         isoOrNil(created, cok),
			"distinguishedName": e.DN,
		})
	}
	sort.SliceStable(stale, func(i, j int) bool {
		a, b := stale[i]["enabled"].(bool), stale[j]["enabled"].(bool)
		if a != b {
			return a
		}
		return stale[i]["samAccountName"].(string) < stale[j]["samAccountName"].(string)
	})
	check := newAdCheck("stale-accounts", stale)
	check.Examined = intp(len(entries))
	check.ThresholdDays = intp(adStaleAfterDays)
	check.Note = "Read over LDAP by the appliance: the last sign-in is the directory's lastLogonTimestamp, which replicates and can lag the real last sign-in by days."
	return check
}

// groupType bits, from the directory: 0x80000000 a security group, and 0x2,
// 0x4, 0x8 a global, domain-local and universal scope.
func groupCategoryAndScope(e ldifEntry) (string, string) {
	n, err := strconv.ParseInt(e.first("groupType"), 10, 64)
	if err != nil {
		return "", ""
	}
	category := "Distribution"
	if uint32(n)&0x80000000 != 0 {
		category = "Security"
	}
	scope := ""
	switch {
	case n&0x2 != 0:
		scope = "Global"
	case n&0x4 != 0:
		scope = "DomainLocal"
	case n&0x8 != 0:
		scope = "Universal"
	}
	return category, scope
}

func groupChecks(r adRead) (adCheck, adCheck) {
	if r.Status != 0 {
		reason := readFailed(r, "groups")
		return couldNotAnswer("empty-groups", reason), couldNotAnswer("unowned-groups", reason)
	}
	entries, err := parseLDIF(r.Text)
	if err != nil {
		reason := "The groups read could not be parsed: " + err.Error()
		return couldNotAnswer("empty-groups", reason), couldNotAnswer("unowned-groups", reason)
	}
	var empty, unowned []map[string]any
	withMembers := 0
	rangedAny := false
	for _, e := range entries {
		category, scope := groupCategoryAndScope(e)
		count, ranged := e.members()
		if ranged {
			rangedAny = true
		}
		if count == 0 {
			created, ok := generalizedTime(e.first("whenCreated"))
			empty = append(empty, map[string]any{
				"name": e.first("name"), "groupCategory": category, "groupScope": scope,
				"createdAt": isoOrNil(created, ok), "distinguishedName": e.DN,
			})
			continue
		}
		withMembers++
		if strings.TrimSpace(e.first("managedBy")) == "" {
			unowned = append(unowned, map[string]any{
				"name": e.first("name"), "groupCategory": category, "memberCount": count, "distinguishedName": e.DN,
			})
		}
	}
	sort.SliceStable(empty, func(i, j int) bool { return empty[i]["name"].(string) < empty[j]["name"].(string) })
	sort.SliceStable(unowned, func(i, j int) bool {
		a, b := unowned[i]["memberCount"].(int), unowned[j]["memberCount"].(int)
		if a != b {
			return a > b
		}
		return unowned[i]["name"].(string) < unowned[j]["name"].(string)
	})
	emptyCheck := newAdCheck("empty-groups", empty)
	emptyCheck.Examined = intp(len(entries))
	unownedCheck := newAdCheck("unowned-groups", unowned)
	unownedCheck.Examined = intp(withMembers)
	if rangedAny {
		unownedCheck.Note = "Read over LDAP by the appliance: a group with more members than the directory returns at once is counted from what it returned, so its member count is a lower bound."
	}
	return emptyCheck, unownedCheck
}

// gpoInventoryCheck reads the Group Policy containers and the gPLink values
// that point at them. flags is MS-GPOL's: bit 0 ignores the GPO for user policy
// mode and bit 1 for computer policy mode ([MS-GPOL] GPO Search, updated
// 30 October 2024, read 16 October 2026).
func gpoInventoryCheck(gpos, links adRead) adCheck {
	if gpos.Status != 0 {
		return couldNotAnswer("gpo-inventory", readFailed(gpos, "Group Policy objects"))
	}
	entries, err := parseLDIF(gpos.Text)
	if err != nil {
		return couldNotAnswer("gpo-inventory", "The Group Policy objects read could not be parsed: "+err.Error())
	}
	var linked map[string][]string
	if links.Status == 0 {
		if containers, lerr := parseLDIF(links.Text); lerr == nil {
			linked = map[string][]string{}
			for _, c := range containers {
				for _, value := range c.all("gPLink") {
					for _, guid := range gpoGUIDs(value) {
						linked[guid] = append(linked[guid], c.DN)
					}
				}
			}
		}
	}
	var rows []map[string]any
	for _, e := range entries {
		guid := strings.ToLower(strings.Trim(e.first("cn"), "{}"))
		flags, _ := strconv.ParseInt(e.first("flags"), 10, 64)
		created, cok := generalizedTime(e.first("whenCreated"))
		changed, mok := generalizedTime(e.first("whenChanged"))
		row := map[string]any{
			"name": e.first("displayName"), "id": guid,
			"createdAt": isoOrNil(created, cok), "modifiedAt": isoOrNil(changed, mok),
			"computerEnabled": flags&0x2 == 0, "userEnabled": flags&0x1 == 0,
			"linkedTo": nil, "linkCount": nil,
		}
		if linked != nil {
			to := linked[guid]
			if to == nil {
				to = []string{}
			}
			row["linkedTo"] = to
			row["linkCount"] = len(to)
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i]["name"].(string) < rows[j]["name"].(string) })
	check := newAdCheck("gpo-inventory", rows)
	check.Note = "Read over LDAP by the appliance: modifiedAt is the directory object's whenChanged, which moves when the object changes and not when only its files on SYSVOL do."
	if linked == nil {
		check.Note += " Where each object is linked could not be read, so linkedTo is absent rather than empty."
	}
	return check
}

// gpoGUIDs takes the GUIDs out of a gPLink value: [LDAP://cn={GUID},cn=policies,...;0]...
func gpoGUIDs(value string) []string {
	var out []string
	for _, part := range strings.Split(value, "[") {
		open := strings.Index(part, "{")
		closing := strings.Index(part, "}")
		if open >= 0 && closing == open+37 {
			out = append(out, strings.ToLower(part[open+1:closing]))
		}
	}
	return out
}

// dnsName turns DC=example,DC=com into example.com.
func dnsName(dn string) string {
	var labels []string
	for _, rdn := range strings.Split(dn, ",") {
		rdn = strings.TrimSpace(rdn)
		if len(rdn) > 3 && strings.EqualFold(rdn[:3], "dc=") {
			labels = append(labels, rdn[3:])
		}
	}
	return strings.Join(labels, ".")
}

// rdnValue is the value of the rdn at index n of a DN, counting from 0.
func rdnValue(dn string, n int) string {
	parts := strings.Split(dn, ",")
	if n >= len(parts) {
		return ""
	}
	_, value, _ := strings.Cut(parts[n], "=")
	return value
}

// domainControllersCheck reads the nTDSDSA objects under the configuration
// partition, CN=NTDS Settings,CN=<server>,CN=Servers,CN=<site>,CN=Sites,...,
// and keeps those holding this domain.
func domainControllersCheck(r adRead, baseDN string) adCheck {
	if r.Status != 0 {
		return couldNotAnswer("domain-controllers", readFailed(r, "domain controllers"))
	}
	entries, err := parseLDIF(r.Text)
	if err != nil {
		return couldNotAnswer("domain-controllers", "The domain controllers read could not be parsed: "+err.Error())
	}
	domain := dnsName(baseDN)
	var rows []map[string]any
	for _, e := range entries {
		holds := false
		for _, nc := range append(e.all("msDS-hasDomainNCs"), e.all("hasMasterNCs")...) {
			if strings.EqualFold(strings.TrimSpace(nc), baseDN) {
				holds = true
			}
		}
		if !holds {
			continue
		}
		rows = append(rows, map[string]any{"name": rdnValue(e.DN, 1), "site": rdnValue(e.DN, 3), "domain": domain})
	}
	if len(rows) == 0 {
		return couldNotAnswer("domain-controllers", "The directory listed no domain controller holding this domain, which a domain that answered the other reads cannot have, so the list could not be read.")
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i]["name"].(string) < rows[j]["name"].(string) })
	return newAdCheck("domain-controllers", rows)
}

// dnsZonesCheck reads the dnsZone objects in the three places a directory keeps
// them. Only directory-integrated zones are in the directory, so a zone a server
// keeps in a file is not here, and the note says so.
func dnsZonesCheck(reads []adRead) adCheck {
	seen := map[string]bool{}
	var rows []map[string]any
	answered := 0
	var failed []string
	for _, r := range reads {
		switch r.Status {
		case 0:
			answered++
		case 32:
			continue
		default:
			failed = append(failed, readFailed(r, "a DNS zone container"))
			continue
		}
		entries, err := parseLDIF(r.Text)
		if err != nil {
			failed = append(failed, "A DNS zone container read could not be parsed: "+err.Error())
			continue
		}
		for _, e := range entries {
			name := e.first("dc")
			if name == "" || seen[strings.ToLower(name)] {
				continue
			}
			seen[strings.ToLower(name)] = true
			lower := strings.ToLower(name)
			rows = append(rows, map[string]any{
				"zoneName": name, "isDsIntegrated": true,
				"isReverseLookupZone": strings.HasSuffix(lower, ".in-addr.arpa") || strings.HasSuffix(lower, ".ip6.arpa"),
			})
		}
	}
	if len(failed) > 0 {
		return couldNotAnswer("dns-zones", strings.Join(failed, " "))
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i]["zoneName"].(string) < rows[j]["zoneName"].(string) })
	check := newAdCheck("dns-zones", rows)
	if answered == 0 {
		check.Note = "None of the places a directory keeps DNS zones exists here, so this domain keeps no zone in the directory."
	} else {
		check.Note = "Read over LDAP by the appliance: only zones kept in the directory are listed, and zoneType and isAutoCreated are not in the directory, so they are not sent."
	}
	return check
}

// readAdDir loads one read the shell wrote: <name>.ldif, <name>.status, <name>.said.
func readAdDir(dir, name string) adRead {
	text, terr := os.ReadFile(filepath.Join(dir, name+".ldif"))
	statusText, serr := os.ReadFile(filepath.Join(dir, name+".status"))
	said, _ := os.ReadFile(filepath.Join(dir, name+".said"))
	if terr != nil || serr != nil {
		return adRead{Status: -1, Said: "the shell left no file for this read, so it was not made"}
	}
	status, err := strconv.Atoi(strings.TrimSpace(string(statusText)))
	if err != nil {
		return adRead{Status: -1, Said: "the shell's record of this read's exit status could not be read"}
	}
	return adRead{Text: string(text), Status: status, Said: string(said)}
}

// buildAdChecks assembles every declared check, in the script's order.
func buildAdChecks(dir, baseDN string, collectedAt time.Time) []adCheck {
	built := map[string]adCheck{}
	built["stale-accounts"] = staleAccountsCheck(readAdDir(dir, "users"), collectedAt)
	built["empty-groups"], built["unowned-groups"] = groupChecks(readAdDir(dir, "groups"))
	built["gpo-inventory"] = gpoInventoryCheck(readAdDir(dir, "gpos"), readAdDir(dir, "gplinks"))
	built["domain-controllers"] = domainControllersCheck(readAdDir(dir, "dcs"), baseDN)
	built["dns-zones"] = dnsZonesCheck([]adRead{readAdDir(dir, "dns-domain"), readAdDir(dir, "dns-system"), readAdDir(dir, "dns-forest")})
	built["password-policy"] = passwordPolicyCheck(readAdDir(dir, "domain"), readAdDir(dir, "psos"))
	built["privileged-groups"] = privilegedGroupsCheck(readAdDir(dir, "domain"), readAdDir(dir, "groups"), readAdDir(dir, "users"))
	built["replication-failures"] = replicationFailuresCheck(readAdDir(dir, "dcs"), readAdDir(dir, "servers"), readReplDir(dir), baseDN)
	out := make([]adCheck, 0, len(adCheckIDs))
	for _, id := range adCheckIDs {
		if check, ok := built[id]; ok {
			out = append(out, check)
			continue
		}
		out = append(out, couldNotAnswer(id, adNotRead[id]))
	}
	return out
}

// buildAdSubmission is the whole of what leaves. Its items are the domain
// controllers the directory named: the door refuses a submission with no items,
// and writes none of an ad submission's items, so they are a count and a
// short list, never an inventory to retire against.
func buildAdSubmission(checks []adCheck, collectedAt time.Time, host, account, submissionID string) ([]byte, error) {
	items := []map[string]any{}
	for _, check := range checks {
		if check.ID == "domain-controllers" && check.State == "found" {
			items = check.Items
		}
	}
	return json.Marshal(map[string]any{
		"envelope": map[string]any{
			"schemaVersion": 1,
			"source":        "ad",
			"collectedAt":   collectedAt.UTC().Format(time.RFC3339),
			"senderVersion": "appliance-" + stamp(),
			"host":          host,
			"account":       account,
		},
		"declared": len(items),
		"part": map[string]any{
			"submissionId":  submissionID,
			"page":          1,
			"pages":         1,
			"totalDeclared": len(items),
		},
		"findings": checks,
		"items":    items,
	})
}

var errAdNotAsked = errors.New("not asked")

// collectAd is the -collect-ad mode: check the grant, build, sign, send.
func collectAd(portal, fingerprint string, private ed25519.PrivateKey, dir, baseDN, sysvolHost string, collectedAt time.Time) error {
	credential, err := fetchCredential(portal, fingerprint, private)
	if err != nil {
		return fmt.Errorf("%w: fetching the credential: %v", errAdNotAsked, err)
	}
	if !granted(credential, "ad") {
		return fmt.Errorf("%w: Active Directory is not among what this organization has allowed the collector to read", errAdNotAsked)
	}
	checks := buildAdChecks(dir, baseDN, collectedAt)
	for i := range checks {
		if checks[i].ID == "gpo-settings" {
			checks[i] = sysvolSettings(granted(credential, sysvolCapability), sysvolHost, baseDN, dir, readSysvol)
		}
	}
	answered := 0
	for _, check := range checks {
		if check.State != "could-not-answer" {
			answered++
		}
	}
	fmt.Printf("directory checks: %d of %d answered\n", answered, len(checks))
	for _, check := range checks {
		if check.ID == "domain-controllers" && check.State != "found" {
			// The door refuses a submission with no items, and the items are the
			// controllers, so this is said here rather than sent to be refused.
			return fmt.Errorf("the domain controllers could not be read (%s), so nothing was sent", check.Reason)
		}
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("minting a submission id: %w", err)
	}
	hostName, _ := os.Hostname()
	body, err := buildAdSubmission(checks, collectedAt, hostName, os.Getenv("CAIRN_PRINCIPAL"), hex.EncodeToString(id))
	if err != nil {
		return err
	}
	if err := signedPost(portal, collectionPath, "application/json", fingerprint, private, body); err != nil {
		return err
	}
	fmt.Println("submitted")
	return nil
}
