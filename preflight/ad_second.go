package main

// The Active Directory assessment's second slice: the password policy,
// privileged group membership walked through nested groups, and replication
// failures read from each of the domain's controllers. WO-1016-N40 item 2.
//
// The same discipline as ad.go: the shell made every read, this file turns the
// LDIF into the CheckResult shape the script assess-ad.ps1 produces, no verdict
// is made, and a read that did not happen is a could-not-answer that names why.
//
// Every attribute name below was read from Microsoft's Active Directory schema
// reference (learn.microsoft.com/windows/win32/adschema, each page ms.date
// 2018-05-31) on 16 October 2026: minPwdLength, pwdHistoryLength, maxPwdAge,
// minPwdAge, lockoutThreshold, lockoutDuration, lockOutObservationWindow, the
// class msDS-PasswordSettings and its msDS-MinimumPasswordLength,
// msDS-PasswordHistoryLength, msDS-PasswordComplexityEnabled,
// msDS-PasswordReversibleEncryptionEnabled, msDS-MaximumPasswordAge,
// msDS-MinimumPasswordAge, msDS-LockoutThreshold, msDS-LockoutDuration,
// msDS-LockoutObservationWindow, msDS-PasswordSettingsPrecedence and
// msDS-PSOAppliesTo. pwdProperties' bits DOMAIN_PASSWORD_COMPLEX (1) and
// DOMAIN_PASSWORD_STORE_CLEARTEXT (16) are from its own page, read the same
// day. The replication record's element names are DS_REPL_NEIGHBORW's fields
// in [MS-DRSR] (updated 2025-11-21), which [MS-ADTS] (updated 2026-08-24) says
// msDS-ReplAllInboundNeighbors carries as XML, integers in decimal and
// FILETIMEs as UTC dateTime.

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// pwdProperties bits, from the attribute's own page.
const (
	domainPasswordComplex        = 1
	domainPasswordStoreCleartext = 16
)

// An Interval is 100-nanosecond units; the directory stores a policy's ages
// and durations as negative numbers, so it is read as a magnitude.
const intervalsPerMinute = 600000000

// interval reads an Interval attribute as whole minutes. The smallest number
// the attribute can hold is not interpreted, so it is absent rather than a
// figure; so is a value that is not there or not a number.
func interval(value string) (float64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || n == math.MinInt64 {
		return 0, false
	}
	if n < 0 {
		n = -n
	}
	return float64(n) / intervalsPerMinute, true
}

// The script rounds a TimeSpan's TotalDays and TotalMinutes with [int], which
// rounds half to even; this rounds the same way so the two readers agree.
func intervalDays(value string) any {
	minutes, ok := interval(value)
	if !ok {
		return nil
	}
	return int(math.RoundToEven(minutes / (60 * 24)))
}

func intervalMinutes(value string) any {
	minutes, ok := interval(value)
	if !ok {
		return nil
	}
	return int(math.RoundToEven(minutes))
}

func integerOrNil(value string) any {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return nil
	}
	return int(n)
}

// The directory's Boolean syntax is TRUE or FALSE.
func booleanOrNil(value string) any {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "TRUE":
		return true
	case "FALSE":
		return false
	}
	return nil
}

// absentFields names the attributes an entry did not carry, so a null in the
// item is said to be a value the directory did not return rather than a zero.
func absentFields(e ldifEntry, names ...string) []string {
	var missing []string
	for _, name := range names {
		if strings.TrimSpace(e.first(name)) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

// passwordPolicyCheck reads the domain head object's policy and every
// msDS-PasswordSettings object, as the script's Get-ADDefaultDomainPasswordPolicy
// and Get-ADFineGrainedPasswordPolicy do.
func passwordPolicyCheck(domain, psos adRead) adCheck {
	if domain.Status != 0 {
		return couldNotAnswer("password-policy", readFailed(domain, "the domain's own object"))
	}
	entries, err := parseLDIF(domain.Text)
	if err != nil {
		return couldNotAnswer("password-policy", "The domain's own object could not be parsed: "+err.Error())
	}
	if len(entries) != 1 {
		return couldNotAnswer("password-policy", fmt.Sprintf("The read of the domain's own object returned %d entries where it names exactly one, so the policy could not be read.", len(entries)))
	}
	head := entries[0]
	properties, perr := strconv.ParseInt(strings.TrimSpace(head.first("pwdProperties")), 10, 64)
	complexity, reversible := any(nil), any(nil)
	if perr == nil {
		complexity = properties&domainPasswordComplex != 0
		reversible = properties&domainPasswordStoreCleartext != 0
	}
	policies := []map[string]any{{
		"scope":                       "domain-default",
		"name":                        "Default Domain Policy",
		"minPasswordLength":           integerOrNil(head.first("minPwdLength")),
		"passwordHistoryCount":        integerOrNil(head.first("pwdHistoryLength")),
		"complexityEnabled":           complexity,
		"reversibleEncryptionEnabled": reversible,
		"maxPasswordAgeDays":          intervalDays(head.first("maxPwdAge")),
		"minPasswordAgeDays":          intervalDays(head.first("minPwdAge")),
		"lockoutThreshold":            integerOrNil(head.first("lockoutThreshold")),
		"lockoutDurationMinutes":      intervalMinutes(head.first("lockoutDuration")),
		"lockoutObservationMinutes":   intervalMinutes(head.first("lockOutObservationWindow")),
	}}
	notes := []string{"Read over LDAP by the appliance: the domain-default row is the domain's own object, which the script labels Default Domain Policy; ages and durations are the magnitude of the directory's interval, rounded as the script rounds."}
	if missing := absentFields(head, "minPwdLength", "pwdHistoryLength", "pwdProperties", "maxPwdAge", "minPwdAge", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow"); len(missing) > 0 {
		notes = append(notes, "The domain's own object did not return "+strings.Join(missing, ", ")+", so those values are absent rather than zero.")
	}

	if psos.Status != 0 {
		policies = append(policies, map[string]any{
			"scope": "fine-grained",
			"error": "Could not read fine-grained policies: " + readFailed(psos, "password settings objects"),
		})
	} else if fine, ferr := parseLDIF(psos.Text); ferr != nil {
		policies = append(policies, map[string]any{
			"scope": "fine-grained",
			"error": "Could not read fine-grained policies: the read could not be parsed: " + ferr.Error(),
		})
	} else {
		var rows []map[string]any
		for _, e := range fine {
			appliesTo := e.all("msDS-PSOAppliesTo")
			if appliesTo == nil {
				appliesTo = []string{}
			}
			rows = append(rows, map[string]any{
				"scope":                  "fine-grained",
				"name":                   e.first("name"),
				"precedence":             integerOrNil(e.first("msDS-PasswordSettingsPrecedence")),
				"appliesTo":              appliesTo,
				"minPasswordLength":      integerOrNil(e.first("msDS-MinimumPasswordLength")),
				"passwordHistoryCount":   integerOrNil(e.first("msDS-PasswordHistoryLength")),
				"complexityEnabled":      booleanOrNil(e.first("msDS-PasswordComplexityEnabled")),
				"maxPasswordAgeDays":     intervalDays(e.first("msDS-MaximumPasswordAge")),
				"lockoutThreshold":       integerOrNil(e.first("msDS-LockoutThreshold")),
				"lockoutDurationMinutes": intervalMinutes(e.first("msDS-LockoutDuration")),
			})
		}
		sort.SliceStable(rows, func(i, j int) bool { return rows[i]["name"].(string) < rows[j]["name"].(string) })
		policies = append(policies, rows...)
	}
	check := newAdCheck("password-policy", policies)
	check.Note = strings.Join(notes, " ")
	return check
}

// sidString turns the directory's binary objectSid into S-1-5-21-... form:
// a revision byte, a count of sub-authorities, a six-byte big-endian
// authority, then each sub-authority as four little-endian bytes.
func sidString(raw string) (string, bool) {
	b := []byte(raw)
	if len(b) < 8 {
		return "", false
	}
	count := int(b[1])
	if len(b) != 8+4*count {
		return "", false
	}
	var authority uint64
	for _, v := range b[2:8] {
		authority = authority<<8 | uint64(v)
	}
	parts := []string{"S", strconv.Itoa(int(b[0])), strconv.FormatUint(authority, 10)}
	for i := 0; i < count; i++ {
		parts = append(parts, strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[8+4*i:12+4*i])), 10))
	}
	return strings.Join(parts, "-"), true
}

// The groups the script reads, by SID, because they are renamed and localised.
// Enterprise Admins and Schema Admins exist only in the forest root, so a
// group that is not here is skipped, as the script skips it.
var privilegedGroups = []struct{ name, rid, builtin string }{
	{"Domain Admins", "512", ""},
	{"Enterprise Admins", "519", ""},
	{"Schema Admins", "518", ""},
	{"Administrators", "", "S-1-5-32-544"},
	{"Account Operators", "", "S-1-5-32-548"},
	{"Backup Operators", "", "S-1-5-32-551"},
	{"Server Operators", "", "S-1-5-32-549"},
}

// privilegedGroupsCheck walks each privileged group's member list through
// every nested group it holds, as Get-ADGroupMember -Recursive does, and
// reports the members that are not groups.
func privilegedGroupsCheck(domain, groups, users adRead) adCheck {
	for _, r := range []struct {
		read adRead
		what string
	}{{domain, "the domain's own object"}, {groups, "groups"}, {users, "user accounts"}} {
		if r.read.Status != 0 {
			return couldNotAnswer("privileged-groups", readFailed(r.read, r.what))
		}
	}
	heads, err := parseLDIF(domain.Text)
	if err != nil || len(heads) != 1 {
		return couldNotAnswer("privileged-groups", "The domain's own object could not be read as one entry, so the domain's identifier, which names its privileged groups, is not known.")
	}
	domainSid, ok := sidString(heads[0].first("objectSid"))
	if !ok {
		return couldNotAnswer("privileged-groups", "The domain's own object returned no identifier this reader could read, so its privileged groups cannot be named.")
	}
	groupEntries, err := parseLDIF(groups.Text)
	if err != nil {
		return couldNotAnswer("privileged-groups", "The groups read could not be parsed: "+err.Error())
	}
	userEntries, err := parseLDIF(users.Text)
	if err != nil {
		return couldNotAnswer("privileged-groups", "The user accounts read could not be parsed: "+err.Error())
	}

	bySid := map[string]ldifEntry{}
	groupByDN := map[string]ldifEntry{}
	for _, g := range groupEntries {
		groupByDN[strings.ToLower(g.DN)] = g
		if sid, ok := sidString(g.first("objectSid")); ok {
			bySid[sid] = g
		}
	}
	userByDN := map[string]ldifEntry{}
	for _, u := range userEntries {
		userByDN[strings.ToLower(u.DN)] = u
	}

	twin := func(u ldifEntry) any {
		given, sn := u.first("givenName"), u.first("sn")
		if given == "" || sn == "" {
			return nil
		}
		for _, other := range userEntries {
			if !strings.EqualFold(other.DN, u.DN) && !uacDisabled(other) && other.first("givenName") == given && other.first("sn") == sn {
				return other.first("sAMAccountName")
			}
		}
		return nil
	}

	var rows []map[string]any
	found, ranged, unknown := 0, false, 0
	for _, want := range privilegedGroups {
		sid := want.builtin
		if sid == "" {
			sid = domainSid + "-" + want.rid
		}
		group, ok := bySid[sid]
		if !ok {
			continue
		}
		found++
		seen := map[string]bool{strings.ToLower(group.DN): true}
		emitted := map[string]bool{}
		queue := []ldifEntry{group}
		for len(queue) > 0 {
			g := queue[0]
			queue = queue[1:]
			if _, r := g.members(); r {
				ranged = true
			}
			for key, values := range g.Attrs {
				lower := strings.ToLower(key)
				if lower != "member" && !strings.HasPrefix(lower, "member;range=") {
					continue
				}
				for _, dn := range values {
					k := strings.ToLower(dn)
					if nested, isGroup := groupByDN[k]; isGroup {
						if !seen[k] {
							seen[k] = true
							queue = append(queue, nested)
						}
						continue
					}
					if emitted[k] {
						continue
					}
					emitted[k] = true
					row := map[string]any{
						"group": want.name, "distinguishedName": dn,
						"samAccountName": "", "name": rdnValue(dn, 0), "objectClass": nil,
						"enabled": nil, "lastLogonDate": nil, "hasMailbox": nil, "otherEnabledAccountSameName": nil,
					}
					if u, isUser := userByDN[k]; isUser {
						last, lok := fileTime(u.first("lastLogonTimestamp"))
						row["samAccountName"] = u.first("sAMAccountName")
						row["name"] = u.first("name")
						row["objectClass"] = "user"
						row["enabled"] = !uacDisabled(u)
						row["lastLogonDate"] = isoOrNil(last, lok)
						row["hasMailbox"] = strings.TrimSpace(u.first("mail")) != ""
						row["otherEnabledAccountSameName"] = twin(u)
					} else {
						unknown++
					}
					rows = append(rows, row)
				}
			}
		}
	}
	if found == 0 {
		return couldNotAnswer("privileged-groups", "None of the privileged groups was among the groups the directory returned, which a domain cannot be without, so their membership could not be read.")
	}
	check := newAdCheck("privileged-groups", rows)
	check.Examined = intp(found)
	notes := []string{"Read over LDAP by the appliance: nested groups are walked through the groups read, and a member's primary group is not in any member list, so an account that holds a privileged group only as its primary group is not listed."}
	if ranged {
		notes = append(notes, "A group with more members than the directory returns at once is listed from what it returned, so its membership is a lower bound.")
	}
	if unknown > 0 {
		notes = append(notes, fmt.Sprintf("%d members are not user accounts this reader read (a computer, an account from another domain, or a contact), so only their name and distinguished name are sent.", unknown))
	}
	check.Note = strings.Join(notes, " ")
	return check
}

// One inbound neighbor, as a domain controller returns it in
// msDS-ReplAllInboundNeighbors: one XML document per value.
type replNeighbor struct {
	NamingContext       string `xml:"pszNamingContext"`
	SourceDsaDN         string `xml:"pszSourceDsaDN"`
	SourceDsaAddress    string `xml:"pszSourceDsaAddress"`
	LastSyncSuccess     string `xml:"ftimeLastSyncSuccess"`
	LastSyncAttempt     string `xml:"ftimeLastSyncAttempt"`
	LastSyncResult      string `xml:"dwLastSyncResult"`
	ConsecutiveFailures string `xml:"cNumConsecutiveSyncFailures"`
}

func xmlTimeOrNil(value string) any {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// replRead is one controller's rootDSE read and the host the shell asked.
type replRead struct {
	host string
	read adRead
}

// readReplDir loads every repl-<n> read the shell made, with its .host file.
func readReplDir(dir string) []replRead {
	matches, _ := filepath.Glob(filepath.Join(dir, "repl-*.host"))
	sort.Strings(matches)
	var out []replRead
	for _, path := range matches {
		host, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(path), ".host")
		out = append(out, replRead{host: strings.TrimSpace(string(host)), read: readAdDir(dir, name)})
	}
	return out
}

// domainControllerHosts names the host of every controller holding this
// domain: the server object above each nTDSDSA, and its dNSHostName.
func domainControllerHosts(dcs, servers adRead, baseDN string) (hosts []string, unnamed []string, reason string) {
	if dcs.Status != 0 {
		return nil, nil, readFailed(dcs, "domain controllers")
	}
	if servers.Status != 0 {
		return nil, nil, readFailed(servers, "the server objects that name each controller's host")
	}
	dsas, err := parseLDIF(dcs.Text)
	if err != nil {
		return nil, nil, "The domain controllers read could not be parsed: " + err.Error()
	}
	serverEntries, err := parseLDIF(servers.Text)
	if err != nil {
		return nil, nil, "The server objects read could not be parsed: " + err.Error()
	}
	hostOf := map[string]string{}
	for _, s := range serverEntries {
		hostOf[strings.ToLower(s.DN)] = strings.TrimSpace(s.first("dNSHostName"))
	}
	for _, e := range dsas {
		holds := false
		for _, nc := range append(e.all("msDS-hasDomainNCs"), e.all("hasMasterNCs")...) {
			if strings.EqualFold(strings.TrimSpace(nc), baseDN) {
				holds = true
			}
		}
		if !holds {
			continue
		}
		_, server, _ := strings.Cut(e.DN, ",")
		if host := hostOf[strings.ToLower(server)]; host != "" {
			hosts = append(hosts, host)
		} else {
			unnamed = append(unnamed, rdnValue(e.DN, 1))
		}
	}
	sort.Strings(hosts)
	sort.Strings(unnamed)
	return hosts, unnamed, ""
}

// replicationFailuresCheck reads each of the domain's controllers' inbound
// neighbors and lists those whose last attempt failed and has gone on failing,
// as Get-ADReplicationFailure -Scope Domain lists them.
func replicationFailuresCheck(dcs, servers adRead, repl []replRead, baseDN string) adCheck {
	hosts, unnamed, reason := domainControllerHosts(dcs, servers, baseDN)
	if reason != "" {
		return couldNotAnswer("replication-failures", reason)
	}
	readOf := map[string]adRead{}
	for _, r := range repl {
		readOf[strings.ToLower(r.host)] = r.read
	}
	var rows []map[string]any
	answered := 0
	var failed []string
	for _, host := range hosts {
		r, made := readOf[strings.ToLower(host)]
		if !made {
			failed = append(failed, host+" (the shell made no read of it)")
			continue
		}
		if r.Status != 0 {
			failed = append(failed, host+" ("+readFailed(r, "its replication partners")+")")
			continue
		}
		entries, err := parseLDIF(r.Text)
		if err != nil || len(entries) != 1 {
			failed = append(failed, host+" (its rootDSE could not be read as one entry)")
			continue
		}
		answered++
		for _, value := range entries[0].all("msDS-ReplAllInboundNeighbors") {
			var n replNeighbor
			if err := xml.Unmarshal([]byte(value), &n); err != nil {
				failed = append(failed, host+" (a replication partner's record was not XML this reader could read)")
				continue
			}
			failures, ferr := strconv.Atoi(strings.TrimSpace(n.ConsecutiveFailures))
			if ferr != nil || failures <= 0 {
				continue
			}
			rows = append(rows, map[string]any{
				"server": host, "partner": n.SourceDsaDN, "partnerAddress": n.SourceDsaAddress,
				"namingContext": n.NamingContext, "failureCount": failures,
				"failureType": nil, "firstFailureTime": nil,
				"lastError":       strings.TrimSpace(n.LastSyncResult),
				"lastSuccessTime": xmlTimeOrNil(n.LastSyncSuccess), "lastAttemptTime": xmlTimeOrNil(n.LastSyncAttempt),
			})
		}
	}
	if answered == 0 {
		why := "No domain controller of this domain could be asked for its replication partners."
		if len(failed) > 0 {
			why += " " + strings.Join(failed, "; ") + "."
		}
		if len(unnamed) > 0 {
			why += " The directory names no host for " + strings.Join(unnamed, ", ") + "."
		}
		return couldNotAnswer("replication-failures", why)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i]["server"].(string)+rows[i]["partner"].(string), rows[j]["server"].(string)+rows[j]["partner"].(string)
		return a < b
	})
	check := newAdCheck("replication-failures", rows)
	check.Examined = intp(answered)
	notes := []string{"Read over LDAP by the appliance from each controller's msDS-ReplAllInboundNeighbors: one row per partner and naming context whose consecutive failures are above zero; failureCount is that count, lastError the last result as a decimal code, and failureType and firstFailureTime are not in what a controller returns, so they are absent."}
	if len(failed) > 0 {
		notes = append(notes, "Not read: "+strings.Join(failed, "; ")+".")
	}
	if len(unnamed) > 0 {
		notes = append(notes, "The directory names no host for "+strings.Join(unnamed, ", ")+", so it was not asked.")
	}
	check.Note = strings.Join(notes, " ")
	return check
}
