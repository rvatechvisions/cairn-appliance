package main

// Group Policy setting values, read from SYSVOL. WO-1017-N54 item 3, on
// Jackie's decision of 16 October 2026 (the portal's CLAUDE.md, beside the
// collector rules): the appliance may read setting values from SYSVOL, as a
// permission a client grants separately, read-only, and only the named
// settings, never whole policy files.
//
// ## What is read, and from where
//
// Each Group Policy object linked somewhere in the domain keeps its security
// settings in one file: <Sysvol>\<Domain>\Policies\{GUID}\Machine\Microsoft\
// Windows NT\SecEdit\GptTmpl.inf (Microsoft's troubleshooting article "Reset
// user rights in the Default Domain Controller Policy GPO", ms.date
// 2026-02-12, read 17 October 2026). Its format is MS-GPSB's: UTF-16LE with a
// byte-order mark, a [Registry Values] section whose lines are
// RegistryValueName=RegistryValueType,RegistryValue, the name possibly in
// quotes, type 4 a DWORD, numbers decimal unless prefixed 0x ([MS-GPSB]
// Registry Values, updated 2024-04-23, and Message Syntax, updated
// 2024-10-30, both read 17 October 2026).
//
// These values are taken from that section, and nothing else in the file is
// kept:
//   - inactivity-limit: MACHINE\Software\Microsoft\Windows\CurrentVersion\
//     Policies\System\InactivityTimeoutSecs, a DWORD of seconds;
//   - lan-manager-level: MACHINE\System\CurrentControlSet\Control\Lsa\
//     LmCompatibilityLevel, a DWORD from 0 to 5;
//   - logon-message and logon-message-title: LegalNoticeText and
//     LegalNoticeCaption under the same Policies\System key, strings.
//
// ## The sign-in notice
//
// ~~Not read: no current Microsoft page read on 17 October 2026 named the
// registry value the policy writes.~~ Corrected where it stands by WO-1017-N55
// item 7, the same day: a current Microsoft page names both values (see
// gptSettings). They are read as strings only.
//
// ## What leaves
//
// For each value found, one item: the setting, the policy's display name, and
// the object it came from, by name and id. A DWORD carries its value. The
// notice carries whether it is set and its length in characters, never its
// words. Nothing else from the file, and no file that is not one of these.
//
// ## Read-only, and the session ends
//
// The share is opened for reading and each file is read whole and closed. The
// session is signed off explicitly when the read finishes, whatever the read
// did, and a sign-off that fails is reported on the check rather than
// swallowed: read-only forbids anything that outlives the read.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	msrpcsmb2 "github.com/oiweiwei/go-msrpc/smb2"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

// sysvolCapability is the consent this read rides on. It is its own
// permission, never Active Directory's.
const sysvolCapability = "sysvol"

// gptSetting is one value this reader takes from a GptTmpl.inf.
type gptSetting struct {
	setting string // the check's own name for it, the script's
	policy  string // the policy's display name, the script's
	value   string // the [Registry Values] name, compared without regard to case
	text    bool   // a string (type 1) rather than a DWORD (type 4)
}

// gptSettings are the values read. Held by TestOnlyTheNamedValuesAreRead.
//
// The sign-in notice's two values were named by a current Microsoft page on
// 17 October 2026, WO-1017-N55 item 7: "Manage security defaults for Azure
// Local" (ms.date 2025-10-23) fixes the rules "Interactive logon: Message text
// for users attempting to log on" and "... Message title ..." by setting
// LegalNoticeText and LegalNoticeCaption under
// HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System, as strings.
// Only a string is read: another type is named as unread, never guessed at.
var gptSettings = []gptSetting{
	{"inactivity-limit", "Interactive logon: Machine inactivity limit",
		`MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs`, false},
	{"lan-manager-level", "Network security: LAN Manager authentication level",
		`MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel`, false},
	{"logon-message", "Interactive logon: Message text for users attempting to log on",
		`MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText`, true},
	{"logon-message-title", "Interactive logon: Message title for users attempting to log on",
		`MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption`, true},
}

// gptValue is one value found. A DWORD leaves as its number. A notice leaves
// as whether it is set and its length in characters, never its words: those
// are the client's own text, and whether a notice is shown is the question.
type gptValue struct {
	setting string
	policy  string
	number  int64
	text    bool
	length  int
}

// decodeGptTmpl turns the file's bytes into text. MS-GPSB says Unicode, and a
// file that does not start with the UTF-16LE mark is refused by name rather
// than guessed at.
func decodeGptTmpl(raw []byte) (string, error) {
	if len(raw) < 2 || raw[0] != 0xFF || raw[1] != 0xFE {
		return "", errors.New("the file does not begin with the UTF-16LE byte-order mark MS-GPSB describes")
	}
	body := raw[2:]
	if len(body)%2 != 0 {
		return "", errors.New("the file has an odd number of bytes after its byte-order mark, so it is not UTF-16")
	}
	units := make([]uint16, len(body)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(body[2*i:])
	}
	return string(utf16.Decode(units)), nil
}

// parseGptTmpl reads the [Registry Values] section and returns only the named
// values. A named value whose type is not a DWORD, or whose number does not
// read, is an error naming it: a value we could not read is never a value we
// did not find.
func parseGptTmpl(raw []byte) ([]gptValue, error) {
	text, err := decodeGptTmpl(raw)
	if err != nil {
		return nil, err
	}
	var out []gptValue
	inSection := false
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inSection = strings.EqualFold(strings.TrimSpace(line[1:len(line)-1]), "Registry Values")
			continue
		}
		if !inSection {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		name := strings.Trim(strings.TrimSpace(line[:eq]), `"`)
		var wanted *gptSetting
		for i := range gptSettings {
			if strings.EqualFold(name, gptSettings[i].value) {
				wanted = &gptSettings[i]
			}
		}
		if wanted == nil {
			continue
		}
		typeText, valueText, ok := strings.Cut(line[eq+1:], ",")
		if !ok {
			return nil, fmt.Errorf("%s is set with no type and value", wanted.setting)
		}
		if wanted.text {
			if strings.TrimSpace(typeText) != "1" {
				return nil, fmt.Errorf("%s is set with type %s, and only a string (type 1) is read", wanted.setting, strings.TrimSpace(typeText))
			}
			words := strings.Trim(strings.TrimSpace(valueText), `"`)
			out = append(out, gptValue{setting: wanted.setting, policy: wanted.policy, text: true, length: len([]rune(words))})
			continue
		}
		if strings.TrimSpace(typeText) != "4" {
			return nil, fmt.Errorf("%s is set with type %s, and only a DWORD (type 4) is read", wanted.setting, strings.TrimSpace(typeText))
		}
		valueText = strings.Trim(strings.TrimSpace(valueText), `"`)
		var number int64
		if strings.HasPrefix(strings.ToLower(valueText), "0x") {
			number, err = strconv.ParseInt(valueText[2:], 16, 64)
		} else {
			number, err = strconv.ParseInt(valueText, 10, 64)
		}
		if err != nil || number < 0 || number > 0xFFFFFFFF {
			return nil, fmt.Errorf("%s is set to %q, which is not a DWORD", wanted.setting, valueText)
		}
		out = append(out, gptValue{setting: wanted.setting, policy: wanted.policy, number: number})
	}
	return out, nil
}

// linkedGPOs is every object a gPLink names, with its display name from the
// containers read. The link's own options are not read: a link that is
// switched off still names the object.
func linkedGPOs(gpos, links adRead) (map[string]string, error) {
	if gpos.Status != 0 {
		return nil, errors.New(readFailed(gpos, "Group Policy objects"))
	}
	if links.Status != 0 {
		return nil, errors.New(readFailed(links, "Group Policy links"))
	}
	entries, err := parseLDIF(gpos.Text)
	if err != nil {
		return nil, fmt.Errorf("the Group Policy objects read could not be parsed: %v", err)
	}
	containers, err := parseLDIF(links.Text)
	if err != nil {
		return nil, fmt.Errorf("the Group Policy links read could not be parsed: %v", err)
	}
	names := map[string]string{}
	for _, e := range entries {
		names[strings.ToLower(strings.Trim(e.first("cn"), "{}"))] = e.first("displayName")
	}
	linked := map[string]string{}
	for _, c := range containers {
		for _, value := range c.all("gPLink") {
			for _, guid := range gpoGUIDs(value) {
				linked[guid] = names[guid]
			}
		}
	}
	return linked, nil
}

// gptFileReader reads one object's GptTmpl.inf by its GUID. An object with no
// such file returns an error satisfying errors.Is(err, os.ErrNotExist).
type gptFileReader func(guid string) ([]byte, error)

// gpoSettingsCheck builds the check from the linked objects and their files.
// signOff is what ending the session said, nil when it ended cleanly.
func gpoSettingsCheck(gpos, links adRead, read gptFileReader, signOff error) adCheck {
	linked, err := linkedGPOs(gpos, links)
	if err != nil {
		return couldNotAnswer("gpo-settings", err.Error())
	}
	guids := make([]string, 0, len(linked))
	for guid := range linked {
		guids = append(guids, guid)
	}
	sort.Strings(guids)
	var rows []map[string]any
	var unread []string
	withFile := 0
	for _, guid := range guids {
		raw, err := read(guid)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			unread = append(unread, fmt.Sprintf("%s (%s): %v", linked[guid], guid, err))
			continue
		}
		withFile++
		values, err := parseGptTmpl(raw)
		if err != nil {
			unread = append(unread, fmt.Sprintf("%s (%s): %v", linked[guid], guid, err))
			continue
		}
		for _, v := range values {
			row := map[string]any{"setting": v.setting, "policy": v.policy, "name": linked[guid], "id": guid}
			if v.text {
				row["set"] = v.length > 0
				row["length"] = v.length
			} else {
				row["value"] = v.number
			}
			rows = append(rows, row)
		}
	}
	if len(guids) > 0 && len(unread) == len(guids) {
		return couldNotAnswer("gpo-settings", "No linked Group Policy object's security settings could be read from SYSVOL: "+strings.Join(unread, "; "))
	}
	check := newAdCheck("gpo-settings", rows)
	check.Examined = intp(len(guids))
	note := fmt.Sprintf("Read from SYSVOL by the appliance: the value each linked object sets, from its security template. %d linked objects were looked at, %d carry a security template.", len(guids), withFile)
	note += " The sign-in notice is sent as whether it is set and its length, never its words."
	if len(unread) > 0 {
		note += fmt.Sprintf(" %d objects could not be read, so this is a lower bound: %s.", len(unread), strings.Join(unread, "; "))
	}
	if signOff != nil {
		note += " Cairn could not end its SYSVOL session cleanly, so it may stay open on the domain controller until it times out: " + signOff.Error()
	}
	check.Note = note
	return check
}

// sysvolNotGranted is the check when the organization has not allowed it.
func sysvolNotGranted() adCheck {
	return couldNotAnswer("gpo-settings", "Reading Group Policy setting values from SYSVOL is its own permission, and this organization has not granted it.")
}

// sysvolSettings decides the gpo-settings check for one run. The grant comes
// first: without it SYSVOL is never opened, whatever else is true. read is
// readSysvol in a run and a fixture in a test.
func sysvolSettings(grantedSysvol bool, host, baseDN, dir string, read func(host, domain string, gpos, links adRead) adCheck) adCheck {
	if !grantedSysvol {
		return sysvolNotGranted()
	}
	if host == "" {
		return couldNotAnswer("gpo-settings", "SYSVOL is granted, and this box's script named no domain controller to read it on, so it was not opened. That is this box's software, not the domain.")
	}
	return read(host, dnsName(baseDN), readAdDir(dir, "gpos"), readAdDir(dir, "gplinks"))
}

// gptPath is where one object's security template is kept, inside the share.
func gptPath(domain, guid string) string {
	return domain + `\Policies\{` + strings.ToUpper(guid) + `}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`
}

// readSysvol opens SYSVOL on host over SMB with the run's Kerberos ticket,
// reads each linked object's template through the check, and signs off. The
// ticket and the mechanism are the ones bindDHCP sets up; Kerberos only, with
// no NTLM to fall back through.
func readSysvol(host, domain string, gpos, links adRead) adCheck {
	if host == "" || strings.ContainsAny(host, "/\\ ") {
		return couldNotAnswer("gpo-settings", "The domain controller's name is not a plain host name, so SYSVOL was not opened.")
	}
	if err := setupKerberos(); err != nil {
		return couldNotAnswer("gpo-settings", "The run's Kerberos ticket could not be used for SYSVOL: "+err.Error())
	}
	dialer := msrpcsmb2.NewDialer(
		msrpcsmb2.WithSign(),
		msrpcsmb2.WithSecurity(gssapi.WithTargetName("cifs/"+host)),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, "445"))
	if err != nil {
		return couldNotAnswer("gpo-settings", "SYSVOL could not be reached on the domain controller: "+err.Error())
	}
	defer conn.Close()
	session, err := dialer.DialContext(ctx, conn)
	if err != nil {
		return couldNotAnswer("gpo-settings", "The domain controller did not accept a SYSVOL session: "+err.Error())
	}
	share, err := session.Mount("SYSVOL")
	if err != nil {
		signOff := session.Logoff()
		return couldNotAnswer("gpo-settings", "SYSVOL could not be opened: "+err.Error()+signOffSentence(signOff))
	}
	reader := func(guid string) ([]byte, error) {
		return share.ReadFile(gptPath(domain, guid))
	}
	check := gpoSettingsCheck(gpos, links, reader, nil)
	umount := share.Umount()
	signOff := session.Logoff()
	if failure := errors.Join(umount, signOff); failure != nil {
		if check.State == "could-not-answer" {
			check.Reason += signOffSentence(failure)
		} else {
			check.Note += " Cairn could not end its SYSVOL session cleanly, so it may stay open on the domain controller until it times out: " + failure.Error()
		}
	}
	return check
}

func signOffSentence(err error) string {
	if err == nil {
		return ""
	}
	return " Cairn also could not end its SYSVOL session cleanly: " + err.Error()
}
