package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"
)

// encodeGptTmpl writes a fixture the way MS-GPSB describes the file: the
// UTF-16LE byte-order mark, then UTF-16LE text with CRLF line ends.
func encodeGptTmpl(lines ...string) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xFE})
	for _, unit := range utf16.Encode([]rune(strings.Join(lines, "\r\n") + "\r\n")) {
		_ = binary.Write(&buf, binary.LittleEndian, unit)
	}
	return buf.Bytes()
}

const defaultPolicyGUID = "31b2f340-016d-11d2-945f-00c04fb984f9"
const unlinkedGUID = "0a1b2c3d-0000-0000-0000-000000000001"

// A template shaped as MS-GPSB's Message Syntax gives it, carrying the two
// named values beside others that must not leave. NoLMHash is the line
// Microsoft's own example template carries.
func defaultPolicyTemplate() []byte {
	return encodeGptTmpl(
		"[Unicode]", "Unicode=yes",
		"[System Access]", "MinimumPasswordLength = 14", "ClearTextPassword = 0",
		"[Version]", `signature="$CHICAGO$"`, "Revision=1",
		"[Registry Values]",
		`MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1`,
		`MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5`,
		`machine\software\microsoft\windows\currentversion\policies\system\inactivitytimeoutsecs=4,900`,
		`MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=1,"Authorized use only"`,
		`MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption=1,"Notice"`,
		`MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,1`,
	)
}

type recordingReader struct {
	asked []string
	files map[string][]byte
	err   map[string]error
}

func (r *recordingReader) read(guid string) ([]byte, error) {
	r.asked = append(r.asked, guid)
	if err, ok := r.err[guid]; ok {
		return nil, err
	}
	if raw, ok := r.files[guid]; ok {
		return raw, nil
	}
	return nil, os.ErrNotExist
}

func TestOnlyTheNamedValuesAreRead(t *testing.T) {
	dir := fixtureDir(t)
	reader := &recordingReader{files: map[string][]byte{defaultPolicyGUID: defaultPolicyTemplate()}}
	c := gpoSettingsCheck(readAdDir(dir, "gpos"), readAdDir(dir, "gplinks"), reader.read, nil)
	if c.State != "found" || c.Count != 4 || c.Examined == nil || *c.Examined != 1 {
		t.Fatalf("got %s count %d examined %v: %+v", c.State, c.Count, c.Examined, c)
	}
	got := map[string]map[string]any{}
	for _, item := range c.Items {
		keys := []string{}
		for k := range item {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		want := "id,name,policy,setting,value"
		if strings.HasPrefix(item["setting"].(string), "logon-message") {
			want = "id,length,name,policy,set,setting"
		}
		if strings.Join(keys, ",") != want {
			t.Fatalf("%v carries %v; only %s leave", item["setting"], keys, want)
		}
		if item["id"] != defaultPolicyGUID || item["name"] != "Default Domain Policy" {
			t.Fatalf("an item names %v %v, not the object it came from", item["name"], item["id"])
		}
		got[item["setting"].(string)] = item
	}
	if got["inactivity-limit"]["value"] != int64(900) || got["lan-manager-level"]["value"] != int64(5) {
		t.Fatalf("values read %v, want 900 seconds and level 5", got)
	}
	if got["logon-message"]["set"] != true || got["logon-message"]["length"] != 19 || got["logon-message-title"]["length"] != 6 {
		t.Fatalf("the notice read %v and %v, want set, 19 and 6 characters", got["logon-message"], got["logon-message-title"])
	}
	for _, item := range c.Items {
		for _, v := range item {
			if s, ok := v.(string); ok && strings.Contains(s, "Authorized use only") {
				t.Fatalf("the notice's words left the box: %v", item)
			}
		}
	}
	if _, read := got["dont-display-last-user-name"]; read || len(got) != 4 {
		t.Fatalf("a value nobody named was read: %v", got)
	}
}

func TestANoticeOfAnotherTypeIsUnreadNotGuessed(t *testing.T) {
	values, err := parseGptTmpl(encodeGptTmpl("[Registry Values]",
		`MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText=7,line one,line two`))
	if err == nil || !strings.Contains(err.Error(), "logon-message") || !strings.Contains(err.Error(), "type 7") {
		t.Fatalf("got %+v %v; a notice not stored as a string is named as unread", values, err)
	}
}

func TestAnUnlinkedObjectIsNeverRead(t *testing.T) {
	dir := fixtureDir(t)
	reader := &recordingReader{files: map[string][]byte{
		defaultPolicyGUID: defaultPolicyTemplate(),
		unlinkedGUID:      defaultPolicyTemplate(),
	}}
	gpoSettingsCheck(readAdDir(dir, "gpos"), readAdDir(dir, "gplinks"), reader.read, nil)
	if strings.Join(reader.asked, ",") != defaultPolicyGUID {
		t.Fatalf("asked for %v; only objects a gPLink names are read", reader.asked)
	}
}

func TestAnObjectWithNoTemplateIsNotFoundAndCounted(t *testing.T) {
	dir := fixtureDir(t)
	reader := &recordingReader{}
	c := gpoSettingsCheck(readAdDir(dir, "gpos"), readAdDir(dir, "gplinks"), reader.read, nil)
	if c.State != "not-found" || *c.Examined != 1 || !strings.Contains(c.Note, "0 carry a security template") {
		t.Fatalf("got %s examined %d note %q", c.State, *c.Examined, c.Note)
	}
}

func TestAFileItCannotReadIsNeverReadAsNotSet(t *testing.T) {
	dir := fixtureDir(t)
	for name, raw := range map[string][]byte{
		"no byte-order mark": []byte("[Registry Values]\r\n"),
		"a value not a DWORD": encodeGptTmpl("[Registry Values]",
			`MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=1,5`),
		"a number that does not read": encodeGptTmpl("[Registry Values]",
			`MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,five`),
	} {
		reader := &recordingReader{files: map[string][]byte{defaultPolicyGUID: raw}}
		c := gpoSettingsCheck(readAdDir(dir, "gpos"), readAdDir(dir, "gplinks"), reader.read, nil)
		if c.State != "could-not-answer" || !strings.Contains(c.Reason, "Default Domain Policy") {
			t.Fatalf("%s: got %s %q; an unreadable template is a read that did not happen", name, c.State, c.Reason)
		}
	}
	reader := &recordingReader{err: map[string]error{defaultPolicyGUID: errors.New("STATUS_ACCESS_DENIED")}}
	c := gpoSettingsCheck(readAdDir(dir, "gpos"), readAdDir(dir, "gplinks"), reader.read, nil)
	if c.State != "could-not-answer" || !strings.Contains(c.Reason, "STATUS_ACCESS_DENIED") {
		t.Fatalf("a refused file: got %s %q", c.State, c.Reason)
	}
}

func TestAQuotedNameAndAHexValueRead(t *testing.T) {
	values, err := parseGptTmpl(encodeGptTmpl("[Registry Values]",
		`"MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel"=4,0x3`))
	if err != nil || len(values) != 1 || values[0].number != 3 || values[0].setting != "lan-manager-level" {
		t.Fatalf("got %+v %v", values, err)
	}
}

func TestAValueOutsideRegistryValuesIsNotRead(t *testing.T) {
	values, err := parseGptTmpl(encodeGptTmpl("[System Access]",
		`MACHINE\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,5`))
	if err != nil || len(values) != 0 {
		t.Fatalf("a line in another section was read as a registry value: %+v %v", values, err)
	}
}

func TestSysvolIsNeverOpenedWithoutItsOwnGrant(t *testing.T) {
	dir := fixtureDir(t)
	called := false
	read := func(host, domain string, gpos, links adRead) adCheck { called = true; return adCheck{} }
	c := sysvolSettings(false, "dc1.example.test", adBase, dir, read)
	if called || c.State != "could-not-answer" || !strings.Contains(c.Reason, "its own permission") {
		t.Fatalf("not granted: opened %v, got %s %q", called, c.State, c.Reason)
	}
	c = sysvolSettings(true, "", adBase, dir, read)
	if called || c.State != "could-not-answer" || !strings.Contains(c.Reason, "named no domain controller") {
		t.Fatalf("no host: opened %v, got %s %q", called, c.State, c.Reason)
	}
	var gotDomain string
	sysvolSettings(true, "dc1.example.test", adBase, dir, func(host, domain string, gpos, links adRead) adCheck {
		gotDomain = domain
		return adCheck{}
	})
	if gotDomain != "example.test" {
		t.Fatalf("the share path's domain is %q, want example.test", gotDomain)
	}
}

func TestASignOffThatFailedIsSaid(t *testing.T) {
	dir := fixtureDir(t)
	reader := &recordingReader{files: map[string][]byte{defaultPolicyGUID: defaultPolicyTemplate()}}
	c := gpoSettingsCheck(readAdDir(dir, "gpos"), readAdDir(dir, "gplinks"), reader.read, errors.New("logoff refused"))
	if !strings.Contains(c.Note, "could not end its SYSVOL session") || !strings.Contains(c.Note, "logoff refused") {
		t.Fatalf("a sign-off that failed must be reported, never swallowed: %q", c.Note)
	}
}

func TestTheTemplatePathIsTheDocumentedOne(t *testing.T) {
	got := gptPath("example.test", defaultPolicyGUID)
	want := `example.test\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf`
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
