package main

// Whose an error is, as an exit status, and the session count on every vSphere
// read. APPLIANCE-BINARY-QUEUE.md items 1, 3 and 4 in the portal repository,
// WO-1017-N47 item 2. Each test drives the real reader or the real signed post
// against a stand-in server, never a literal error handed to failureExit, so a
// reader that stopped wrapping its error would fail here.
//
// The appliance key in these tests is a test fixture, generated in the test.

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func fixtureApplianceKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private
}

func TestFailureExitSaysWhoseAnErrorIs(t *testing.T) {
	plain := errors.New("a timeout")
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"the portal refusing, wrapped twice", fmt.Errorf("submitting: %w", fmt.Errorf("sending: %w", portalRefused(plain))), exitPortalRefused},
		{"the far end refusing", fmt.Errorf("reading: %w", farEndRefused(plain)), exitFarEndRefused},
		{"neither", plain, 1},
		{"the portal refusing what followed a far end that also refused", portalRefused(farEndRefused(plain)), exitPortalRefused},
	}
	for _, c := range cases {
		if got := failureExit(c.err); got != c.want {
			t.Errorf("%s: failureExit = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestThePortalRefusingASubmissionExitsFour(t *testing.T) {
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"The submission is not the shape the contract describes."}`))
	}))
	defer portal.Close()
	err := signedPost(portal.URL, collectionPath, "application/json", "fp", fixtureApplianceKey(t), []byte(`{}`))
	if err == nil || failureExit(err) != exitPortalRefused {
		t.Fatalf("the portal's 400 gave %v and exit %d, want exit %d", err, failureExit(err), exitPortalRefused)
	}
}

func TestZabbixCodesSayWhoseTheErrorIs(t *testing.T) {
	cases := []struct {
		code       int
		want       int
		says       string
		mustNotSay string
	}{
		{-32700, 1, "which is ours to fix", " refused "},
		{-32601, 1, "which is ours to fix", " refused "},
		{-32603, 1, "not a no", " refused "},
		{-32602, 1, "cannot tell which", " refused "},
		{-32500, exitFarEndRefused, "Zabbix refused host.get (code -32500)", ""},
	}
	for _, c := range cases {
		var seen []map[string]any
		var auth string
		answer := fmt.Sprintf(`{"jsonrpc":"2.0","error":{"code":%d,"message":"A message.","data":"Some data."},"id":1}`, c.code)
		server := zabbixServer(t, answer, &seen, &auth)
		_, err := readZabbixHosts(server.Client(), zabbixCredential{URL: server.URL + "/zabbix", Token: "zbx-token"})
		if err == nil {
			t.Fatalf("code %d: no error", c.code)
		}
		if got := failureExit(err); got != c.want {
			t.Errorf("code %d: exit %d, want %d (%v)", c.code, got, c.want, err)
		}
		if !strings.Contains(err.Error(), c.says) {
			t.Errorf("code %d: %q does not say %q", c.code, err, c.says)
		}
		if c.mustNotSay != "" && strings.Contains(err.Error(), c.mustNotSay) {
			t.Errorf("code %d: %q calls it a refusal", c.code, err)
		}
		if !strings.Contains(err.Error(), "Some data.") {
			t.Errorf("code %d: %q drops Zabbix's own words", c.code, err)
		}
	}
}

func TestVcenterRefusingTheAccountExitsFive(t *testing.T) {
	f := newFakeVcenter(t, func(w http.ResponseWriter) { _, _ = w.Write([]byte(`[]`)) })
	credential := credentialFor(f)
	credential.Password = "not-the-password"
	_, _, err := readVsphere(f.server.Client(), credential)
	if err == nil || failureExit(err) != exitFarEndRefused {
		t.Fatalf("vCenter's 401 gave %v and exit %d, want exit %d", err, failureExit(err), exitFarEndRefused)
	}
}

// stdoutOf runs fn and returns what it printed to standard output.
func stdoutOf(t *testing.T, fn func()) string {
	t.Helper()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = write
	fn()
	os.Stdout = saved
	write.Close()
	out, _ := io.ReadAll(read)
	return string(out)
}

func TestEveryVsphereReadSaysHowManySessionsItLeftOpen(t *testing.T) {
	cases := []struct {
		name         string
		list         func(w http.ResponseWriter)
		refuseLogout bool
		want         string
		wantErr      bool
	}{
		{"a read that listed nothing, with the sign-out refused", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`[]`)) }, true, "sessions-left-open: 1", true},
		{"a read that failed, with the sign-out refused", func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, true, "sessions-left-open: 1", true},
		{"a read that listed machines and signed out", func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`[{"vm":"vm-101","name":"dc01","power_state":"POWERED_ON"}]`))
		}, false, "sessions-left-open: 0", false},
	}
	for _, c := range cases {
		f := newFakeVcenter(t, c.list)
		f.refuseLogout = c.refuseLogout
		credential := credentialFor(f)
		portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == collectionPath {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			_, _ = fmt.Fprintf(w, `{"capabilities":["vsphere"],"vsphere":{"url":%q,"username":%q,"password":%q}}`, credential.URL, credential.Username, credential.Password)
		}))
		var err error
		out := stdoutOf(t, func() {
			err = collectVsphere(f.server.Client(), portal.URL, "fp", fixtureApplianceKey(t))
		})
		portal.Close()
		if !strings.Contains(out, c.want+"\n") {
			t.Errorf("%s: printed %q, want a line %q", c.name, out, c.want)
		}
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, want an error: %v", c.name, err, c.wantErr)
		}
	}
}

func TestSpeaksDeclaresWhatThisBinaryDoes(t *testing.T) {
	lines := strings.Split(speaks(), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "abilities: ") {
		t.Fatalf("speaks() = %q, want the credential block and an abilities: line", speaks())
	}
	declared := " " + strings.TrimPrefix(lines[1], "abilities: ") + " "
	for _, ability := range []string{"error-source", "signed-release", "sessions-left-open", "sysvol-read", "dhcp-authorizations"} {
		if !strings.Contains(declared, " "+ability+" ") {
			t.Errorf("-speaks does not declare %s: %q", ability, lines[1])
		}
	}
}
