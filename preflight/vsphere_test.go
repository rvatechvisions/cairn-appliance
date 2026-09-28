package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// The vSphere reader against a stood-up vCenter. WO-0929-A item 9.

type fakeVcenter struct {
	server   *httptest.Server
	mu       sync.Mutex
	requests []string
	list     func(w http.ResponseWriter)
}

func (f *fakeVcenter) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func newFakeVcenter(t *testing.T, list func(w http.ResponseWriter)) *fakeVcenter {
	t.Helper()
	f := &fakeVcenter{list: list}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/session":
			user, pass, ok := r.BasicAuth()
			if !ok || user != "cairn-reader@vsphere.local" || pass != "the-password" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`"session-abc"`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/vcenter/vm":
			if r.Header.Get("vmware-api-session-id") != "session-abc" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			f.list(w)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/session":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func credentialFor(f *fakeVcenter) vsphereCredential {
	return vsphereCredential{URL: f.server.URL, Username: "cairn-reader@vsphere.local", Password: "the-password"}
}

func TestReadsTheVMListAndKeepsAnAbsentOptionalFieldAbsent(t *testing.T) {
	f := newFakeVcenter(t, func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`[
			{"vm":"vm-101","name":"dc01","power_state":"POWERED_ON","cpu_count":4,"memory_size_MiB":16384},
			{"vm":"vm-102","name":"template-win","power_state":"POWERED_OFF"},
			{"vm":"","name":"orphan","power_state":"POWERED_OFF","cpu_count":0,"memory_size_MiB":null}
		]`))
	})
	items, err := readVsphere(f.server.Client(), credentialFor(f))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("expected three virtual machines, got %d", len(items))
	}
	if *items[0].VM != "vm-101" || *items[0].CPUCount != 4 || *items[0].MemorySizeMiB != 16384 {
		t.Errorf("the first machine was read wrong: %+v", items[0])
	}
	if items[1].CPUCount != nil || items[1].MemorySizeMiB != nil {
		t.Errorf("an optional field vCenter did not send became a value: %+v", items[1])
	}
	if items[2].VM != nil {
		t.Errorf("a machine with an empty id kept one: %q", *items[2].VM)
	}
	if items[2].CPUCount == nil || *items[2].CPUCount != 0 {
		t.Errorf("a zero vCenter sent became absent: %+v", items[2])
	}
	want := "POST /api/session GET /api/vcenter/vm DELETE /api/session"
	if got := strings.Join(f.seen(), " "); got != want {
		t.Errorf("vCenter was asked %q, want %q", got, want)
	}
}

func TestRefusesVcentersOwnCeilingByNameAndStillSignsOut(t *testing.T) {
	f := newFakeVcenter(t, func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error_type":"UNABLE_TO_ALLOCATE_RESOURCE","messages":[{"default_message":"Too many virtual machines. Add more filter criteria to reduce the number."}]}`))
	})
	items, err := readVsphere(f.server.Client(), credentialFor(f))
	if !errors.Is(err, errVsphereTooMany) {
		t.Fatalf("expected the ceiling refused by name, got %v", err)
	}
	if items != nil {
		t.Errorf("a refused list returned %d machines", len(items))
	}
	if seen := f.seen(); seen[len(seen)-1] != "DELETE /api/session" {
		t.Errorf("the session was left open: %v", seen)
	}
	for _, request := range f.seen() {
		if strings.Contains(request, "filter") {
			t.Errorf("the reader narrowed the list to make it fit: %s", request)
		}
	}
}

func TestSendsNoPasswordToAPlainAddress(t *testing.T) {
	f := newFakeVcenter(t, func(w http.ResponseWriter) { _, _ = w.Write([]byte(`[]`)) })
	plain := credentialFor(f)
	plain.URL = strings.Replace(plain.URL, "https://", "http://", 1)
	if _, err := readVsphere(f.server.Client(), plain); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("expected a plain address refused, got %v", err)
	}
	if len(f.seen()) != 0 {
		t.Errorf("vCenter was asked something anyway: %v", f.seen())
	}
}

func TestAWrongPasswordIsARefusalNotAnEmptyList(t *testing.T) {
	f := newFakeVcenter(t, func(w http.ResponseWriter) { _, _ = w.Write([]byte(`[]`)) })
	wrong := credentialFor(f)
	wrong.Password = "not-it"
	if _, err := readVsphere(f.server.Client(), wrong); err == nil || !strings.Contains(err.Error(), "refused the account") {
		t.Fatalf("expected the account refused, got %v", err)
	}
	if strings.Join(f.seen(), " ") != "POST /api/session" {
		t.Errorf("the list was asked for without a session: %v", f.seen())
	}
}

func TestTheSubmissionCarriesFiveFieldsAndCountsWhatCannotBeCorrelated(t *testing.T) {
	id, name, state := "vm-101", "dc01", "POWERED_ON"
	items := []VsphereItem{
		{VM: &id, Name: &name, PowerState: &state},
		{Name: &name, PowerState: &state},
	}
	body, err := buildVsphereSubmission(items, time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC), "cairn", "svc", "s-1")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Envelope struct {
			Source string `json:"source"`
		} `json:"envelope"`
		Findings []struct {
			ID    string `json:"id"`
			Count int    `json:"count"`
		} `json:"findings"`
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Envelope.Source != "vsphere" {
		t.Errorf("source %q", parsed.Envelope.Source)
	}
	keys := make([]string, 0)
	for key := range parsed.Items[0] {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "cpu_count,memory_size_MiB,name,power_state,vm" {
		t.Errorf("an item carries %v", keys)
	}
	if string(parsed.Items[0]["cpu_count"]) != "null" {
		t.Errorf("an absent cpu_count travelled as %s", parsed.Items[0]["cpu_count"])
	}
	counts := map[string]int{}
	for _, finding := range parsed.Findings {
		counts[finding.ID] = finding.Count
	}
	if counts["vsphere-vms-listed"] != 2 || counts["vsphere-vms-without-id"] != 1 || counts["vsphere-vms-not-correlatable"] != 1 {
		t.Errorf("findings were %v", counts)
	}
}
