package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The Proxmox VE reader against a stood-up cluster. WO-0929-C item 6.

const proxmoxToken = "cairn@pve!reader"
const proxmoxSecret = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

func proxmoxCluster(t *testing.T, body string) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	var seen []*http.Request
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r)
		if r.Header.Get("Authorization") != "PVEAPIToken="+proxmoxToken+"="+proxmoxSecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.RequestURI() != "/api2/json/cluster/resources?type=vm" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, &seen
}

func proxmoxCred(server *httptest.Server) proxmoxCredential {
	return proxmoxCredential{URL: server.URL, TokenID: proxmoxToken, Secret: proxmoxSecret, Fingerprint: leafFingerprint(server)}
}

func TestReadsTheGuestListOnceWithTheTokenAndNoSession(t *testing.T) {
	server, seen := proxmoxCluster(t, `{"data":[{"id":"qemu/100","vmid":100,"name":"dc01","node":"pve1","status":"running","type":"qemu","template":0,"maxmem":4294967296}]}`)
	credential := proxmoxCred(server)
	client, err := proxmoxClient(credential.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := proxmoxBase(credential.URL)
	resources, err := listGuests(client, base, credential)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("read %d guests, want 1", len(resources))
	}
	if len(*seen) != 1 || (*seen)[0].Method != http.MethodGet {
		t.Fatalf("requests %d, want exactly one GET and no sign-in", len(*seen))
	}
}

func TestTrustsTheOneCertificateAPersonPinnedForProxmox(t *testing.T) {
	server, seen := proxmoxCluster(t, `{"data":[]}`)
	credential := proxmoxCred(server)
	credential.Fingerprint = strings.Repeat("ab", 32)
	client, err := proxmoxClient(credential.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	base, _ := proxmoxBase(credential.URL)
	if _, err := listGuests(client, base, credential); err == nil {
		t.Fatal("a certificate that is not the pinned one was trusted")
	}
	if len(*seen) != 0 {
		t.Fatalf("the token reached a node presenting another certificate: %d requests", len(*seen))
	}
}

func TestRefusesAnHTTPAddressBeforeTheTokenIsSent(t *testing.T) {
	if _, err := proxmoxBase("http://pve.example:8006"); err == nil {
		t.Fatal("an http address was accepted, and the token would cross in the clear")
	}
}

func TestRefusesAnAnswerWithoutADataList(t *testing.T) {
	server, _ := proxmoxCluster(t, `{"errors":{"type":"bad"}}`)
	credential := proxmoxCred(server)
	client, _ := proxmoxClient(credential.Fingerprint)
	base, _ := proxmoxBase(credential.URL)
	if _, err := listGuests(client, base, credential); err == nil || !strings.Contains(err.Error(), "without a data list") {
		t.Fatalf("an answer with no data list was read as an empty cluster: %v", err)
	}
}

func TestSendsSixFieldsPerGuestAndCountsTemplatesWithoutSendingThem(t *testing.T) {
	var resources []proxmoxResource
	if err := json.Unmarshal([]byte(`[
		{"id":"qemu/100","vmid":100,"name":"dc01","node":"pve1","status":"running","type":"qemu","template":0,"maxmem":4294967296,"tags":"prod"},
		{"id":"lxc/101","vmid":101,"name":"web","node":"pve2","status":"stopped","type":"lxc"},
		{"id":"qemu/9000","vmid":9000,"name":"win11-template","node":"pve1","status":"stopped","type":"qemu","template":1},
		{"vmid":102,"name":"no-id","node":"pve1","status":"running","type":"qemu"}
	]`), &resources); err != nil {
		t.Fatal(err)
	}
	items, templates, err := reduceGuests(resources)
	if err != nil {
		t.Fatal(err)
	}
	if templates != 1 || len(items) != 3 {
		t.Fatalf("items %d, templates %d; want 3 sent and 1 template left out", len(items), templates)
	}
	body, err := buildProxmoxSubmission(items, templates, time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC), "cairn", "", "id")
	if err != nil {
		t.Fatal(err)
	}
	var sent struct {
		Items    []map[string]any `json:"items"`
		Findings []coverageCheck  `json:"findings"`
	}
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatal(err)
	}
	for _, item := range sent.Items {
		if len(item) != 6 {
			t.Fatalf("an item left with %d fields, want exactly six: %v", len(item), item)
		}
		for key := range item {
			switch key {
			case "id", "vmid", "name", "node", "status", "type":
			default:
				t.Fatalf("an item carried %q, which is not one of the six", key)
			}
		}
	}
	if strings.Contains(string(body), "win11-template") {
		t.Fatal("a template left the box")
	}
	want := map[string]int{"proxmox-guests-listed": 3, "proxmox-guests-without-id": 1, "proxmox-guests-not-correlatable": 2, "proxmox-templates-not-sent": 1}
	for _, check := range sent.Findings {
		if check.Count != want[check.ID] {
			t.Fatalf("finding %s counted %v, want %d", check.ID, check.Count, want[check.ID])
		}
	}
}

func TestRefusesATemplateFlagItCannotRead(t *testing.T) {
	var resources []proxmoxResource
	_ = json.Unmarshal([]byte(`[{"id":"qemu/1","template":"maybe"}]`), &resources)
	if _, _, err := reduceGuests(resources); err == nil {
		t.Fatal("a template flag that is neither a boolean nor 0 or 1 was guessed at")
	}
}
