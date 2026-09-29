package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The Configuration Manager reader against a stood-up administration service.
// WO-0929-B item 8. The ticket is stood in for: what is asserted is that the
// header goes on every request, not that Kerberos works.

func leafFingerprint(server *httptest.Server) string {
	sum := sha256.Sum256(server.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

func stubAuthorize(request *http.Request) error {
	request.Header.Set("Authorization", "Negotiate stub")
	return nil
}

func adminService(t *testing.T, pages map[string]string) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Negotiate stub" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, ok := pages[r.URL.RequestURI()]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(server.Close)
	return server, &seen
}

func TestReadsEverySystemPageByPageWithTheTicketOnEachRequest(t *testing.T) {
	var server *httptest.Server
	pages := map[string]string{}
	server, seen := adminService(t, pages)
	pages["/AdminService/wmi/SMS_R_System"] = `{"value":[{"ResourceID":1,"Name":"PC-1","Client":1}],"@odata.nextLink":"` + server.URL + `/AdminService/wmi/SMS_R_System?$skiptoken=2"}`
	pages["/AdminService/wmi/SMS_R_System?$skiptoken=2"] = `{"value":[{"ResourceID":2,"Name":"PC-2","Client":0}]}`

	client, err := pinnedClient(leafFingerprint(server))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := adminServiceBase(server.URL + "/AdminService")
	raw, err := listSystems(client, stubAuthorize, base)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(raw) != 2 {
		t.Fatalf("read %d systems, want 2", len(raw))
	}
	if len(*seen) != 2 || !strings.HasPrefix((*seen)[0], "GET ") || !strings.HasPrefix((*seen)[1], "GET ") {
		t.Fatalf("requests %v, want two GETs", *seen)
	}
}

func TestTrustsTheOneCertificateAPersonPinnedAndNoOther(t *testing.T) {
	server, _ := adminService(t, map[string]string{"/AdminService/wmi/SMS_R_System": `{"value":[]}`})
	base, _ := adminServiceBase(server.URL + "/AdminService")

	wrong, err := pinnedClient(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := listSystems(wrong, stubAuthorize, base); err == nil || !strings.Contains(err.Error(), "not the one the portal holds") {
		t.Fatalf("a certificate nobody pinned was accepted: %v", err)
	}
	if _, err := pinnedClient("not-a-fingerprint"); err == nil {
		t.Fatal("a fingerprint that is not SHA-256 was accepted")
	}
}

func TestFollowsNoNextLinkOffTheProviderAndReturnsARedirect(t *testing.T) {
	pages := map[string]string{"/AdminService/wmi/SMS_R_System": `{"value":[],"@odata.nextLink":"https://elsewhere.example/AdminService/wmi/SMS_R_System?page=2"}`}
	server, _ := adminService(t, pages)
	client, _ := pinnedClient(leafFingerprint(server))
	base, _ := adminServiceBase(server.URL + "/AdminService")
	if _, err := listSystems(client, stubAuthorize, base); err == nil || !strings.Contains(err.Error(), "it is not followed") {
		t.Fatalf("a next link off the provider was followed: %v", err)
	}

	redirecting := httptest.NewTLSServer(http.RedirectHandler("https://elsewhere.example/", http.StatusFound))
	t.Cleanup(redirecting.Close)
	client2, _ := pinnedClient(leafFingerprint(redirecting))
	base2, _ := adminServiceBase(redirecting.URL + "/AdminService")
	if _, err := listSystems(client2, stubAuthorize, base2); err == nil || !strings.Contains(err.Error(), "returned, not followed") {
		t.Fatalf("a redirect was followed: %v", err)
	}
}

func TestRefusesAnAddressThatIsNotHttpsOrNotTheAdministrationService(t *testing.T) {
	for _, address := range []string{"http://sms.example/AdminService", "https://user@sms.example/AdminService", "https://sms.example/other"} {
		if _, err := adminServiceBase(address); err == nil {
			t.Fatalf("%s was accepted", address)
		}
	}
	if _, err := adminServiceBase("https://sms.example/adminservice/"); err != nil {
		t.Fatalf("a correct address was refused: %v", err)
	}
}

func TestLeavesOutAndCountsObsoleteAndDecommissionedRecords(t *testing.T) {
	raw := []json.RawMessage{
		json.RawMessage(`{"ResourceID":1,"Name":"PC-1","Client":1,"Obsolete":0,"Decommissioned":0,"SMBIOSGUID":"x","LastLogonUserName":"someone"}`),
		json.RawMessage(`{"ResourceID":2,"Name":"PC-OLD","Obsolete":1}`),
		json.RawMessage(`{"ResourceID":3,"Name":"PC-GONE","Decommissioned":1}`),
		json.RawMessage(`{"Name":"NO-ID"}`),
	}
	items, obsolete, decommissioned, err := reduceSystems(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || obsolete != 1 || decommissioned != 1 {
		t.Fatalf("items %d obsolete %d decommissioned %d, want 2, 1, 1", len(items), obsolete, decommissioned)
	}
	body, err := buildMecmSubmission(items, obsolete, decommissioned, time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC), "host", "account", "id")
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, item := range decoded.Items {
		if len(item) != 5 {
			t.Fatalf("an item carries %d fields, want exactly five: %v", len(item), item)
		}
		for _, forbidden := range []string{"SMBIOSGUID", "LastLogonUserName", "Obsolete"} {
			if _, present := item[forbidden]; present {
				t.Fatalf("%s left the box", forbidden)
			}
		}
	}
	if !strings.Contains(string(body), `"mecm-systems-obsolete"`) || !strings.Contains(string(body), `"mecm-systems-without-id"`) {
		t.Fatalf("the counts are not in the submission: %s", body)
	}
}

func TestARefusedAccountIsARefusalNotAnEmptyList(t *testing.T) {
	server, _ := adminService(t, map[string]string{})
	client, _ := pinnedClient(leafFingerprint(server))
	base, _ := adminServiceBase(server.URL + "/AdminService")
	noTicket := func(*http.Request) error { return nil }
	_, err := listSystems(client, noTicket, base)
	if err == nil || !strings.Contains(err.Error(), "refused the account (401)") {
		t.Fatalf("a refusal read as something else: %v", err)
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		t.Fatalf("a refusal surfaced as a transport error: %v", err)
	}
}
