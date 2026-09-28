package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The Zabbix reader, against a TLS server answering in Zabbix's documented
// shapes. WO-0928-F item 5a. No live Zabbix server has been read.

func zabbixServer(t *testing.T, answer string, seen *[]map[string]any, auth *string) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/zabbix/api_jsonrpc.php" {
			t.Errorf("request to %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var request map[string]any
		if err := json.Unmarshal(body, &request); err != nil {
			t.Errorf("request did not parse: %s", body)
		}
		*seen = append(*seen, request)
		*auth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(answer))
	}))
	t.Cleanup(server.Close)
	return server
}

// The answer carries interfaces with addresses although none were asked for,
// so the test proves they are not carried even when a server volunteers them.
const hostAnswer = `{"jsonrpc":"2.0","result":[
  {"hostid":"10084","name":"Zabbix server","inventory":{"serialno_a":"PF3X9K2A","macaddress_a":"00:1A:2B:3C:4D:5E"},"interfaces":[{"ip":"10.1.2.3"}]},
  {"hostid":"10085","name":"printer-lib","inventory":[]},
  {"hostid":"","name":"broken","inventory":{"serialno_a":" ","macaddress_a":""}}
],"id":1}`

func TestReadsHostGetOnlyAndAsksForNoAddress(t *testing.T) {
	var seen []map[string]any
	var auth string
	server := zabbixServer(t, hostAnswer, &seen, &auth)

	items, err := readZabbixHosts(server.Client(), zabbixCredential{URL: server.URL + "/zabbix/", Token: "zbx-token"})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0]["method"] != "host.get" {
		t.Fatalf("expected one host.get, got %v", seen)
	}
	if auth != "Bearer zbx-token" {
		t.Errorf("Authorization was %q", auth)
	}
	params, _ := json.Marshal(seen[0]["params"])
	for _, forbidden := range []string{"selectInterfaces", "selectItems", "selectTriggers", "interfaces"} {
		if strings.Contains(string(params), forbidden) {
			t.Errorf("host.get asked for %s: %s", forbidden, params)
		}
	}

	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(items))
	}
	if *items[0].HostID != "10084" || *items[0].Serial != "PF3X9K2A" || *items[0].Mac != "00:1A:2B:3C:4D:5E" {
		t.Errorf("first host read wrong: %+v", items[0])
	}
	if items[1].Serial != nil || items[1].Mac != nil {
		t.Errorf("a host with inventory disabled carried inventory: %+v", items[1])
	}
	if items[2].HostID != nil || items[2].Serial != nil {
		t.Errorf("an empty id or serial was carried as a value: %+v", items[2])
	}
}

func TestRefusesAPlainHttpAddressBeforeAskingAnything(t *testing.T) {
	var seen []map[string]any
	var auth string
	server := zabbixServer(t, hostAnswer, &seen, &auth)
	plain := strings.Replace(server.URL, "https://", "http://", 1)

	_, err := readZabbixHosts(server.Client(), zabbixCredential{URL: plain + "/zabbix", Token: "zbx-token"})
	if err == nil || !strings.Contains(err.Error(), "not https") {
		t.Fatalf("expected a refusal naming https, got %v", err)
	}
	if len(seen) != 0 {
		t.Errorf("the token was sent to a plain http address")
	}
}

func TestSurfacesAZabbixRefusalRatherThanAnEmptyList(t *testing.T) {
	var seen []map[string]any
	var auth string
	server := zabbixServer(t, `{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params.","data":"Not authorized."},"id":1}`, &seen, &auth)

	items, err := readZabbixHosts(server.Client(), zabbixCredential{URL: server.URL + "/zabbix", Token: "bad"})
	if err == nil || !strings.Contains(err.Error(), "Not authorized") {
		t.Fatalf("expected the refusal, got %v and %d items", err, len(items))
	}
}

func TestZabbixSubmissionCarriesFourFieldsAndCounts(t *testing.T) {
	var seen []map[string]any
	var auth string
	server := zabbixServer(t, hostAnswer, &seen, &auth)
	items, err := readZabbixHosts(server.Client(), zabbixCredential{URL: server.URL + "/zabbix", Token: "zbx-token"})
	if err != nil {
		t.Fatal(err)
	}

	body, err := buildZabbixSubmission(items, time.Date(2026, 9, 28, 5, 44, 0, 0, time.UTC), "cairn", "svc-cairn", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "10.1.2.3") {
		t.Fatalf("an address left the box: %s", body)
	}

	var parsed struct {
		Envelope struct {
			Source string `json:"source"`
		} `json:"envelope"`
		Declared int              `json:"declared"`
		Findings []map[string]any `json:"findings"`
		Items    []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Envelope.Source != "zabbix" || parsed.Declared != 3 {
		t.Fatalf("envelope or count wrong: %s", body)
	}
	for _, item := range parsed.Items {
		if len(item) != 4 {
			t.Errorf("an item carries %d fields: %v", len(item), item)
		}
		for key := range item {
			if key != "hostid" && key != "name" && key != "serial" && key != "mac" {
				t.Errorf("an item carries %q", key)
			}
		}
	}
	counts := map[string]float64{}
	for _, finding := range parsed.Findings {
		counts[finding["id"].(string)] = finding["count"].(float64)
	}
	if counts["zabbix-hosts-listed"] != 3 || counts["zabbix-hosts-without-id"] != 1 {
		t.Errorf("coverage counts wrong: %v", counts)
	}
}
