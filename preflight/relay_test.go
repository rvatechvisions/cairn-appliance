package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The relay's refusals, against a TLS server. WO-0928-G item 5. Each is a way
// the appliance would become a pivot point, asserted by whether a request
// reached the server at all.

func relayServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	return server, &hits
}

func clientFor(server *httptest.Server) *http.Client {
	client := relayClient(5 * time.Second)
	client.Transport = server.Client().Transport
	return client
}

func TestRelaysAGetToTheDeclaredOriginAndReturnsWhatCameBack(t *testing.T) {
	server, hits := relayServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+"https://"+r.Host+`/api?page=2>; rel="next"`)
		_, _ = w.Write([]byte(`{"rows":[]}`))
	})
	targets := []relayTarget{{Connection: "snipeit:org", Origin: server.URL}}
	result := relayExecute(clientFor(server), targets, relayJob{JobID: "j1", Connection: "snipeit:org", Method: "GET", URL: server.URL + "/api?page=1"})

	if result.Status != 200 || *hits != 1 {
		t.Fatalf("expected one request and a 200, got %d after %d requests", result.Status, *hits)
	}
	body, _ := base64.StdEncoding.DecodeString(result.Body)
	if string(body) != `{"rows":[]}` {
		t.Errorf("body was %q", body)
	}
	if !strings.Contains(result.Headers["link"], "page=2") {
		t.Errorf("the paging header did not come back: %v", result.Headers)
	}
}

func TestRefusesAnUndeclaredHostWithoutMakingTheRequest(t *testing.T) {
	server, hits := relayServer(t, func(w http.ResponseWriter, r *http.Request) {})
	targets := []relayTarget{{Connection: "snipeit:org", Origin: "https://assets.district.example"}}
	for _, job := range []relayJob{
		{JobID: "a", Connection: "snipeit:org", Method: "GET", URL: server.URL + "/api"},
		{JobID: "b", Connection: "prtg:org", Method: "GET", URL: "https://assets.district.example/api"},
		{JobID: "c", Connection: "snipeit:org", Method: "GET", URL: "http://assets.district.example/api"},
		{JobID: "d", Connection: "snipeit:org", Method: "DELETE", URL: "https://assets.district.example/api/1"},
		{JobID: "e", Connection: "snipeit:org", Method: "POST", URL: "https://assets.district.example/api"},
		{JobID: "f", Connection: "snipeit:org", Method: "GET", URL: "https://u:p@assets.district.example/api"},
	} {
		result := relayExecute(clientFor(server), targets, job)
		if result.Status != relayRefusal {
			t.Errorf("job %s was not refused: %d", job.JobID, result.Status)
		}
	}
	if *hits != 0 {
		t.Fatalf("a refused job reached a server %d times", *hits)
	}
}

func TestNeverFollowsARedirect(t *testing.T) {
	var elsewhere int32
	other, _ := relayServer(t, func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&elsewhere, 1) })
	server, _ := relayServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	})
	targets := []relayTarget{{Connection: "snipeit:org", Origin: server.URL}}
	result := relayExecute(clientFor(server), targets, relayJob{JobID: "r", Connection: "snipeit:org", Method: "GET", URL: server.URL + "/api"})

	if result.Status != http.StatusFound {
		t.Fatalf("expected the redirect as the answer, got %d", result.Status)
	}
	if elsewhere != 0 {
		t.Fatalf("the redirect was followed to an undeclared host")
	}
}

func TestRefusesAnAnswerTooLargeRatherThanCuttingIt(t *testing.T) {
	server, _ := relayServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, relayBodyLimit+1))
	})
	targets := []relayTarget{{Connection: "snipeit:org", Origin: server.URL}}
	result := relayExecute(clientFor(server), targets, relayJob{JobID: "big", Connection: "snipeit:org", Method: "GET", URL: server.URL + "/api"})
	if result.Status != relayRefusal {
		t.Fatalf("an oversized answer was sent on with status %d", result.Status)
	}
}

func TestPostsOnlyToAPathTheConnectionNames(t *testing.T) {
	server, hits := relayServer(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("{}")) })
	targets := []relayTarget{{Connection: "veeam:org", Origin: server.URL, Posts: []string{"/api/oauth2/token"}}}
	body := "grant_type=password"
	ok := relayExecute(clientFor(server), targets, relayJob{JobID: "t", Connection: "veeam:org", Method: "POST", URL: server.URL + "/api/oauth2/token", Body: &body})
	refused := relayExecute(clientFor(server), targets, relayJob{JobID: "u", Connection: "veeam:org", Method: "POST", URL: server.URL + "/api/v1/jobs/start", Body: &body})
	if ok.Status != 200 || refused.Status != relayRefusal || *hits != 1 {
		t.Fatalf("expected one POST made and one refused, got %d and %d after %d requests", ok.Status, refused.Status, *hits)
	}
}

// WO-0929-D item 8b: a connection declaring several origins is relayed to any
// of them and to nothing else, and a portal that sends Origin alone still works.
func TestRelaysToEveryDeclaredOriginAndNoOther(t *testing.T) {
	targets := []relayTarget{{Connection: "paloalto:org", Origins: []string{"https://fw-high.district.example", "https://fw-middle.district.example"}}}
	for _, url := range []string{"https://fw-high.district.example/api/?type=op", "https://fw-middle.district.example/api/?type=op"} {
		if err := relayPermitted(targets, relayJob{Connection: "paloalto:org", Method: "GET", URL: url}); err != nil {
			t.Fatalf("%s refused: %v", url, err)
		}
	}
	for _, url := range []string{"https://fw-elementary.district.example/api/", "https://fw-high.district.example:8443/api/"} {
		if err := relayPermitted(targets, relayJob{Connection: "paloalto:org", Method: "GET", URL: url}); err == nil {
			t.Fatalf("%s was relayed, and the connection never declared it", url)
		}
	}
}

func TestReadsAPortalThatSendsOneOrigin(t *testing.T) {
	targets := []relayTarget{{Connection: "snipeit:org", Origin: "https://assets.district.example"}}
	if err := relayPermitted(targets, relayJob{Connection: "snipeit:org", Method: "GET", URL: "https://assets.district.example/api/v1/hardware"}); err != nil {
		t.Fatalf("a portal sending Origin alone is refused: %v", err)
	}
}
