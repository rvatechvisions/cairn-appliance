package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The relay proven against endpoints stood up for it. WO-0929-A item 4.
//
// relay_test.go asserts each check as a function call. This drives the whole
// -relay loop -- the credential call, asking for work, making each request,
// sending each answer back -- against a portal that speaks the portal's
// protocol and targets that are real HTTPS servers, and asserts on what the
// targets actually received. Five cases, each named in the order:
//
//  1. a read from the declared origin succeeds;
//  2. a read to an undeclared origin is refused and never sent;
//  3. a redirect is returned, and its target is never asked;
//  4. two pages are read, and a next page on another origin is refused by name;
//  5. an answer over 16 MiB is refused rather than cut, and one of exactly
//     16 MiB comes back whole.
//
// Every server here shares httptest's one certificate, so trusting it is one
// transport swap and TLS is verified throughout, never switched off.

type provePortal struct {
	mu      sync.Mutex
	jobs    []relayJob
	results map[string]relayResult
}

func (p *provePortal) handler(targets []relayTarget) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Cairn-Signature") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/appliance/credential":
			_ = json.NewEncoder(w).Encode(map[string]any{"relayTargets": targets})
		case relayNextPath:
			p.mu.Lock()
			defer p.mu.Unlock()
			if len(p.jobs) == 0 {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			job := p.jobs[0]
			p.jobs = p.jobs[1:]
			_ = json.NewEncoder(w).Encode(map[string]any{"job": job})
		case relayResultPath:
			if r.Header.Get("Content-Type") != relayResultContentType {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			}
			var result relayResult
			if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			p.mu.Lock()
			p.results[result.JobID] = result
			p.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// counted is a target that records every path it was asked for.
type counted struct {
	server *httptest.Server
	mu     sync.Mutex
	asked  []string
	hits   int32
}

func (c *counted) paths() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.asked...)
}

func countedServer(t *testing.T, handler func(c *counted, w http.ResponseWriter, r *http.Request)) *counted {
	t.Helper()
	c := &counted{}
	c.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&c.hits, 1)
		c.mu.Lock()
		c.asked = append(c.asked, r.URL.RequestURI())
		c.mu.Unlock()
		handler(c, w, r)
	}))
	t.Cleanup(c.server.Close)
	return c
}

func decoded(t *testing.T, result relayResult) []byte {
	t.Helper()
	body, err := base64.StdEncoding.DecodeString(result.Body)
	if err != nil {
		t.Fatalf("job %s: the body was not base64: %v", result.JobID, err)
	}
	return body
}

func TestRelayProvenAgainstStoodUpEndpoints(t *testing.T) {
	// The undeclared origin. Nothing may ever reach it.
	elsewhere := countedServer(t, func(_ *counted, w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"leaked":true}`))
	})

	declared := countedServer(t, func(c *counted, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ok":
			_, _ = w.Write([]byte(`{"rows":[{"id":"a1"}]}`))
		case "/api/moved":
			http.Redirect(w, r, elsewhere.server.URL+"/api/ok", http.StatusFound)
		case "/api/users":
			switch r.URL.Query().Get("page") {
			case "1":
				w.Header().Set("Link", `<`+c.server.URL+`/api/users?page=2>; rel="next"`)
				_, _ = w.Write([]byte(`[{"id":"u1"}]`))
			case "2":
				w.Header().Set("Link", `<`+elsewhere.server.URL+`/api/users?page=3>; rel="next"`)
				_, _ = w.Write([]byte(`[{"id":"u2"}]`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		case "/api/exactly-the-limit":
			_, _ = w.Write(make([]byte, relayBodyLimit))
		case "/api/one-byte-over":
			_, _ = w.Write(make([]byte, relayBodyLimit+1))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	targets := []relayTarget{{Connection: "okta:district", Origin: declared.server.URL}}
	job := func(id, url string) relayJob {
		return relayJob{JobID: id, Connection: "okta:district", Method: http.MethodGet, URL: url, Headers: map[string]string{"accept": "application/json"}}
	}
	portal := &provePortal{results: map[string]relayResult{}}
	portal.jobs = []relayJob{
		job("declared", declared.server.URL+"/api/ok"),
		job("undeclared", elsewhere.server.URL+"/api/ok"),
		job("redirect", declared.server.URL+"/api/moved"),
		job("page-1", declared.server.URL+"/api/users?page=1"),
		job("page-2", declared.server.URL+"/api/users?page=2"),
		// The portal refuses this before queueing (relay.test.ts); it is asked
		// here anyway, as a portal that forgot would ask it, so the appliance's
		// own check is what is being proven.
		job("page-3-off-origin", elsewhere.server.URL+"/api/users?page=3"),
		job("exactly-16MiB", declared.server.URL+"/api/exactly-the-limit"),
		job("over-16MiB", declared.server.URL+"/api/one-byte-over"),
	}
	portalServer := httptest.NewTLSServer(portal.handler(targets))
	t.Cleanup(portalServer.Close)

	trusted := portalServer.Client().Transport
	saved := http.DefaultTransport
	http.DefaultTransport = trusted
	t.Cleanup(func() { http.DefaultTransport = saved })

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := collectRelay(portalServer.URL, "SHA256:prove", private, 30*time.Second); err != nil {
		t.Fatalf("the relay loop failed: %v", err)
	}

	results := portal.results
	if len(results) != 8 {
		t.Fatalf("expected an answer for all 8 jobs, got %d", len(results))
	}

	// 1. The declared origin: one request, the body whole.
	if r := results["declared"]; r.Status != 200 || string(decoded(t, r)) != `{"rows":[{"id":"a1"}]}` {
		t.Errorf("declared read: status %d, body %q", r.Status, decoded(t, r))
	}

	// 2. The undeclared origin: refused by the appliance, naming the host.
	if r := results["undeclared"]; r.Status != relayRefusal || !strings.Contains(string(decoded(t, r)), "is not a host this connection declared") {
		t.Errorf("undeclared read: status %d, body %q", r.Status, decoded(t, r))
	}

	// 3. The redirect: returned as the answer, never followed.
	if r := results["redirect"]; r.Status != http.StatusFound || !strings.HasPrefix(r.Headers["location"], elsewhere.server.URL) {
		t.Errorf("redirect: status %d, location %q", r.Status, r.Headers["location"])
	}

	// 4. Two pages read; the off-origin third refused by name.
	if r := results["page-1"]; r.Status != 200 || !strings.Contains(r.Headers["link"], declared.server.URL+"/api/users?page=2") {
		t.Errorf("page 1: status %d, link %q", r.Status, r.Headers["link"])
	}
	if r := results["page-2"]; r.Status != 200 || string(decoded(t, r)) != `[{"id":"u2"}]` || !strings.Contains(r.Headers["link"], elsewhere.server.URL) {
		t.Errorf("page 2: status %d, body %q, link %q", r.Status, decoded(t, r), r.Headers["link"])
	}
	if r := results["page-3-off-origin"]; r.Status != relayRefusal || !strings.Contains(string(decoded(t, r)), elsewhere.server.URL+" is not a host this connection declared") {
		t.Errorf("off-origin page: status %d, body %q", r.Status, decoded(t, r))
	}

	// 5. The limit: exactly 16 MiB whole, one byte more refused and not cut.
	if r := results["exactly-16MiB"]; r.Status != 200 || int64(len(decoded(t, r))) != relayBodyLimit {
		t.Errorf("16 MiB answer: status %d, %d bytes", r.Status, len(decoded(t, r)))
	}
	if r := results["over-16MiB"]; r.Status != relayRefusal || !strings.Contains(string(decoded(t, r)), "a cut answer is not sent") {
		body := decoded(t, r)
		// The size, never the body: a cut 16 MiB answer quoted in full is a failure nobody can read.
		t.Errorf("over-limit answer: status %d, %d bytes, starting %q", r.Status, len(body), body[:min(len(body), 80)])
	}

	// What the targets actually received, which is the claim.
	if hits := atomic.LoadInt32(&elsewhere.hits); hits != 0 {
		t.Errorf("the undeclared origin was asked %d times: %v", hits, elsewhere.paths())
	}
	want := []string{"/api/ok", "/api/moved", "/api/users?page=1", "/api/users?page=2", "/api/exactly-the-limit", "/api/one-byte-over"}
	if got := declared.paths(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("the declared origin was asked %v, want %v", got, want)
	}
}
