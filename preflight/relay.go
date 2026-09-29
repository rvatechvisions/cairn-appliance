package main

// The relay. WO-0928-G item 5.
//
// A reader in the portal whose requests go out through this appliance to a
// system inside the client's network. The reader stays in the portal; this
// executes one checked request at a time and hands back what came back.
//
// ## What it refuses is the design
//
// A relay done wrong is a pivot point inside a client's network, so this
// binary does not trust the portal to have checked:
//
//   - Declared targets only. Each job names a connection, and the request is
//     made only if its URL's origin is exactly the origin that connection
//     declared -- read from THIS box's own credential call, never from the job.
//   - Read methods only: GET, or POST to a path the connection names.
//   - A redirect is never followed. It is returned as the answer, and the
//     portal's reader sees a status it does not accept.
//   - An answer larger than relayBodyLimit is refused, never truncated: a cut
//     page reads as a complete one.
//   - TLS is verified. A target with a certificate this box cannot verify is
//     refused like any other failure, and verification is never switched off.
//   - Nothing is written: no file, no log line carrying a URL, a header or a
//     body. The request and its answer exist in memory for one exchange.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	relayNextPath           = "/appliance/relay/next"
	relayResultPath         = "/appliance/relay/result"
	relayResultContentType  = "application/vnd.cairn.relay+json"
	relayBodyLimit    int64 = 16 << 20
)

// relayTarget is one connection this appliance may relay for, as the portal
// named it on the credential call.
//
// A connection declares a LIST of origins -- several firewalls, several
// vCenters -- and every request is checked against the whole list. Nothing
// adds an origin at request time. WO-0929-D item 8. A portal that predates the
// list sends Origin alone, and that one origin is the list.
type relayTarget struct {
	Connection string   `json:"connection"`
	Origin     string   `json:"origin"`
	Origins    []string `json:"origins"`
	Posts      []string `json:"posts"`
}

// declared is every origin the connection declares.
func (t relayTarget) declared() []string {
	if len(t.Origins) > 0 {
		return t.Origins
	}
	if t.Origin != "" {
		return []string{t.Origin}
	}
	return nil
}

type relayJob struct {
	JobID      string            `json:"jobId"`
	Connection string            `json:"connection"`
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	Body       *string           `json:"body"`
}

type relayResult struct {
	JobID   string            `json:"jobId"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// relayRefusal is the status sent back for a job this box would not make.
// 421, Misdirected Request: the request was not for a target this appliance
// serves. The portal's reader sees a status it does not accept, and the read
// fails by name.
const relayRefusal = http.StatusMisdirectedRequest

// relayPermitted is this box's own check, the twin of the portal's `permitted`.
func relayPermitted(targets []relayTarget, job relayJob) error {
	var target *relayTarget
	for i := range targets {
		if targets[i].Connection == job.Connection {
			target = &targets[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("%s is not a connection this appliance relays for", job.Connection)
	}
	parsed, err := url.Parse(job.URL)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("the request is not an address")
	}
	if parsed.User != nil {
		return fmt.Errorf("an address carrying a user name is not relayed")
	}
	origin := parsed.Scheme + "://" + parsed.Host
	listed := false
	for _, declared := range target.declared() {
		if origin == declared {
			listed = true
			break
		}
	}
	if parsed.Scheme != "https" || !listed {
		return fmt.Errorf("%s is not a host this connection declared", origin)
	}
	switch job.Method {
	case http.MethodGet:
		return nil
	case http.MethodPost:
		for _, path := range target.Posts {
			if parsed.Path == path {
				return nil
			}
		}
	}
	return fmt.Errorf("%s %s is not a read this connection names", job.Method, parsed.Path)
}

// relayClient never follows a redirect: the redirect is the answer.
func relayClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// relayExecute makes one checked request and returns what came back, or a
// refusal result. It never returns a partial body.
func relayExecute(client *http.Client, targets []relayTarget, job relayJob) relayResult {
	refuse := func(why string) relayResult {
		return relayResult{
			JobID:   job.JobID,
			Status:  relayRefusal,
			Headers: map[string]string{"content-type": "text/plain"},
			Body:    base64.StdEncoding.EncodeToString([]byte("refused by the Cairn appliance: " + why)),
		}
	}
	if err := relayPermitted(targets, job); err != nil {
		return refuse(err.Error())
	}
	var body io.Reader
	if job.Body != nil {
		body = strings.NewReader(*job.Body)
	}
	request, err := http.NewRequest(job.Method, job.URL, body)
	if err != nil {
		return refuse("the request could not be built")
	}
	for name, value := range job.Headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return refuse("the target did not answer")
	}
	defer response.Body.Close()
	read, err := io.ReadAll(io.LimitReader(response.Body, relayBodyLimit+1))
	if err != nil {
		return refuse("the answer could not be read")
	}
	if int64(len(read)) > relayBodyLimit {
		return refuse(fmt.Sprintf("the answer was larger than %d bytes, and a cut answer is not sent", relayBodyLimit))
	}
	headers := map[string]string{}
	for name, values := range response.Header {
		headers[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	return relayResult{
		JobID:   job.JobID,
		Status:  response.StatusCode,
		Headers: headers,
		Body:    base64.StdEncoding.EncodeToString(read),
	}
}

// signedExchange sends bytes exactly as signed and returns the portal's status
// and answer. The relay needs both, where signedPost needs only acceptance.
func signedExchange(portal, path, contentType, fingerprint string, private ed25519.PrivateKey, payload []byte) (int, []byte, error) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return 0, nil, fmt.Errorf("generating a nonce: %w", err)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	signature := ed25519.Sign(private, canonicalBytes(
		http.MethodPost, path, fingerprint, timestamp, nonce, bodyHash(payload),
	))
	request, err := http.NewRequest(http.MethodPost, strings.TrimRight(portal, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	request.Header.Set("Cairn-Appliance", fingerprint)
	request.Header.Set("Cairn-Timestamp", timestamp)
	request.Header.Set("Cairn-Nonce", nonce)
	request.Header.Set("Cairn-Signature", base64.StdEncoding.EncodeToString(signature))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return 0, nil, fmt.Errorf("reaching the portal: %w", err)
	}
	defer response.Body.Close()
	answer, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("reading the portal's answer: %w", err)
	}
	return response.StatusCode, answer, nil
}

var errRelayNotAsked = errors.New("not asked")

// collectRelay is the -relay mode: fetch the targets, then ask for work until
// the portal has none, making each checked request as it comes.
func collectRelay(portal, fingerprint string, private ed25519.PrivateKey, budget time.Duration) error {
	credential, err := fetchCredential(portal, fingerprint, private)
	if err != nil {
		return fmt.Errorf("%w: fetching the credential: %v", errRelayNotAsked, err)
	}
	if len(credential.RelayTargets) == 0 {
		return fmt.Errorf("%w: no connection names this appliance to read through", errRelayNotAsked)
	}
	client := relayClient(60 * time.Second)
	deadline := time.Now().Add(budget)
	made, refused, idle := 0, 0, 0
	for time.Now().Before(deadline) {
		status, answer, err := signedExchange(portal, relayNextPath, "", fingerprint, private, nil)
		if err != nil {
			return err
		}
		if status == http.StatusNoContent {
			idle++
			if idle >= 2 {
				break
			}
			continue
		}
		if status != http.StatusOK {
			return fmt.Errorf("the portal refused the request for work (%d)", status)
		}
		idle = 0
		var envelope struct {
			Job relayJob `json:"job"`
		}
		if err := json.Unmarshal(answer, &envelope); err != nil {
			return fmt.Errorf("the portal's job did not parse: %w", err)
		}
		result := relayExecute(client, credential.RelayTargets, envelope.Job)
		if result.Status == relayRefusal {
			refused++
		} else {
			made++
		}
		payload, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if status, _, err := signedExchange(portal, relayResultPath, relayResultContentType, fingerprint, private, payload); err != nil {
			return err
		} else if status != http.StatusNoContent {
			return fmt.Errorf("the portal refused the answer (%d)", status)
		}
	}
	fmt.Printf("relayed: %d requests made, %d refused by this appliance\n", made, refused)
	return nil
}
