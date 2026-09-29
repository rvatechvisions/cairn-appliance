package main

// The Proxmox VE reader. WO-0929-C item 6.
//
// It reads the guests an existing Proxmox VE cluster lists, with ONE read --
// GET /api2/json/cluster/resources?type=vm -- and submits six fields per guest
// to the portal's collection door, signed with the key this appliance
// enrolled with. It installs nothing on the cluster and changes nothing there.
//
// ## Signing in, and what outlives the read
//
// An API token, sent on the one request as the Authorization header Proxmox VE
// documents: PVEAPIToken=USER@REALM!TOKENID=SECRET. No ticket is asked for and
// no session is opened, so there is nothing to sign out of (WO-0929-B item 5).
// The token lives as long as whoever made it in Proxmox VE set.
//
// ## The credential is fetched per run and never touches the shell
//
// The address, the token id and its secret live in the portal, on the
// appliance's Proxmox VE slot, and are fetched on the same signed request the
// directory credential uses, held in memory for the read and dropped.
//
// ## The certificate is the cluster's own, and it is pinned
//
// A Proxmox VE node presents a certificate its cluster made for itself unless
// somebody replaced it, which no public root trusts. The portal holds the
// certificate's SHA-256 fingerprint, entered by a person who read it off the
// node, and the connection is refused unless the leaf matches it. A redirect is
// returned, never followed.
//
// ## What is asked, and what leaves
//
// The resource list, filtered to guests: id (Proxmox's own identifier in the
// cluster, required), vmid, name, node, status and type. A guest the cluster
// marks as a template is not a machine, is not sent, and is counted. Nothing
// about disks, networks, memory, CPU, tags, pools, storage or the nodes
// themselves leaves; the portal's door refuses an item carrying anything else.
//
// ## No paging, and no ceiling of ours
//
// The list does not page, and Proxmox VE documents no ceiling on it in what
// was read, so none is invented here.
//
// Built from Proxmox VE's API documentation, read 28 September 2026: the API
// viewer's schema for GET /cluster/resources (the type filter, and the id,
// vmid, name, node, status, type and template properties) and the wiki's API
// page (the PVEAPIToken header, port 8006, and responses wrapped in data).
// Never run against a live cluster.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// proxmoxCredential is what the portal hands over for a Proxmox VE slot.
type proxmoxCredential struct {
	URL         string `json:"url"`
	TokenID     string `json:"tokenId"`
	Secret      string `json:"secret"`
	Fingerprint string `json:"fingerprint"`
}

// ProxmoxItem is what leaves the box for one guest. Six fields, and a seventh
// is refused at the portal's door.
type ProxmoxItem struct {
	ID     *string `json:"id"`
	VMID   *int64  `json:"vmid"`
	Name   *string `json:"name"`
	Node   *string `json:"node"`
	Status *string `json:"status"`
	Type   *string `json:"type"`
}

var errProxmoxNotAsked = errors.New("not asked")

// proxmoxBase is the https origin of a Proxmox VE address.
func proxmoxBase(address string) (string, error) {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("%q is not a Proxmox VE address", address)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("the Proxmox VE address %q is not https, so the token is not sent to it", address)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("the Proxmox VE address carries a user name; the token is its own field")
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

// proxmoxClient trusts exactly the certificate whose SHA-256 fingerprint the
// portal holds, and returns a redirect rather than following it.
func proxmoxClient(fingerprint string) (*http.Client, error) {
	want, err := hex.DecodeString(strings.ReplaceAll(strings.ToLower(fingerprint), ":", ""))
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("the certificate fingerprint the portal holds is not a SHA-256 fingerprint")
	}
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// Chain verification is replaced, not skipped: the check below
				// refuses every certificate but the one a person pinned.
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
					if len(raw) == 0 {
						return fmt.Errorf("the Proxmox VE node presented no certificate")
					}
					got := sha256.Sum256(raw[0])
					if !bytes.Equal(got[:], want) {
						return fmt.Errorf("the Proxmox VE node presented a certificate whose fingerprint is %s, not the one the portal holds", hex.EncodeToString(got[:]))
					}
					return nil
				},
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// listGuests is the one read. It returns every guest, templates included;
// reduceGuests decides what leaves.
func listGuests(client *http.Client, base string, credential proxmoxCredential) ([]proxmoxResource, error) {
	request, err := http.NewRequest(http.MethodGet, base+"/api2/json/cluster/resources?type=vm", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "PVEAPIToken="+credential.TokenID+"="+credential.Secret)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("reaching Proxmox VE: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading Proxmox VE's answer: %w", err)
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("Proxmox VE refused the API token (%d)", response.StatusCode)
	}
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, fmt.Errorf("Proxmox VE answered with a redirect (%d), which is returned rather than followed", response.StatusCode)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Proxmox VE answered the resource list with %d", response.StatusCode)
	}
	var answer struct {
		Data *[]proxmoxResource `json:"data"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, fmt.Errorf("Proxmox VE's answer was not a resource list: %w", err)
	}
	if answer.Data == nil {
		return nil, fmt.Errorf("Proxmox VE answered without a data list, so nothing was read")
	}
	return *answer.Data, nil
}

// proxmoxResource is one row of the resource list, as far as it is read.
type proxmoxResource struct {
	ID       string          `json:"id"`
	VMID     json.RawMessage `json:"vmid"`
	Name     string          `json:"name"`
	Node     string          `json:"node"`
	Status   string          `json:"status"`
	Type     string          `json:"type"`
	Template json.RawMessage `json:"template"`
}

// isTemplate reads the template flag, which the schema types as a boolean and
// Proxmox VE commonly writes as 0 or 1. Anything else is refused rather than
// guessed at.
func isTemplate(raw json.RawMessage) (bool, error) {
	trimmed := strings.TrimSpace(string(raw))
	switch trimmed {
	case "", "null", "0", "false":
		return false, nil
	case "1", "true":
		return true, nil
	}
	return false, fmt.Errorf("the template flag is %s, which is neither a boolean nor 0 or 1", trimmed)
}

// reduceGuests keeps the six fields of every guest that is not a template,
// and counts the templates it left out.
func reduceGuests(resources []proxmoxResource) ([]ProxmoxItem, int, error) {
	items := make([]ProxmoxItem, 0, len(resources))
	templates := 0
	for _, resource := range resources {
		template, err := isTemplate(resource.Template)
		if err != nil {
			return nil, 0, fmt.Errorf("guest %s: %w", resource.ID, err)
		}
		if template {
			templates++
			continue
		}
		vmid, err := optionalCount(resource.VMID)
		if err != nil {
			return nil, 0, fmt.Errorf("guest %s: vmid %w", resource.ID, err)
		}
		items = append(items, ProxmoxItem{
			ID:     nonEmpty(resource.ID),
			VMID:   vmid,
			Name:   nonEmpty(resource.Name),
			Node:   nonEmpty(resource.Node),
			Status: nonEmpty(resource.Status),
			Type:   nonEmpty(resource.Type),
		})
	}
	return items, templates, nil
}

// buildProxmoxSubmission is the whole of what leaves, in one place a test can
// read byte for byte. One part of one: the list does not page.
func buildProxmoxSubmission(items []ProxmoxItem, templates int, collectedAt time.Time, host, account, submissionID string) ([]byte, error) {
	withoutID := 0
	for _, item := range items {
		if item.ID == nil {
			withoutID++
		}
	}
	return json.Marshal(map[string]any{
		"envelope": map[string]any{
			"schemaVersion": 1,
			"source":        "proxmox",
			"collectedAt":   collectedAt.UTC().Format(time.RFC3339),
			"senderVersion": "appliance-" + stamp(),
			"host":          host,
			"account":       account,
		},
		"declared": len(items),
		"part": map[string]any{
			"submissionId":  submissionID,
			"page":          1,
			"pages":         1,
			"totalDeclared": len(items),
		},
		"findings": []coverageCheck{
			checkOf("proxmox-guests-listed", len(items)),
			checkOf("proxmox-guests-without-id", withoutID),
			// Every one: the resource list carries no serial and no hardware address.
			checkOf("proxmox-guests-not-correlatable", len(items)-withoutID),
			checkOf("proxmox-templates-not-sent", templates),
		},
		"items": items,
	})
}

// collectProxmox is the -collect-proxmox mode: fetch, read, reduce, sign, send.
func collectProxmox(portal, fingerprint string, private ed25519.PrivateKey) error {
	credential, err := fetchCredential(portal, fingerprint, private)
	if err != nil {
		return fmt.Errorf("%w: fetching the credential: %v", errProxmoxNotAsked, err)
	}
	if !granted(credential, "proxmox") {
		return fmt.Errorf("%w: Proxmox VE is not among what this organization has allowed the collector to read", errProxmoxNotAsked)
	}
	if credential.Proxmox == nil {
		return fmt.Errorf("%w: no Proxmox VE cluster is named for this collector in the portal", errProxmoxNotAsked)
	}
	named := *credential.Proxmox
	credential.Proxmox = nil

	base, err := proxmoxBase(named.URL)
	if err != nil {
		return err
	}
	client, err := proxmoxClient(named.Fingerprint)
	if err != nil {
		return err
	}

	collectedAt := time.Now()
	resources, err := listGuests(client, base, named)
	named.Secret = ""
	if err != nil {
		return err
	}
	items, templates, err := reduceGuests(resources)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		// Far more often a token that may see nothing than a cluster with no
		// guests. Said here rather than sent.
		return fmt.Errorf("Proxmox VE listed no guest this token may see, so nothing was sent")
	}
	fmt.Printf("guests: %d listed, %d templates left out\n", len(items), templates)

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("minting a submission id: %w", err)
	}
	hostName, _ := os.Hostname()
	body, err := buildProxmoxSubmission(items, templates, collectedAt, hostName, os.Getenv("CAIRN_PRINCIPAL"), hex.EncodeToString(id))
	if err != nil {
		return err
	}
	if err := signedPost(portal, collectionPath, "application/json", fingerprint, private, body); err != nil {
		return err
	}
	fmt.Println("submitted")
	return nil
}
