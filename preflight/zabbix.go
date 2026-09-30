package main

// The Zabbix reader. WO-0928-F item 5a.
//
// It reads an existing Zabbix server the client already runs -- the appliance
// installs nothing there and creates nothing there -- with ONE JSON-RPC
// method, host.get, and submits four fields per host to the portal's
// collection door, signed with the key this appliance enrolled with.
//
// ## The credential is fetched per run and never touches the shell
//
// The Zabbix address and API token live in the portal, on the appliance's
// Zabbix slot. This mode fetches them itself, on the same signed request the
// directory credential uses, holds them in memory for the read and drops them
// when the process exits. Unlike the directory password they are never
// written to stdout for the shell to carry: nothing but this process needs
// them, so nothing else is handed them.
//
// ## What is asked, and what leaves
//
// host.get is asked for `hostid` and `name`, and for the inventory fields
// `serialno_a` and `macaddress_a`. It is NOT asked for interfaces, items,
// triggers, history or problems -- those are the monitoring data, and the
// monitoring data stays on the client's equipment the way a lease list does.
// Not asking is stronger than asking and discarding: an address never enters
// this process, so no later change here can send one.
//
// What leaves is one item per host carrying exactly hostid, name, serial and
// mac, and the portal's door refuses an item carrying anything else.
//
// ## Reach, and the documented ceiling
//
// The address must be https: the token crosses the client's network to reach
// the server, and a plain http address would send it in the clear. host.get
// documents no paging -- it returns every host the token's user may read in
// one answer -- so this reads once and does not page. A token whose user can
// see only some hosts produces a submission covering only those, which is why
// the portal requires no coverage of this source and retires nothing from it.
//
// Built from Zabbix's published API documentation (the JSON-RPC overview and
// host.get, and API token authentication with the Authorization: Bearer
// header, available from Zabbix 6.4), read 28 September 2026. Never run
// against a live Zabbix server.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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

// zabbixCredential is what the portal hands over for a Zabbix slot.
type zabbixCredential struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// ZabbixItem is what leaves the box for one host. Four fields, and a fifth is
// refused at the portal's door.
type ZabbixItem struct {
	HostID *string `json:"hostid"`
	Name   *string `json:"name"`
	Serial *string `json:"serial"`
	Mac    *string `json:"mac"`
}

// errZabbixNotAsked is a run that asked nothing of any Zabbix server: not
// granted, or no server named. It is not a refusal by the network.
var errZabbixNotAsked = errors.New("not asked")

// The one request this reader makes. Its output list is the whole of what is
// read; anything added here is something new read from a client's server.
func hostGetRequest() ([]byte, error) {
	return json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "host.get",
		"params": map[string]any{
			"output":          []string{"hostid", "name"},
			"selectInventory": []string{"serialno_a", "macaddress_a"},
		},
		"id": 1,
	})
}

// apiEndpoint is the JSON-RPC endpoint under an https Zabbix address.
func apiEndpoint(address string) (string, error) {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("%q is not a Zabbix address", address)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("the Zabbix address %q is not https, so the token is not sent to it", address)
	}
	return strings.TrimRight(parsed.String(), "/") + "/api_jsonrpc.php", nil
}

func nonEmpty(value string) *string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

// readZabbixHosts asks host.get once and reduces the answer to the four
// fields. A host with no id is still returned, carrying no id, so the portal
// counts it the way it counts any unkeyable record.
func readZabbixHosts(client *http.Client, credential zabbixCredential) ([]ZabbixItem, error) {
	endpoint, err := apiEndpoint(credential.URL)
	if err != nil {
		return nil, err
	}
	payload, err := hostGetRequest()
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json-rpc")
	request.Header.Set("Authorization", "Bearer "+credential.Token)

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("reaching the Zabbix server: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading the Zabbix answer: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the Zabbix server answered %d", response.StatusCode)
	}

	var answer struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
			Data    string `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		return nil, fmt.Errorf("the Zabbix answer did not parse: %w", err)
	}
	if answer.Error != nil {
		return nil, fmt.Errorf("Zabbix refused host.get: %s %s", answer.Error.Message, answer.Error.Data)
	}
	if answer.Result == nil {
		return nil, fmt.Errorf("the Zabbix answer carried neither a result nor an error")
	}

	var hosts []struct {
		HostID string `json:"hostid"`
		Name   string `json:"name"`
		// An object when inventory is enabled on the host. What comes back when
		// it is not is NOT documented: neither the host.get page nor the host
		// object page, in 6.4, 7.0 or 7.4, says -- read 30 September 2026. An
		// empty array is what an unset inventory would plausibly serialize as,
		// so it is parsed as well as an object, and that tolerance is ours
		// rather than Zabbix's word. WO-0930-F item 5.
		Inventory json.RawMessage `json:"inventory"`
	}
	if err := json.Unmarshal(answer.Result, &hosts); err != nil {
		return nil, fmt.Errorf("the Zabbix result was not a host list: %w", err)
	}

	items := make([]ZabbixItem, 0, len(hosts))
	for _, host := range hosts {
		var inventory struct {
			Serial string `json:"serialno_a"`
			Mac    string `json:"macaddress_a"`
		}
		trimmed := bytes.TrimSpace(host.Inventory)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			if err := json.Unmarshal(trimmed, &inventory); err != nil {
				return nil, fmt.Errorf("host %s: the inventory did not parse: %w", host.HostID, err)
			}
		}
		items = append(items, ZabbixItem{
			HostID: nonEmpty(host.HostID),
			Name:   nonEmpty(host.Name),
			Serial: nonEmpty(inventory.Serial),
			Mac:    nonEmpty(inventory.Mac),
		})
	}
	return items, nil
}

// buildZabbixSubmission is the whole of what leaves, in one place a test can
// read byte for byte. One part of one: host.get does not page.
func buildZabbixSubmission(items []ZabbixItem, collectedAt time.Time, host, account, submissionID string) ([]byte, error) {
	withoutID := 0
	for _, item := range items {
		if item.HostID == nil {
			withoutID++
		}
	}
	return json.Marshal(map[string]any{
		"envelope": map[string]any{
			"schemaVersion": 1,
			"source":        "zabbix",
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
			checkOf("zabbix-hosts-listed", len(items)),
			checkOf("zabbix-hosts-without-id", withoutID),
		},
		"items": items,
	})
}

func granted(credential directoryCredential, capability string) bool {
	if credential.Capabilities == nil {
		return false
	}
	for _, each := range *credential.Capabilities {
		if each == capability {
			return true
		}
	}
	return false
}

// collectZabbix is the -collect-zabbix mode: fetch, read, reduce, sign, send.
func collectZabbix(client *http.Client, portal, fingerprint string, private ed25519.PrivateKey) error {
	credential, err := fetchCredential(portal, fingerprint, private)
	if err != nil {
		// Our side, not the Zabbix server saying no: nothing was asked of it.
		return fmt.Errorf("%w: fetching the credential: %v", errZabbixNotAsked, err)
	}
	if !granted(credential, "zabbix") {
		return fmt.Errorf("%w: Zabbix is not among what this organization has allowed the collector to read", errZabbixNotAsked)
	}
	if credential.Zabbix == nil {
		return fmt.Errorf("%w: no Zabbix server is named for this collector in the portal", errZabbixNotAsked)
	}

	collectedAt := time.Now()
	items, err := readZabbixHosts(client, *credential.Zabbix)
	credential.Zabbix = nil
	if err != nil {
		return err
	}
	if len(items) == 0 {
		// An empty host list is far more often a token whose user may read
		// nothing than a server monitoring nothing. Said here rather than sent.
		return fmt.Errorf("the Zabbix server listed no host this token may read, so nothing was sent")
	}
	fmt.Printf("hosts: %d listed\n", len(items))

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("minting a submission id: %w", err)
	}
	hostName, _ := os.Hostname()
	body, err := buildZabbixSubmission(items, collectedAt, hostName, os.Getenv("CAIRN_PRINCIPAL"), hex.EncodeToString(id))
	if err != nil {
		return err
	}
	if err := signedPost(portal, collectionPath, "application/json", fingerprint, private, body); err != nil {
		return err
	}
	fmt.Println("submitted")
	return nil
}
