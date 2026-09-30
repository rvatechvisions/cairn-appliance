package main

// The vSphere reader. WO-0929-A item 9.
//
// It reads the virtual machines an existing vCenter Server lists, with ONE
// read -- GET /api/vcenter/vm -- and submits five fields per virtual machine
// to the portal's collection door, signed with the key this appliance
// enrolled with. It installs nothing on vCenter and changes nothing there.
//
// ## Signing in, which is the only thing that is not a read
//
// vCenter's REST API is read with a session: POST /api/session with the
// account's name and password returns a session id, and DELETE /api/session
// ends it. The session is the sign-in and nothing else -- it creates no
// object anybody else can see -- and it is ended as soon as the read returns,
// whatever the read did, so the appliance leaves nothing open in vCenter.
//
// ## The credential is fetched per run and never touches the shell
//
// The vCenter address, account and password live in the portal, on the
// appliance's vSphere slot, and are fetched on the same signed request the
// directory credential uses, held in memory for the read and dropped. The
// address must be https: the password crosses the client's network to reach
// vCenter, and a plain http address would send it in the clear.
//
// ## What is asked, and what leaves
//
// The VM list's summary is the whole of what is read: vm (vCenter's own id,
// required), name (required), power_state (required), cpu_count and
// memory_size_MiB (both optional). Nothing is asked about guests, disks,
// networks, snapshots, events or performance. What leaves is one item per
// virtual machine carrying exactly those five, and the portal's door refuses
// an item carrying anything else.
//
// **An optional field vCenter did not send is absent, never zero.** A pointer
// that stays nil travels as null and reads, in the portal, as not sent by
// your instance -- not as a machine with no memory.
//
// ## The ceiling is vCenter's, and it is refused rather than worked around
//
// The list has no paging. When a vCenter holds more virtual machines than it
// will return in one answer -- at most 4,000 -- it refuses with HTTP 500 and the
// error type UNABLE_TO_ALLOCATE_RESOURCE. That is read as a refusal, by name, and nothing
// is sent: Cairn carries no cap of its own, and a partial list read by
// narrowing the filter until it fits would be a short list that looks whole.
//
// ## Virtual machines only, and none of them can be correlated
//
// The summary carries no serial number and no hardware address, so a virtual
// machine is keyed on vCenter's own id and can never be joined to what another
// source reports about the guest. The submission says so in a counted finding
// rather than leaving it to be inferred.
//
// Built from the work order's statement of GET /api/vcenter/vm and from
// vCenter's session convention, then read against Broadcom's vSphere
// Automation API 9.1 and 9.1.1 reference on 30 September 2026 (WO-0930-E item
// 5), whose pages render server-side: GET /api/vcenter/vm "Returns information
// about at most 4000 visible ... virtual machines"; 500 "if more than 4000
// virtual machines match", as UnableToAllocateResource, whose discriminator is
// UNABLE_TO_ALLOCATE_RESOURCE; 400 only for an unsupported power state, as
// InvalidArgument. The first version checked for the ceiling under 400, from
// the work order's statement, so the refusal it promised never fired. The
// field Broadcom spells memory_size_mib is decoded under the tag below, which
// encoding/json matches without regard to case. Never run against a live
// vCenter.

import (
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

// vsphereCredential is what the portal hands over for a vSphere slot.
type vsphereCredential struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// VsphereItem is what leaves the box for one virtual machine. Five fields,
// and a sixth is refused at the portal's door.
type VsphereItem struct {
	VM            *string `json:"vm"`
	Name          *string `json:"name"`
	PowerState    *string `json:"power_state"`
	CPUCount      *int64  `json:"cpu_count"`
	MemorySizeMiB *int64  `json:"memory_size_MiB"`
}

var errVsphereNotAsked = errors.New("not asked")

// errVsphereTooMany is vCenter's own ceiling, refused by name.
var errVsphereTooMany = errors.New("unable_to_allocate_resource")

// vcenterBase is the https origin and path of a vCenter address.
func vcenterBase(address string) (string, error) {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("%q is not a vCenter address", address)
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("the vCenter address %q is not https, so the password is not sent to it", address)
	}
	if parsed.User != nil {
		return "", fmt.Errorf("the vCenter address carries a user name; the account is its own field")
	}
	return strings.TrimRight(parsed.Scheme+"://"+parsed.Host+parsed.Path, "/"), nil
}

// openSession signs in and returns the session id.
func openSession(client *http.Client, base string, credential vsphereCredential) (string, error) {
	request, err := http.NewRequest(http.MethodPost, base+"/api/session", nil)
	if err != nil {
		return "", err
	}
	request.SetBasicAuth(credential.Username, credential.Password)
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("reaching vCenter: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("reading vCenter's sign-in answer: %w", err)
	}
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return "", fmt.Errorf("vCenter refused the account (%d)", response.StatusCode)
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("vCenter answered the sign-in with %d", response.StatusCode)
	}
	var session string
	if err := json.Unmarshal(body, &session); err != nil || session == "" {
		return "", fmt.Errorf("vCenter's sign-in answer carried no session id")
	}
	return session, nil
}

// closeSession ends the session this run opened. Its failure is reported and
// does not change what the read returned.
func closeSession(client *http.Client, base, session string) error {
	request, err := http.NewRequest(http.MethodDelete, base+"/api/session", nil)
	if err != nil {
		return err
	}
	request.Header.Set("vmware-api-session-id", session)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("ending the vCenter session: %w", err)
	}
	response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("vCenter answered the sign-out with %d", response.StatusCode)
	}
	return nil
}

// listVMs is the one read.
func listVMs(client *http.Client, base, session string) ([]VsphereItem, error) {
	request, err := http.NewRequest(http.MethodGet, base+"/api/vcenter/vm", nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("vmware-api-session-id", session)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("reaching vCenter: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("reading vCenter's answer: %w", err)
	}
	// The ceiling, by the status and the name Broadcom documents for it.
	if response.StatusCode == http.StatusInternalServerError {
		var refusal struct {
			ErrorType string `json:"error_type"`
		}
		_ = json.Unmarshal(body, &refusal)
		if strings.EqualFold(refusal.ErrorType, "unable_to_allocate_resource") {
			return nil, fmt.Errorf("%w: vCenter holds more virtual machines than it returns in one answer, and it said so; nothing was sent, because a list narrowed until it fits is a short list that looks whole", errVsphereTooMany)
		}
	}
	if response.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("vCenter refused the virtual machine list (400), which Broadcom documents for an unsupported power state")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vCenter answered the virtual machine list with %d", response.StatusCode)
	}

	var vms []struct {
		VM            string          `json:"vm"`
		Name          string          `json:"name"`
		PowerState    string          `json:"power_state"`
		CPUCount      json.RawMessage `json:"cpu_count"`
		MemorySizeMiB json.RawMessage `json:"memory_size_MiB"`
	}
	if err := json.Unmarshal(body, &vms); err != nil {
		return nil, fmt.Errorf("vCenter's answer was not a list of virtual machines: %w", err)
	}
	items := make([]VsphereItem, 0, len(vms))
	for _, vm := range vms {
		cpu, err := optionalCount(vm.CPUCount)
		if err != nil {
			return nil, fmt.Errorf("virtual machine %s: cpu_count %w", vm.VM, err)
		}
		memory, err := optionalCount(vm.MemorySizeMiB)
		if err != nil {
			return nil, fmt.Errorf("virtual machine %s: memory_size_MiB %w", vm.VM, err)
		}
		items = append(items, VsphereItem{
			VM:            nonEmpty(vm.VM),
			Name:          nonEmpty(vm.Name),
			PowerState:    nonEmpty(vm.PowerState),
			CPUCount:      cpu,
			MemorySizeMiB: memory,
		})
	}
	return items, nil
}

// optionalCount reads an optional long: absent or null is nil, never zero.
func optionalCount(raw json.RawMessage) (*int64, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("is not a whole number")
	}
	return &value, nil
}

// readVsphere signs in, reads, and signs out -- the sign-out whatever the read did.
//
// WO-0929-B item 5: read-only forbids anything that outlives the read, and a
// session that ends is not an artifact -- one left open is. So a sign-out that
// fails is reported, never swallowed: with the list, as a counted finding the
// portal files; without it, in the error the run reports. A vCenter
// administrator who finds a session we left should have heard it from us first.
func readVsphere(client *http.Client, credential vsphereCredential) ([]VsphereItem, bool, error) {
	base, err := vcenterBase(credential.URL)
	if err != nil {
		return nil, false, err
	}
	session, err := openSession(client, base, credential)
	if err != nil {
		return nil, false, err
	}
	items, readErr := listVMs(client, base, session)
	closeErr := closeSession(client, base, session)
	leftOpen := closeErr != nil
	if leftOpen {
		fmt.Fprintln(os.Stderr, "preflight:", closeErr, "-- the session may stay open on vCenter until it times out")
	}
	if readErr != nil && leftOpen {
		return nil, true, fmt.Errorf("%w; and signing out failed too, so the session may stay open on vCenter until it times out", readErr)
	}
	return items, leftOpen, readErr
}

// buildVsphereSubmission is the whole of what leaves, in one place a test can
// read byte for byte. One part of one: the list does not page.
func buildVsphereSubmission(items []VsphereItem, sessionLeftOpen bool, collectedAt time.Time, host, account, submissionID string) ([]byte, error) {
	leftOpen := 0
	if sessionLeftOpen {
		leftOpen = 1
	}
	withoutID := 0
	for _, item := range items {
		if item.VM == nil {
			withoutID++
		}
	}
	return json.Marshal(map[string]any{
		"envelope": map[string]any{
			"schemaVersion": 1,
			"source":        "vsphere",
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
			checkOf("vsphere-vms-listed", len(items)),
			checkOf("vsphere-vms-without-id", withoutID),
			// Every one: the summary carries no serial and no hardware address.
			checkOf("vsphere-vms-not-correlatable", len(items)-withoutID),
			// The session this run could not close, reported rather than swallowed.
			checkOf("vsphere-session-left-open", leftOpen),
		},
		"items": items,
	})
}

// collectVsphere is the -collect-vsphere mode: fetch, read, reduce, sign, send.
func collectVsphere(client *http.Client, portal, fingerprint string, private ed25519.PrivateKey) error {
	credential, err := fetchCredential(portal, fingerprint, private)
	if err != nil {
		return fmt.Errorf("%w: fetching the credential: %v", errVsphereNotAsked, err)
	}
	if !granted(credential, "vsphere") {
		return fmt.Errorf("%w: vSphere is not among what this organization has allowed the collector to read", errVsphereNotAsked)
	}
	if credential.Vsphere == nil {
		return fmt.Errorf("%w: no vCenter is named for this collector in the portal", errVsphereNotAsked)
	}

	collectedAt := time.Now()
	items, leftOpen, err := readVsphere(client, *credential.Vsphere)
	credential.Vsphere = nil
	if err != nil {
		return err
	}
	if len(items) == 0 {
		// Far more often an account that may see nothing than a vCenter with
		// no virtual machines. Said here rather than sent.
		return fmt.Errorf("vCenter listed no virtual machine this account may see, so nothing was sent")
	}
	fmt.Printf("virtual machines: %d listed\n", len(items))

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("minting a submission id: %w", err)
	}
	hostName, _ := os.Hostname()
	body, err := buildVsphereSubmission(items, leftOpen, collectedAt, hostName, os.Getenv("CAIRN_PRINCIPAL"), hex.EncodeToString(id))
	if err != nil {
		return err
	}
	if err := signedPost(portal, collectionPath, "application/json", fingerprint, private, body); err != nil {
		return err
	}
	fmt.Println("submitted")
	return nil
}
