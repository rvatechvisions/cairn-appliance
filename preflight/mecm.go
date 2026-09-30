package main

// The Configuration Manager (SCCM / MECM) reader. WO-0929-B item 8.
//
// It reads the systems a site's SMS Provider has discovered, through the
// administration service -- GET <SMS Provider>/AdminService/wmi/SMS_R_System --
// and submits five fields per system to the portal's collection door, signed
// with the key this appliance enrolled with. It installs nothing on the site
// and changes nothing there.
//
// ## Why this is on the appliance
//
// The administration service lives on the SMS Provider, inside the client's
// network, and answers a Windows account. Microsoft documents a route through
// the cloud management gateway as well; nothing here uses it. So the reader
// runs where the network is, as the directory reader does.
//
// ## Signing in, and what outlives the read
//
// Kerberos, from the ticket cache preflight.sh established, presented to the
// service principal HTTP/<provider host> in a Negotiate header. No NTLM: a
// fallback would let this succeed where the collector would not. A service
// ticket is not a session on the provider -- nothing is left there that an
// administrator could find -- and it expires with the cache the run already
// discards, so there is nothing to sign out of (WO-0929-B item 5).
//
// **Whether the administration service accepts a Negotiate header from a
// client outside the domain is unverified.** Microsoft's pages say the caller
// must be an administrative user in Configuration Manager and show a request
// arriving as DOMAIN\user, and the usage page says "Choose Windows
// Authentication" and sends -UseDefaultCredentials -- so the scheme is Windows
// authentication, which is Negotiate. What they do not say is Kerberos against
// NTLM, and it is Kerberos this reader sends. Read 30 September 2026;
// WO-0930-F item 5. The first site that answers is the verification.
//
// ## The certificate is the provider's own, and it is pinned
//
// By default the SMS Provider presents a certificate the site creates for
// itself, which no public root trusts. Rather than trusting everything, the
// portal holds the certificate's SHA-256 fingerprint, entered by a person who
// read it off the provider, and the connection is refused unless the leaf the
// provider presents matches it. A redirect is returned, never followed.
//
// ## What is asked, and what leaves
//
// The whole SMS_R_System object is asked for -- a $select is a claim about
// somebody else's schema -- and five properties leave: ResourceID (the key),
// Name, Client, OperatingSystemNameandVersion and IsVirtualMachine. A record
// Configuration Manager marks Obsolete (superseded by another record for the
// same computer) or Decommissioned is not sent, and is counted. Nothing about
// users, groups, OUs, addresses or sites leaves.
//
// ## Paging
//
// An OData answer carries @odata.nextLink when there is more. The next link is
// followed only when it stays on the provider's own origin and under
// AdminService, and a list past mecmPageGuard pages is refused -- that ceiling
// is ours, and Microsoft documents none for this route in what was read.
//
// WHETHER THE ADMINISTRATION SERVICE PAGES AT ALL IS UNREAD. Following a next
// link is what an OData service does when it pages; no Microsoft page read says
// that AdminService's WMI route does, at what size, or that it never does.
// Recorded as unread rather than as matching on 30 September 2026 (WO-0930-F
// item 5). A service that returned a truncated list with no next link would
// not be detected here, and the first large site is what answers it.
//
// Built from Microsoft Learn, read 28 September 2026: What is the
// administration service (the two routes, HTTPS, OData v4, the administrative
// user requirement), How to set up the admin service (the self-signed
// certificate, the cloud management gateway route, the request log showing a
// domain user), and the SMS_R_System class (its properties and their types).
// Never run against a live site.

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

	krbclient "github.com/oiweiwei/gokrb5.fork/v9/client"
	krbconfig "github.com/oiweiwei/gokrb5.fork/v9/config"
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"
	"github.com/oiweiwei/gokrb5.fork/v9/spnego"
)

// mecmCredential is what the portal hands over for an MECM slot: where the
// administration service is, and the fingerprint of the certificate it must
// present. The account is the directory account preflight.sh signed in as.
type mecmCredential struct {
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
}

// MecmItem is what leaves the box for one system. Five fields, and a sixth
// is refused at the portal's door.
type MecmItem struct {
	ResourceID       *int64  `json:"ResourceID"`
	Name             *string `json:"Name"`
	Client           *int64  `json:"Client"`
	OperatingSystem  *string `json:"OperatingSystemNameandVersion"`
	IsVirtualMachine *bool   `json:"IsVirtualMachine"`
}

// mecmPageGuard is ours, not Microsoft's.
const mecmPageGuard = 500

var errMecmNotAsked = errors.New("not asked")

// adminServiceBase is the https origin and path of an administration service
// address, ending in /AdminService.
func adminServiceBase(address string) (*url.URL, error) {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" {
		return nil, fmt.Errorf("%q is not an administration service address", address)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("the administration service address %q is not https", address)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("the administration service address carries a user name")
	}
	if !strings.EqualFold(strings.TrimRight(parsed.Path, "/"), "/AdminService") {
		return nil, fmt.Errorf("the administration service address %q does not end in /AdminService", address)
	}
	parsed.Path = "/AdminService"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed, nil
}

// pinnedClient trusts exactly the certificate whose SHA-256 fingerprint the
// portal holds, and returns a redirect rather than following it.
func pinnedClient(fingerprint string) (*http.Client, error) {
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
						return fmt.Errorf("the administration service presented no certificate")
					}
					got := sha256.Sum256(raw[0])
					if !bytes.Equal(got[:], want) {
						return fmt.Errorf("the administration service presented a certificate whose fingerprint is %s, not the one the portal holds", hex.EncodeToString(got[:]))
					}
					return nil
				},
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// ticketClient is the Kerberos client over the ticket cache preflight.sh holds.
func ticketClient() (*krbclient.Client, error) {
	ccname := os.Getenv("KRB5CCNAME")
	if ccname == "" {
		return nil, fmt.Errorf("KRB5CCNAME is unset: this runs from preflight.sh, which sets it")
	}
	ccpath := strings.TrimPrefix(ccname, "FILE:")
	if ccpath == ccname && strings.Contains(ccname, ":") {
		return nil, fmt.Errorf("KRB5CCNAME is %q, and only a FILE: cache can be read here", ccname)
	}
	cache, err := credentials.LoadCCache(ccpath)
	if err != nil {
		return nil, fmt.Errorf("reading the ticket cache at %s: %w", ccpath, err)
	}
	confPath := os.Getenv("KRB5_CONFIG")
	if confPath == "" {
		confPath = "/etc/krb5.conf"
	}
	conf, err := krbconfig.Load(confPath)
	if err != nil {
		return nil, fmt.Errorf("reading the Kerberos configuration at %s: %w", confPath, err)
	}
	return krbclient.NewFromCCache(cache, conf)
}

// mecmPage is one OData answer: the systems and the next link, if any.
type mecmPage struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}

// sameService refuses a next link that leaves the provider or AdminService.
func sameService(base *url.URL, next string) (*url.URL, error) {
	parsed, err := base.Parse(next)
	if err != nil {
		return nil, fmt.Errorf("the administration service named a next page that is not an address")
	}
	if parsed.Scheme != base.Scheme || !strings.EqualFold(parsed.Host, base.Host) || !strings.HasPrefix(strings.ToLower(parsed.Path), "/adminservice/") {
		return nil, fmt.Errorf("the administration service named a next page at %s, which is not this provider's administration service; it is not followed", parsed.Redacted())
	}
	return parsed, nil
}

// listSystems reads every SMS_R_System record, page by page. authorize puts
// the Negotiate header on each request; it is a parameter so a test can stand
// in for the ticket.
func listSystems(client *http.Client, authorize func(*http.Request) error, base *url.URL) ([]json.RawMessage, error) {
	next := base.JoinPath("wmi", "SMS_R_System")
	var out []json.RawMessage
	for page := 0; ; page++ {
		if page >= mecmPageGuard {
			return nil, fmt.Errorf("the administration service returned more than %d pages of systems; that is Cairn's ceiling, not Microsoft's, and nothing was sent", mecmPageGuard)
		}
		request, err := http.NewRequest(http.MethodGet, next.String(), nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/json")
		if err := authorize(request); err != nil {
			return nil, err
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("reaching the administration service: %w", err)
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("reading the administration service's answer: %w", readErr)
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			return nil, fmt.Errorf("the administration service answered with a redirect (%d); it is returned, not followed, and nothing was sent", response.StatusCode)
		}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("the administration service refused the account (%d); it must be an administrative user in Configuration Manager", response.StatusCode)
		}
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("the administration service answered with %d", response.StatusCode)
		}
		var parsed mecmPage
		if err := json.Unmarshal(body, &parsed); err != nil || parsed.Value == nil {
			return nil, fmt.Errorf("the administration service's answer carried no value list")
		}
		out = append(out, parsed.Value...)
		if parsed.NextLink == "" {
			return out, nil
		}
		following, err := sameService(base, parsed.NextLink)
		if err != nil {
			return nil, err
		}
		if following.String() == next.String() {
			return nil, fmt.Errorf("the administration service named the same page as next; the list is not read as complete")
		}
		next = following
	}
}

// reduceSystems keeps the five fields of every system that is neither
// obsolete nor decommissioned, and counts the ones left out.
func reduceSystems(raw []json.RawMessage) (items []MecmItem, obsolete, decommissioned int, err error) {
	for index, record := range raw {
		var system struct {
			ResourceID                    *int64  `json:"ResourceID"`
			Name                          *string `json:"Name"`
			Client                        *int64  `json:"Client"`
			Obsolete                      *int64  `json:"Obsolete"`
			Decommissioned                *int64  `json:"Decommissioned"`
			OperatingSystemNameandVersion *string `json:"OperatingSystemNameandVersion"`
			IsVirtualMachine              *bool   `json:"IsVirtualMachine"`
		}
		if err := json.Unmarshal(record, &system); err != nil {
			return nil, 0, 0, fmt.Errorf("system %d is not a record this reader understands: %w", index, err)
		}
		if system.Obsolete != nil && *system.Obsolete == 1 {
			obsolete++
			continue
		}
		if system.Decommissioned != nil && *system.Decommissioned == 1 {
			decommissioned++
			continue
		}
		var name, os *string
		if system.Name != nil {
			name = nonEmpty(*system.Name)
		}
		if system.OperatingSystemNameandVersion != nil {
			os = nonEmpty(*system.OperatingSystemNameandVersion)
		}
		items = append(items, MecmItem{
			ResourceID:       system.ResourceID,
			Name:             name,
			Client:           system.Client,
			OperatingSystem:  os,
			IsVirtualMachine: system.IsVirtualMachine,
		})
	}
	return items, obsolete, decommissioned, nil
}

// buildMecmSubmission is the whole of what leaves, in one place a test can
// read byte for byte. One part of one.
func buildMecmSubmission(items []MecmItem, obsolete, decommissioned int, collectedAt time.Time, host, account, submissionID string) ([]byte, error) {
	withoutID := 0
	for _, item := range items {
		if item.ResourceID == nil {
			withoutID++
		}
	}
	return json.Marshal(map[string]any{
		"envelope": map[string]any{
			"schemaVersion": 1,
			"source":        "mecm",
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
			checkOf("mecm-systems-listed", len(items)),
			checkOf("mecm-systems-without-id", withoutID),
			checkOf("mecm-systems-obsolete", obsolete),
			checkOf("mecm-systems-decommissioned", decommissioned),
		},
		"items": items,
	})
}

// collectMecm is the -collect-mecm mode: fetch, read, reduce, sign, send.
func collectMecm(portal, fingerprint string, private ed25519.PrivateKey) error {
	credential, err := fetchCredential(portal, fingerprint, private)
	if err != nil {
		return fmt.Errorf("%w: fetching the credential: %v", errMecmNotAsked, err)
	}
	if !granted(credential, "mecm") {
		return fmt.Errorf("%w: Configuration Manager is not among what this organization has allowed the collector to read", errMecmNotAsked)
	}
	if credential.Mecm == nil {
		return fmt.Errorf("%w: no administration service is named for this collector in the portal", errMecmNotAsked)
	}
	named := *credential.Mecm
	credential.Mecm = nil

	base, err := adminServiceBase(named.URL)
	if err != nil {
		return err
	}
	client, err := pinnedClient(named.Fingerprint)
	if err != nil {
		return err
	}
	krb, err := ticketClient()
	if err != nil {
		return err
	}
	defer krb.Destroy()

	spn := "HTTP/" + base.Hostname()
	authorize := func(request *http.Request) error {
		if err := spnego.SetSPNEGOHeader(krb, request, spn); err != nil {
			return fmt.Errorf("presenting the ticket for %s: %w", spn, err)
		}
		return nil
	}

	collectedAt := time.Now()
	raw, err := listSystems(client, authorize, base)
	if err != nil {
		return err
	}
	items, obsolete, decommissioned, err := reduceSystems(raw)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return fmt.Errorf("the administration service listed no system this account may see, so nothing was sent")
	}
	fmt.Printf("systems: %d listed, %d obsolete and %d decommissioned left out\n", len(items), obsolete, decommissioned)

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("minting a submission id: %w", err)
	}
	hostName, _ := os.Hostname()
	body, err := buildMecmSubmission(items, obsolete, decommissioned, collectedAt, hostName, os.Getenv("CAIRN_PRINCIPAL"), hex.EncodeToString(id))
	if err != nil {
		return err
	}
	if err := signedPost(portal, collectionPath, "application/json", fingerprint, private, body); err != nil {
		return err
	}
	fmt.Println("submitted")
	return nil
}
