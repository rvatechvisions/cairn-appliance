package main

// The DHCP reader. WO-0928-B item 7.
//
// It reads every scope on one server, reduces the leases to the inventory R20
// permits (see leases.go), and submits that to the portal's collection door
// signed with the key this appliance enrolled with. The lease list is held in
// memory for the length of the read and is never written to disk or sent.
//
// ## What is sent about coverage, and what is not
//
// The door needs to know how much of the source this reading covers before it
// may retire anything: scopes attempted, scopes that refused, scopes that were
// empty. It needs the COUNTS, and the counts are all that is sent. The scope
// identifiers are the structure of somebody's network and they are part of
// what the lease list is; the portal decides retirement on the counts alone.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	dhcpsrv "github.com/oiweiwei/go-msrpc/msrpc/dhcpm/dhcpsrv/v1"
	dhcpsrv2 "github.com/oiweiwei/go-msrpc/msrpc/dhcpm/dhcpsrv2/v1"
)

const collectionPath = "/ingest/collection"

// scopeCoverage is what the reading can say about its own reach.
type scopeCoverage struct {
	Attempted  int
	Unreadable int
	Empty      int
}

type coverageCheck struct {
	ID    string `json:"id"`
	State string `json:"state"`
	Count int    `json:"count"`
}

func checkOf(id string, count int) coverageCheck {
	state := "not-found"
	if count > 0 {
		state = "found"
	}
	return coverageCheck{ID: id, State: state, Count: count}
}

// buildSubmission is the whole of what leaves, assembled in one place so a
// test can read it byte for byte. One part of one: this reader does not page.
func buildSubmission(items []DerivedItem, coverage scopeCoverage, collectedAt time.Time, host, account, submissionID string) ([]byte, error) {
	body := map[string]any{
		"envelope": map[string]any{
			"schemaVersion": 1,
			"source":        "dhcp",
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
			checkOf("dhcp-scopes-attempted", coverage.Attempted),
			checkOf("dhcp-scopes-unreadable", coverage.Unreadable),
			checkOf("dhcp-scopes-empty", coverage.Empty),
		},
		"items": items,
	}
	return json.Marshal(body)
}

// readAllLeases walks every scope and every page of every scope. A scope that
// refuses is counted and skipped, never read as empty: the door then declines
// to retire anything this reading did not reach.
func readAllLeases(ctx context.Context, servers dhcpsrv.DHCPServerClient, clients dhcpsrv2.Dhcpsrv2Client, server string) ([]leaseRecord, scopeCoverage, error) {
	subnets, err := servers.EnumSubnets(ctx, &dhcpsrv.EnumSubnetsRequest{
		ServerIPAddress:  server,
		PreferredMaximum: 0xFFFFFFFF,
	})
	if err != nil {
		return nil, scopeCoverage{}, fmt.Errorf("R_DhcpEnumSubnets: %w", err)
	}
	var addresses []uint32
	if subnets != nil && subnets.EnumInfo != nil {
		addresses = subnets.EnumInfo.Elements
	}

	var leases []leaseRecord
	coverage := scopeCoverage{}
	for _, address := range addresses {
		coverage.Attempted++
		var resume uint32
		read := 0
		failed := false
		for {
			page, err := clients.EnumSubnetClientsV5(ctx, &dhcpsrv2.EnumSubnetClientsV5Request{
				ServerIPAddress:  server,
				SubnetAddress:    address,
				Resume:           resume,
				PreferredMaximum: 0xFFFFFFFF,
			})
			if err != nil {
				if strings.Contains(err.Error(), "ERROR_NO_MORE_ITEMS") {
					break
				}
				failed = true
				break
			}
			if page == nil || page.ClientInfo == nil || len(page.ClientInfo.Clients) == 0 {
				break
			}
			for _, client := range page.ClientInfo.Clients {
				if client == nil {
					continue
				}
				record := leaseRecord{IP: client.ClientIPAddress, Mask: client.SubnetMask, HostName: client.ClientName}
				if client.ClientHardwareAddress != nil {
					record.UID = client.ClientHardwareAddress.Data
				}
				leases = append(leases, record)
				read++
			}
			// ERROR_MORE_DATA arrives as a successful page with a resume
			// handle; a handle that does not move means the server has nothing
			// further, and looping on it would never end.
			if page.Resume == resume {
				break
			}
			resume = page.Resume
		}
		switch {
		case failed:
			coverage.Unreadable++
		case read == 0:
			coverage.Empty++
		}
	}
	return leases, coverage, nil
}

// collectDHCP is the -collect-dhcp mode: bind, read, reduce, sign, send.
func collectDHCP(ctx context.Context, server, transport, targetName string, debug bool, portal, fingerprint string, private ed25519.PrivateKey) error {
	servers, clients, closer, ctx, err := bindDHCP(ctx, server, transport, targetName, debug)
	if err != nil {
		return err
	}
	defer closer()

	collectedAt := time.Now()
	leases, coverage, err := readAllLeases(ctx, servers, clients, server)
	if err != nil {
		return err
	}
	items, unkeyable := derive(leases)
	leases = nil

	fmt.Printf("scopes: %d attempted, %d refused, %d empty\n", coverage.Attempted, coverage.Unreadable, coverage.Empty)
	fmt.Printf("devices: %d, from leases whose hardware address could be read; %d refused as unreadable\n", len(items), unkeyable)

	if len(items) == 0 {
		// The door refuses an empty submission, and it is right to: nothing
		// read is far more often a reader that could not than an estate that
		// emptied. Said here rather than sent to be refused.
		return fmt.Errorf("no lease with a readable hardware address was found, so nothing was sent")
	}

	// A lease whose hardware address could not be read travels as an item
	// carrying nothing at all, so the portal counts it the way it already
	// counts one: refused and counted, and nothing of the lease leaves with it.
	items = append(items, make([]DerivedItem, unkeyable)...)

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return fmt.Errorf("minting a submission id: %w", err)
	}
	host, _ := os.Hostname()
	body, err := buildSubmission(items, coverage, collectedAt, host, os.Getenv("CAIRN_PRINCIPAL"), hex.EncodeToString(id))
	if err != nil {
		return err
	}
	if err := signedPost(portal, collectionPath, "application/json", fingerprint, private, body); err != nil {
		return err
	}
	fmt.Println("submitted")
	return nil
}
