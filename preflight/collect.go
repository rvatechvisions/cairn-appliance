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
	"time"

	dhcpsrv "github.com/oiweiwei/go-msrpc/msrpc/dhcpm/dhcpsrv/v1"
	dhcpsrv2 "github.com/oiweiwei/go-msrpc/msrpc/dhcpm/dhcpsrv2/v1"
)

const collectionPath = "/ingest/collection"

// scopeCoverage is what the reading can say about its own reach.
//
// Unreadable counts every scope that could not be read COMPLETELY: one that
// refused outright, one that failed part-way, and one whose server kept saying
// there was more without sending anything new. A scope read in part is never
// reported as a scope with few devices -- it is counted here, so the door
// retires nothing on its strength. WO-0930-F item 1.
//
// Incomplete names each of those scopes, with what stopped it. It is printed on
// this box and never sent: a scope address is the structure of the network the
// lease list describes, and only the counts leave (R20).
type scopeCoverage struct {
	Attempted  int
	Unreadable int
	Empty      int
	Incomplete []incompleteScope
}

// incompleteScope is one scope that could not be read completely, for the
// box's own output.
type incompleteScope struct {
	Address string
	Read    int
	Reason  string
}

// The Win32 codes MS-DHCPM gives for its enumerations. R_DhcpEnumSubnets and
// R_DhcpEnumSubnetClientsV5 both document ERROR_MORE_DATA as "there are more
// elements available to enumerate" and ERROR_NO_MORE_ITEMS as "there are no
// more elements left to enumerate" (MS-DHCPM, as carried in go-msrpc v1.6.4;
// the Win32 DhcpEnumSubnetClientsV5 page, updated 2024-02-22, says of
// ERROR_MORE_DATA: "call this function again with the returned resume handle").
// Read on 30 September 2026.
//
// go-msrpc returns a non-zero code as an error AND hands back the response
// carrying it, so the loops below read the code from the response rather than
// matching text in the error.
const (
	dhcpErrorSuccess     = 0x00000000
	dhcpErrorMoreData    = 0x000000EA
	dhcpErrorNoMoreItems = 0x00000103
)

// dhcpPageGuard bounds one enumeration. A server answering ERROR_MORE_DATA for
// ever would otherwise hold the run for ever; reaching the guard is reported as
// a read that could not finish, never as a finished one.
const dhcpPageGuard = 10000

// enumerateSubnets reads every scope the server serves, page by page.
//
// The stop is the server's own code, never the resume handle: MS-DHCPM does not
// say what the handle holds after the last page, so a loop that stopped when the
// handle stopped moving would, on a server that resets it, start the list again.
// A page that claims more and adds no scope not already seen is a server that
// will not finish, and it is refused rather than looped on.
//
// No scopes at all is an answer. R_DhcpEnumSubnets answers ERROR_NO_MORE_ITEMS
// on a server that serves none, which is what MS-DHCPM documents the code to
// mean -- read from the specification, not yet seen from a server with no
// scopes, and first contact is what confirms it.
func enumerateSubnets(ctx context.Context, servers dhcpsrv.DHCPServerClient, server string) ([]uint32, error) {
	var addresses []uint32
	seen := map[uint32]bool{}
	var resume uint32
	for pages := 0; ; pages++ {
		if pages == dhcpPageGuard {
			return nil, fmt.Errorf("R_DhcpEnumSubnets was still answering ERROR_MORE_DATA after %d pages, so the scope list was not read completely", dhcpPageGuard)
		}
		page, err := servers.EnumSubnets(ctx, &dhcpsrv.EnumSubnetsRequest{
			ServerIPAddress:  server,
			Resume:           resume,
			PreferredMaximum: 0xFFFFFFFF,
		})
		if page == nil {
			if err == nil {
				err = fmt.Errorf("no response")
			}
			return nil, fmt.Errorf("R_DhcpEnumSubnets: %w", err)
		}
		switch page.Return {
		case dhcpErrorNoMoreItems:
			return addresses, nil
		case dhcpErrorSuccess, dhcpErrorMoreData:
		default:
			if err == nil {
				err = fmt.Errorf("return code 0x%08X", page.Return)
			}
			return nil, fmt.Errorf("R_DhcpEnumSubnets: %w", err)
		}
		fresh := 0
		if page.EnumInfo != nil {
			for _, address := range page.EnumInfo.Elements {
				if !seen[address] {
					seen[address] = true
					addresses = append(addresses, address)
					fresh++
				}
			}
		}
		if page.Return == dhcpErrorSuccess {
			return addresses, nil
		}
		if fresh == 0 {
			return nil, fmt.Errorf("R_DhcpEnumSubnets answered ERROR_MORE_DATA and sent no scope not already read, so the scope list was not read completely")
		}
		resume = page.Resume
	}
}

// readScope reads every lease in one scope, page by page, on the same rule as
// enumerateSubnets. It returns what it read and whether that is the whole scope;
// a scope that stopped part-way keeps what it read, and says why it stopped.
//
// ERROR_MORE_DATA is the server saying "there is more, ask again". Until
// WO-0930-F it was read as a failure, so a scope larger than one reply --
// 64 KB, the server's own ceiling on a reply -- came back as a scope that
// refused, with nothing from it sent.
func readScope(ctx context.Context, clients dhcpsrv2.Dhcpsrv2Client, server string, address uint32) ([]leaseRecord, bool, string) {
	var records []leaseRecord
	seen := map[uint32]bool{}
	var resume uint32
	for pages := 0; ; pages++ {
		if pages == dhcpPageGuard {
			return records, false, fmt.Sprintf("still answering ERROR_MORE_DATA after %d pages", dhcpPageGuard)
		}
		page, err := clients.EnumSubnetClientsV5(ctx, &dhcpsrv2.EnumSubnetClientsV5Request{
			ServerIPAddress:  server,
			SubnetAddress:    address,
			Resume:           resume,
			PreferredMaximum: 0xFFFFFFFF,
		})
		if page == nil {
			if err == nil {
				err = fmt.Errorf("no response")
			}
			return records, false, err.Error()
		}
		switch page.Return {
		case dhcpErrorNoMoreItems:
			return records, true, ""
		case dhcpErrorSuccess, dhcpErrorMoreData:
		default:
			if err == nil {
				err = fmt.Errorf("return code 0x%08X", page.Return)
			}
			return records, false, err.Error()
		}
		fresh := 0
		if page.ClientInfo != nil {
			for _, client := range page.ClientInfo.Clients {
				if client == nil || seen[client.ClientIPAddress] {
					continue
				}
				seen[client.ClientIPAddress] = true
				record := leaseRecord{IP: client.ClientIPAddress, Mask: client.SubnetMask, HostName: client.ClientName}
				if client.ClientHardwareAddress != nil {
					record.UID = client.ClientHardwareAddress.Data
				}
				records = append(records, record)
				fresh++
			}
		}
		if page.Return == dhcpErrorSuccess {
			return records, true, ""
		}
		if fresh == 0 {
			return records, false, "the server answered ERROR_MORE_DATA and sent no lease not already read"
		}
		resume = page.Resume
	}
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
// could not be read completely is counted as unreadable and named on this box,
// never read as empty and never as a small scope: the door then declines to
// retire anything this reading did not reach.
func readAllLeases(ctx context.Context, servers dhcpsrv.DHCPServerClient, clients dhcpsrv2.Dhcpsrv2Client, server string) ([]leaseRecord, scopeCoverage, error) {
	addresses, err := enumerateSubnets(ctx, servers, server)
	if err != nil {
		return nil, scopeCoverage{}, err
	}

	var leases []leaseRecord
	coverage := scopeCoverage{}
	for _, address := range addresses {
		coverage.Attempted++
		records, complete, reason := readScope(ctx, clients, server, address)
		leases = append(leases, records...)
		switch {
		case !complete:
			coverage.Unreadable++
			coverage.Incomplete = append(coverage.Incomplete, incompleteScope{Address: formatIPv4(address), Read: len(records), Reason: reason})
		case len(records) == 0:
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

	if coverage.Attempted == 0 {
		// Answered, and empty: a server with no scopes -- a failover partner that
		// holds none, a server being decommissioned -- is a real state and not a
		// refusal. The door refuses an empty submission, so nothing is sent.
		fmt.Println("the server answered and serves no scopes. That is an answer, not a refusal; nothing was sent.")
		return nil
	}

	fmt.Printf("scopes: %d attempted, %d could not be read completely, %d empty\n", coverage.Attempted, coverage.Unreadable, coverage.Empty)
	for _, scope := range coverage.Incomplete {
		fmt.Printf("  could not run to the end: scope %s, %d lease(s) read before it stopped: %s\n", scope.Address, scope.Read, scope.Reason)
	}
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
