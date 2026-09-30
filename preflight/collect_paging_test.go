package main

import (
	"context"
	"errors"
	"testing"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dhcpm"
	dhcpsrv "github.com/oiweiwei/go-msrpc/msrpc/dhcpm/dhcpsrv/v1"
	dhcpsrv2 "github.com/oiweiwei/go-msrpc/msrpc/dhcpm/dhcpsrv2/v1"
)

// The DHCP pager against a fake server that answers the way MS-DHCPM
// documents: a page carrying ERROR_MORE_DATA and a resume handle, and a last
// page carrying ERROR_SUCCESS. go-msrpc returns a non-zero code as an error
// and the response beside it, so the fakes do the same. WO-0930-F item 1.

// page is one reply from a fake enumeration.
type page struct {
	code    uint32
	resume  uint32
	clients []uint32
}

// fakeClients answers EnumSubnetClientsV5 from a script of pages per scope,
// keyed by the resume handle the caller sends.
type fakeClients struct {
	dhcpsrv2.Dhcpsrv2Client
	pages map[uint32]map[uint32]page
	calls int
}

func codeError(code uint32) error {
	if code == dhcpErrorSuccess {
		return nil
	}
	return errors.New("EnumSubnetClientsV5: win32 error")
}

func (f *fakeClients) EnumSubnetClientsV5(_ context.Context, in *dhcpsrv2.EnumSubnetClientsV5Request, _ ...dcerpc.CallOption) (*dhcpsrv2.EnumSubnetClientsV5Response, error) {
	f.calls++
	p, ok := f.pages[in.SubnetAddress][in.Resume]
	if !ok {
		return nil, errors.New("transport: the fake has no page for that handle")
	}
	info := &dhcpm.ClientInfoArrayV5{}
	for _, ip := range p.clients {
		info.Clients = append(info.Clients, &dhcpm.ClientInfoV5{ClientIPAddress: ip, ClientHardwareAddress: &dhcpm.ClientUID{Data: []byte{0, 1, 2, 3, 4, byte(ip)}}})
	}
	return &dhcpsrv2.EnumSubnetClientsV5Response{Resume: p.resume, ClientInfo: info, Return: p.code}, codeError(p.code)
}

// fakeServers answers EnumSubnets from a script of pages keyed by handle.
type fakeServers struct {
	dhcpsrv.DHCPServerClient
	pages map[uint32]page
}

func (f *fakeServers) EnumSubnets(_ context.Context, in *dhcpsrv.EnumSubnetsRequest, _ ...dcerpc.CallOption) (*dhcpsrv.EnumSubnetsResponse, error) {
	p, ok := f.pages[in.Resume]
	if !ok {
		return nil, errors.New("transport: the fake has no page for that handle")
	}
	return &dhcpsrv.EnumSubnetsResponse{Resume: p.resume, EnumInfo: &dhcpm.IPArray{Elements: p.clients}, Return: p.code}, codeError(p.code)
}

func ips(from, to uint32) []uint32 {
	var out []uint32
	for ip := from; ip < to; ip++ {
		out = append(out, ip)
	}
	return out
}

const scopeA, scopeB = uint32(0x0A000000), uint32(0x0A010000)

// A scope larger than one reply: three pages, the first two ERROR_MORE_DATA,
// the last ERROR_SUCCESS with the handle reset to zero -- the reset a loop
// keyed on the handle would have followed back to the start.
func largeScope() map[uint32]page {
	return map[uint32]page{
		0:   {code: dhcpErrorMoreData, resume: 100, clients: ips(1, 101)},
		100: {code: dhcpErrorMoreData, resume: 200, clients: ips(101, 201)},
		200: {code: dhcpErrorSuccess, resume: 0, clients: ips(201, 251)},
	}
}

func TestAScopeLargerThanOneReplyIsReadToTheEnd(t *testing.T) {
	clients := &fakeClients{pages: map[uint32]map[uint32]page{scopeA: largeScope()}}
	records, complete, reason := readScope(context.Background(), clients, "dhcp", scopeA)
	if !complete || reason != "" {
		t.Fatalf("a scope the server finished was reported as incomplete: %q", reason)
	}
	if len(records) != 250 {
		t.Fatalf("read %d leases across three pages, want 250", len(records))
	}
	if clients.calls != 3 {
		t.Fatalf("made %d calls; the last page said ERROR_SUCCESS and the reset handle must not be followed", clients.calls)
	}
}

func TestAScopeThatFailsPartWayIsIncompleteAndKeepsWhatItRead(t *testing.T) {
	pages := largeScope()
	pages[100] = page{code: 0x00004E2D} // ERROR_DHCP_JET_ERROR
	clients := &fakeClients{pages: map[uint32]map[uint32]page{scopeA: pages}}
	records, complete, reason := readScope(context.Background(), clients, "dhcp", scopeA)
	if complete {
		t.Fatal("a scope that failed on its second page was reported as read completely")
	}
	if len(records) != 100 || reason == "" {
		t.Fatalf("kept %d leases with reason %q; want the first page's 100 and a reason", len(records), reason)
	}
}

func TestMoreDataWithNothingNewIsIncompleteRatherThanAnEndlessLoop(t *testing.T) {
	clients := &fakeClients{pages: map[uint32]map[uint32]page{scopeA: {
		0:   {code: dhcpErrorMoreData, resume: 100, clients: ips(1, 11)},
		100: {code: dhcpErrorMoreData, resume: 0, clients: ips(1, 11)},
	}}}
	records, complete, reason := readScope(context.Background(), clients, "dhcp", scopeA)
	if complete || len(records) != 10 || reason == "" {
		t.Fatalf("complete=%v records=%d reason=%q; a server that says more and sends nothing new has not finished", complete, len(records), reason)
	}
}

func TestAnEmptyScopeIsEmptyNotRefused(t *testing.T) {
	clients := &fakeClients{pages: map[uint32]map[uint32]page{scopeA: {0: {code: dhcpErrorNoMoreItems}}}}
	records, complete, _ := readScope(context.Background(), clients, "dhcp", scopeA)
	if !complete || len(records) != 0 {
		t.Fatalf("ERROR_NO_MORE_ITEMS on the first page is an empty scope; got complete=%v records=%d", complete, len(records))
	}
}

func TestNoScopesIsAnAnswerNotAFailure(t *testing.T) {
	servers := &fakeServers{pages: map[uint32]page{0: {code: dhcpErrorNoMoreItems}}}
	addresses, err := enumerateSubnets(context.Background(), servers, "dhcp")
	if err != nil || len(addresses) != 0 {
		t.Fatalf("a server serving no scopes answered err=%v, %d scopes; want no error and none", err, len(addresses))
	}
}

func TestTheScopeListPagesToo(t *testing.T) {
	servers := &fakeServers{pages: map[uint32]page{
		0: {code: dhcpErrorMoreData, resume: 2, clients: []uint32{scopeA, scopeB}},
		2: {code: dhcpErrorSuccess, resume: 0, clients: []uint32{0x0A020000}},
	}}
	addresses, err := enumerateSubnets(context.Background(), servers, "dhcp")
	if err != nil || len(addresses) != 3 {
		t.Fatalf("err=%v, %d scopes; want all three across two pages", err, len(addresses))
	}
}

func TestReadAllLeasesCountsAnIncompleteScopeAsUnreadableAndNamesIt(t *testing.T) {
	failing := largeScope()
	failing[200] = page{code: 0x00004E2D}
	servers := &fakeServers{pages: map[uint32]page{0: {code: dhcpErrorSuccess, clients: []uint32{scopeA, scopeB}}}}
	clients := &fakeClients{pages: map[uint32]map[uint32]page{scopeA: largeScope(), scopeB: failing}}
	leases, coverage, err := readAllLeases(context.Background(), servers, clients, "dhcp")
	if err != nil {
		t.Fatal(err)
	}
	if coverage.Attempted != 2 || coverage.Unreadable != 1 || coverage.Empty != 0 {
		t.Fatalf("coverage %+v; want 2 attempted, 1 that could not be read completely, none empty", coverage)
	}
	if len(coverage.Incomplete) != 1 || coverage.Incomplete[0].Address != formatIPv4(scopeB) || coverage.Incomplete[0].Read != 200 {
		t.Fatalf("the incomplete scope was not named with what was read: %+v", coverage.Incomplete)
	}
	if len(leases) != 450 {
		t.Fatalf("%d leases; want 250 from the whole scope and 200 from the one that stopped", len(leases))
	}
}
