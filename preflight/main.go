// Command preflight asks one DHCP server what it holds, over MS-DHCPM.
//
// # THIS HAS NEVER BEEN COMPILED, AND THAT IS STATED HERE RATHER THAN FOUND OUT
//
// It was written on a workstation with no Go toolchain, against go-msrpc's
// documented shape rather than against its source. The module path is the one
// specified; **every symbol below it is unread** — the sub-package, the client
// constructor, the request and response struct names, and the fields the
// results are pulled out of. Any of them may be spelled differently.
//
// That is not a reason to distrust the design, which is two documented MS-DHCPM
// reads over Kerberos, and it is every reason to distrust the identifiers. The
// first person with Go settles it in one command, and the compiler is the
// authority — not this comment and not the person who wrote it.
//
//	cd preflight && go mod tidy && go build .
//
// Expect the names to need correcting on that first build. Correct them against
// the module's own source, and delete this notice in the commit that does,
// because a warning that outlives the thing it warns about is read as noise the
// next time one is genuinely needed.
//
// # Two calls, both reads
//
// R_DhcpEnumSubnets lists the scopes a server serves; R_DhcpEnumSubnetClientsV5
// lists the leases in one scope. They are the pair the collector itself uses,
// so proving them here proves the thing that matters rather than a neighbouring
// call that happens to be easier.
//
// Nothing in this program writes. There is no R_DhcpSetSubnetInfo, no
// R_DhcpDeleteSubnet, no R_DhcpCreateClientInfo, and adding one would change
// what the service account must be trusted with — the account is an ordinary
// domain user plus DHCP Users, which is read-only by design.
//
// # It reports what it found and asserts no expected count
//
// There is no number in here that a site is compared against. A district with
// one scope and a district with sixty are both correct, and a probe that
// decides otherwise produces a confident wrong verdict about a network it has
// never seen. It prints what answered.
//
// # It submits nothing
//
// No portal, no token, no upload. Output goes to stdout.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dhcpm/dhcpsrv/v2"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	// Kerberos, from the ticket cache preflight.sh established. No password is
	// read, prompted for or stored by this program: the credential is the
	// keytab, and kinit has already turned it into a ticket.
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

func main() {
	server := flag.String("server", "", "the DHCP server to ask, by name")
	scopes := flag.Int("scopes", 3, "how many scopes to read leases from, for the probe")
	timeout := flag.Duration("timeout", 30*time.Second, "how long to wait for the server")
	flag.Parse()

	if *server == "" {
		fmt.Fprintln(os.Stderr, "preflight: -server is required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := run(ctx, *server, *scopes); err != nil {
		// The reason, in full. A probe that reports "failed" teaches nobody
		// which of the four things it depends on was the one that broke.
		fmt.Fprintf(os.Stderr, "REFUSED by %s: %v\n", *server, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, server string, scopeLimit int) error {
	// Kerberos only. No NTLM fallback, and that is deliberate: a fallback
	// would let this succeed in a way the collector would not, and a probe
	// that can pass where the real thing fails is worse than no probe.
	ctx = gssapi.NewSecurityContext(ctx)

	conn, err := dcerpc.Dial(ctx, net.JoinHostPort(server, "135"),
		dcerpc.WithSeal(),
		dcerpc.WithMechanism(ssp.SPNEGO),
		dcerpc.WithTargetName("host/"+server),
	)
	if err != nil {
		return fmt.Errorf("dialling the endpoint mapper: %w", err)
	}
	defer conn.Close(ctx)

	client, err := dhcpsrv.NewDhcpsrvClient(ctx, conn)
	if err != nil {
		return fmt.Errorf("binding the DHCP server interface: %w", err)
	}

	fmt.Printf("bound: MS-DHCPM on %s\n", server)

	subnets, err := client.EnumSubnets(ctx, &dhcpsrv.EnumSubnetsRequest{
		PreferredMaximum: 0xFFFFFFFF,
	})
	if err != nil {
		return fmt.Errorf("R_DhcpEnumSubnets: %w", err)
	}

	addresses := subnetAddresses(subnets)
	fmt.Printf("R_DhcpEnumSubnets: %d scope(s)\n", len(addresses))
	for _, address := range addresses {
		fmt.Printf("  %s\n", formatIPv4(address))
	}

	if len(addresses) == 0 {
		// Answered, and empty. A server with no scopes is a real state -- a
		// failover partner that holds none, a server being decommissioned --
		// and it is not the same as a server that refused.
		fmt.Println("the server answered and serves no scopes. That is an answer, not a refusal.")
		return nil
	}

	// A sample rather than the estate. This is a probe: reading every lease on
	// every scope is the collector's job and a large read against somebody's
	// production DHCP server for no extra certainty.
	read := scopeLimit
	if read > len(addresses) {
		read = len(addresses)
	}

	fmt.Printf("reading leases from %d of %d scope(s), as a sample:\n", read, len(addresses))
	for _, address := range addresses[:read] {
		count, err := leaseCount(ctx, client, address)
		if err != nil {
			// Per scope, because one scope refusing is a different fact from
			// the server refusing, and the difference is what somebody acts on.
			fmt.Printf("  %-18s could not be read: %v\n", formatIPv4(address), err)
			continue
		}
		fmt.Printf("  %-18s %d lease(s)\n", formatIPv4(address), count)
	}

	fmt.Println("what is correct for this site is not something preflight can know.")
	return nil
}

func leaseCount(ctx context.Context, client dhcpsrv.DhcpsrvClient, subnet uint32) (int, error) {
	response, err := client.EnumSubnetClientsV5(ctx, &dhcpsrv.EnumSubnetClientsV5Request{
		SubnetAddress:    subnet,
		PreferredMaximum: 0xFFFFFFFF,
	})
	if err != nil {
		return 0, fmt.Errorf("R_DhcpEnumSubnetClientsV5: %w", err)
	}

	if response == nil || response.ClientInfo == nil {
		return 0, nil
	}

	return len(response.ClientInfo.Clients), nil
}

// subnetAddresses pulls the scope addresses out of whatever shape the
// enumeration came back in, and tolerates an empty one.
func subnetAddresses(response *dhcpsrv.EnumSubnetsResponse) []uint32 {
	if response == nil || response.EnumInfo == nil {
		return nil
	}
	return response.EnumInfo.Elements
}

// formatIPv4 renders a scope address the way a person reads it. MS-DHCPM
// carries addresses as host-order 32-bit integers, which is the detail that
// makes a scope list look like nonsense if it is printed raw.
func formatIPv4(address uint32) string {
	return net.IPv4(
		byte(address>>24),
		byte(address>>16),
		byte(address>>8),
		byte(address),
	).String()
}
