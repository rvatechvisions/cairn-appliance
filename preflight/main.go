// Command preflight asks one DHCP server what it holds, over MS-DHCPM.
//
// # It compiles, and it has reached a domain controller
//
// First built on 20 September 2026, on the appliance, against go-msrpc v1.6.4.
// It dialled RVA Tech Visions' own domain controller and got a protocol-level
// answer. **What it has not yet done is complete a bind and read a lease**, and
// that distinction is the whole of what this notice is now for.
//
// The warning this replaces said every identifier below the module path was
// unread, and it was right: the sub-package, the version suffix and the client
// constructor were all wrong, and the wrongness was invisible until a compiler
// saw it. They were corrected against the module's own source in the cache on
// the appliance rather than against anybody's recollection.
//
//	cd preflight && go mod tidy && go build .
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
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	// MS-DHCPM is TWO RPC interfaces, and the calls this probe makes are split
	// across them: R_DhcpEnumSubnets is on DHCPSRV, R_DhcpEnumSubnetClientsV5
	// is on DHCPSRV2. So two imports and two clients over one connection.
	//
	// **The version suffix belongs to go-msrpc's layout, not to the
	// interface.** Both packages live under a `v1` directory -- `dhcpsrv/v1`
	// and `dhcpsrv2/v1` -- and the `2` in dhcpsrv2 is part of the interface's
	// name rather than a version of the first one.
	//
	// The original import here was `dhcpm/dhcpsrv/v2`, written from memory and
	// wrong in both halves: it asked for a major version 2 of the DHCPSRV
	// package, which does not exist, while the interface it meant is a
	// sibling. Go reported the module as found and the package as absent,
	// which is exactly what a path nobody has compiled looks like. Read from
	// the module in the appliance's own cache, 20 September 2026.
	dhcpsrv "github.com/oiweiwei/go-msrpc/msrpc/dhcpm/dhcpsrv/v1"
	dhcpsrv2 "github.com/oiweiwei/go-msrpc/msrpc/dhcpm/dhcpsrv2/v1"

	// The endpoint mapper, which is how a dynamic service is found at all.
	//
	// The DHCP server does not listen on a fixed port. It registers with the
	// mapper on 135 and is assigned whatever was free, so a client asks the
	// mapper where the interface lives and is then told. Dialling 135 and
	// offering it MS-DHCPM asks the MAPPER to speak a protocol only the DHCP
	// service speaks, which it answers with "abstract syntax not supported" --
	// a sentence about presentation contexts that is really about having
	// knocked on the wrong door. Seen on the appliance, 20 September 2026.
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"

	// Kerberos, from the ticket cache preflight.sh established. No password is
	// read, prompted for or stored by this program: kinit has already turned
	// the credential into a ticket and this only presents it.
	"github.com/oiweiwei/go-msrpc/ssp/credential"

	// The gokrb5 fork go-msrpc itself uses, and it has to be THIS one.
	//
	// `credential.NewFromCCache` takes its cache as `any` and type-switches on
	// it, so the wrong fork's *credentials.CCache is a perfectly good Go value
	// that matches neither case. It does not fail to compile and it does not
	// panic: it returns a credential carrying "invalid type ... for ccache",
	// which surfaces much later as an unhelpful security-provider error.
	// Read from go-msrpc's own imports rather than inferred.
	"github.com/oiweiwei/gokrb5.fork/v9/credentials"

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

		// Name the grant when the server names the grant.
		//
		// ERROR_ACCESS_DENIED here is the DHCP service ANSWERING, after the
		// mapper resolved, the interface bound and Kerberos authenticated. It
		// is a decision about what this account may read, and the whole of the
		// answer is one group -- so saying so beats leaving a Win32 code to be
		// looked up. It arrives at the end of a long run where every earlier
		// layer looks fine, which is exactly when a bare code reads as
		// something being broken.
		if strings.Contains(err.Error(), "ERROR_ACCESS_DENIED") {
			account := accountName(os.Getenv("CAIRN_PRINCIPAL"))
			fmt.Fprintf(os.Stderr, "\n"+
				"  THE SERVER ANSWERED. Everything below this is working: the endpoint\n"+
				"  mapper resolved, the interface bound, Kerberos authenticated, and the\n"+
				"  call was dispatched. What it refused is the READ.\n"+
				"\n"+
				"  FIRST, whether the account holds the grant at all:\n"+
				"\n"+
				"    Get-ADPrincipalGroupMembership %s | Select-Object Name\n"+
				"\n"+
				"  DHCP Users is read-only on the DHCP service and is the whole grant\n"+
				"  this appliance asks for. If it is absent:\n"+
				"\n"+
				"    Add-ADGroupMember -Identity \"DHCP Users\" -Members %s\n"+
				"\n"+
				"  Membership travels in the Kerberos ticket and preflight takes a fresh\n"+
				"  one each run, so adding it is enough -- there is nothing to restart\n"+
				"  here and nothing to sign out of.\n"+
				"\n"+
				"  IF IT IS ALREADY THERE, this is not the answer and the refusal is\n"+
				"  something else. Seen on RVA's own domain, 20 September 2026, with the\n"+
				"  membership present. What separates the possibilities is asking the\n"+
				"  same question from Windows as the same account:\n"+
				"\n"+
				"    Get-DhcpServerv4Scope -ComputerName <the DHCP server>\n"+
				"\n"+
				"  Refused there too, and the grant is genuinely not sufficient on this\n"+
				"  server, which is a question for whoever administers it. Answered\n"+
				"  there, and the account can read DHCP while THIS probe cannot, which\n"+
				"  makes it ours.\n",
				account, account)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, server string, scopeLimit int) error {
	// The ticket preflight.sh already holds, handed to the RPC layer.
	//
	// `gssapi.NewSecurityContext` alone establishes a context with no
	// credential in it, which is what produced "init security context:
	// security provider: operation unavailable" on the first run that got this
	// far: the bind had nothing to present. The ticket was valid the whole
	// time and sitting in the cache this reads.
	//
	// Both values come from the environment preflight.sh already set, rather
	// than from flags of this program. Configuring the realm, the principal
	// and the cache in two places is how the two copies come to disagree, and
	// the one that is wrong is whichever is read less.
	ccname := os.Getenv("KRB5CCNAME")
	if ccname == "" {
		return fmt.Errorf("KRB5CCNAME is unset: this runs from preflight.sh, which sets it")
	}
	// MIT writes it as a type-qualified name. Only FILE: is handled, because
	// it is the only one preflight.sh creates -- and a MEMORY: cache could not
	// be read by this process anyway, which is the lesson that put the ticket
	// on tmpfs in the first place.
	ccpath := strings.TrimPrefix(ccname, "FILE:")
	if ccpath == ccname && strings.Contains(ccname, ":") {
		return fmt.Errorf("KRB5CCNAME is %q, and only a FILE: cache can be read here", ccname)
	}

	principal := os.Getenv("CAIRN_PRINCIPAL")
	if principal == "" {
		return fmt.Errorf("CAIRN_PRINCIPAL is unset: this runs from preflight.sh, which sets it")
	}

	cache, err := credentials.LoadCCache(ccpath)
	if err != nil {
		return fmt.Errorf("reading the ticket cache at %s: %w", ccpath, err)
	}

	// Kerberos only. No NTLM fallback, and that is deliberate: a fallback
	// would let this succeed in a way the collector would not, and a probe
	// that can pass where the real thing fails is worse than no probe.
	//
	// Naming KRB5 rather than SPNEGO makes that structural instead of hoped
	// for -- there is no negotiation to fall back through.
	gssapi.AddMechanism(ssp.KRB5)
	gssapi.AddCredential(credential.NewFromCCache(principal, cache))

	ctx = gssapi.NewSecurityContext(ctx)

	// The server by NAME, with no port, and the mapper as a dial option.
	//
	// The first version dialled host:135 and put the security options here.
	// Both were wrong, and in a way that produced a bind which succeeded --
	// against the endpoint mapper, which is not the service being asked for.
	// The options below belong on the CLIENTS rather than on the connection:
	// the connection is how you reach the mapper, and each client then says
	// which interface it wants and over what transport.
	conn, err := dcerpc.Dial(ctx, server, epm.EndpointMapper(ctx, server))
	if err != nil {
		return fmt.Errorf("dialling %s through the endpoint mapper: %w", server, err)
	}
	defer conn.Close(ctx)

	// Two clients, one connection. Bound separately and reported separately,
	// because a server can answer one interface and refuse the other -- and
	// collapsing that into "MS-DHCPM refused" would name the wrong thing.
	//
	// WithSeal encrypts the exchange. `host/<server>` is the target principal,
	// which kvno confirmed exists on this domain rather than being assumed:
	// the DHCP service runs as the machine account, so its ticket is the
	// host one rather than a dhcp-specific principal.
	options := []dcerpc.Option{
		dcerpc.WithSeal(),
		dcerpc.WithMechanism(ssp.KRB5),
		dcerpc.WithEndpoint("ncacn_ip_tcp:"),
		dcerpc.WithTargetName("host/" + server),
	}

	servers, err := dhcpsrv.NewDHCPServerClient(ctx, conn, options...)
	if err != nil {
		return fmt.Errorf("binding DHCPSRV: %w", err)
	}

	clients, err := dhcpsrv2.NewDhcpsrv2Client(ctx, conn, options...)
	if err != nil {
		return fmt.Errorf("binding DHCPSRV2: %w", err)
	}

	fmt.Printf("bound: MS-DHCPM on %s (DHCPSRV and DHCPSRV2)\n", server)

	subnets, err := servers.EnumSubnets(ctx, &dhcpsrv.EnumSubnetsRequest{
		PreferredMaximum: 0xFFFFFFFF,
	})
	if err != nil {
		return fmt.Errorf("R_DhcpEnumSubnets: %w", err)
	}

	// Read inline rather than through a helper, so no response type has to be
	// named in a signature. The field names below are still unverified against
	// the module -- the compiler is the authority for those and has not run
	// yet -- and naming a type as well would be a second guess resting on the
	// first.
	var addresses []uint32
	if subnets != nil && subnets.EnumInfo != nil {
		addresses = subnets.EnumInfo.Elements
	}
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
		leases, err := clients.EnumSubnetClientsV5(ctx, &dhcpsrv2.EnumSubnetClientsV5Request{
			SubnetAddress:    address,
			PreferredMaximum: 0xFFFFFFFF,
		})
		if err != nil {
			// Per scope, because one scope refusing is a different fact from
			// the server refusing, and the difference is what somebody acts on.
			fmt.Printf("  %-18s could not be read: %v\n", formatIPv4(address), err)
			continue
		}

		count := 0
		if leases != nil && leases.ClientInfo != nil {
			count = len(leases.ClientInfo.Clients)
		}
		fmt.Printf("  %-18s %d lease(s)\n", formatIPv4(address), count)
	}

	fmt.Println("what is correct for this site is not something preflight can know.")
	return nil
}

// accountName strips the realm from a principal, because Add-ADGroupMember
// wants the account and not the Kerberos name. A command printed for somebody
// to paste has to be the command, not a shape they finish themselves.
func accountName(principal string) string {
	if principal == "" {
		return "svc-cairn"
	}
	if at := strings.IndexByte(principal, '@'); at > 0 {
		return principal[:at]
	}
	return principal
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
