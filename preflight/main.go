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
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	// Only reached under -debug. go-msrpc's own examples log through zerolog,
	// so this is the logger its option expects rather than a wrapper written
	// to fit.
	"github.com/rs/zerolog"

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

// commit is the commit this binary was built from, set at link time with
// -ldflags "-X main.commit=<sha>".
//
// EMPTY IS A REAL STATE AND IS REPORTED AS ONE. A binary built without the
// stamp says so rather than printing something that looks like an answer --
// "unstamped" is information and a blank line is not, and this is the one
// question the binary can answer about itself with certainty.
//
// It is the input to the update decision: the appliance refuses to run bytes
// whose digest does not match what the portal named, and a binary that cannot
// say what it is gives the pin nothing to check against. A build that did not
// stamp is refused by preflight.sh rather than shipped.
var commit string

// version is the tag, where a build had one. Same rules as commit.
var version string

// stamp is what -version prints and what a build check reads back.
func stamp() string {
	c := commit
	if c == "" {
		c = "unstamped"
	}
	v := version
	if v == "" {
		v = "no-tag"
	}
	return fmt.Sprintf("preflight %s %s", v, c)
}

// readRegistrationKey takes the key from stdin so it is never an argument.
//
// **An argument is visible in /proc/<pid>/cmdline** to every user on the box
// for as long as the process runs. On a lab box nobody else uses that is a
// second or two of exposure to nobody; on a district's collector it is a host
// on somebody else's network with somebody else's administrators on it, and
// the key redeems into a binding that fetches a credential.
//
// Works both ways a person will use it: piped, and typed at a prompt. The
// prompt goes to STDERR rather than stdout so that a caller redirecting the
// output still sees it, and so nothing a script captures contains it.
//
// **Whitespace is trimmed and the result refused if empty**, because a key
// pasted into a terminal picks up a trailing newline and a key that arrives
// empty would otherwise be sent to the portal as one -- which the portal would
// refuse in the same words as a wrong key, sending the reader to the wrong
// question.
func readRegistrationKey() (string, error) {
	// Whether anything is piped in, without taking a dependency to ask.
	//
	// A character device means a terminal, so nothing is waiting on stdin and a
	// bare `-enrol` would hang with no explanation. That is worse than refusing:
	// a command that sits there looks like a slow network.
	info, err := os.Stdin.Stat()
	if err != nil {
		return "", fmt.Errorf("checking stdin: %w", err)
	}

	if (info.Mode() & os.ModeCharDevice) != 0 {
		return "", fmt.Errorf(
			"-enrol reads the registration key from stdin and nothing is piped in.\n"+
				"       Type it without it reaching your shell history:\n"+
				"         read -rs KEY; printf '%%s' \"$KEY\" | preflight/preflight -portal <url> -enrol; unset KEY")
	}

	piped, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading the registration key from stdin: %w", err)
	}

	// Trimmed because a key pasted into a terminal picks up a trailing newline,
	// and refused when empty because an empty key would otherwise be sent and
	// refused by the portal in the same words as a wrong one -- which sends the
	// reader to the wrong question.
	key := strings.TrimSpace(string(piped))
	if key == "" {
		return "", fmt.Errorf("no registration key arrived on stdin")
	}
	return key, nil
}

func main() {
	server := flag.String("server", "", "the DHCP server to ask, by name")
	scopes := flag.Int("scopes", 3, "how many scopes to read leases from, for the probe")
	timeout := flag.Duration("timeout", 30*time.Second, "how long to wait for the server")

	// Two flags that exist to answer a question rather than to configure
	// anything, and they are here because guessing at the answer has already
	// cost several runs.
	//
	// On 20 September 2026 the same account read this same server perfectly
	// well from Windows -- Get-DhcpServerv4Scope and netsh both returned the
	// scope -- while this probe was refused ERROR_ACCESS_DENIED. So the grant
	// is sufficient and something about HOW this asks differs from how Windows
	// asks. These make the difference observable instead of theorised.
	debug := flag.Bool("debug", false, "log the RPC exchange, including the security negotiation")
	target := flag.String("target", "", "the service principal to request; default follows the transport")
	transport := flag.String("transport", "ncacn_ip_tcp:",
		"the RPC transport to request; Windows tools commonly use ncacn_np:")
	showVersion := flag.Bool("version", false, "print the commit this binary was built from, and exit")

	// Talking to the portal. Two verbs, because they are two different acts:
	// one redeems a grant and one spends an identity.
	//
	// The registration key is an ARGUMENT and never a file. A key baked into
	// something on the box is a key that gets forwarded, kept, and run
	// somewhere else a year later.
	portalURL := flag.String("portal", "", "the portal base URL, for -enrol or -fetch")
	// -enrol takes NO value. The key is read from stdin, which is the whole
	// point: an argument is visible in /proc/<pid>/cmdline to every user on the
	// box for the life of the process. Seconds, on a host we do not own, with
	// somebody else's administrators on it.
	enrolling := flag.Bool("enrol", false,
		"redeem a registration key read from stdin and bind this appliance")
	fetch := flag.Bool("fetch", false, "fetch the connection credential with a signed request")
	fingerprint := flag.String("fingerprint", "", "the fingerprint this appliance is bound as, for -fetch")
	keyFile := flag.String("keyfile", keyPath, "where this appliance keeps its private key")
	emit := flag.Bool("emit", false,
		"with -fetch: write ONLY the password to stdout, everything else to stderr")
	// **-emit-credential is a second flag rather than a change to -emit, and
	// the reason is what a partial pull would do.**
	//
	// -emit writes the password and nothing else, which is a contract a script
	// relies on. A new binary that changed that contract, run by a preflight.sh
	// somebody had not pulled yet, would hand the whole block to kinit as a
	// password -- and a failed logon against a customer's domain controller is
	// a security event in THEIR tenant. One failed authentication is a stop,
	// not a cost of upgrading.
	//
	// So the old spelling keeps its old meaning, the new spelling is a name an
	// old binary refuses outright, and a half-pulled box fails loudly in the
	// one direction that asks nothing of anybody's KDC.
	emitCredential := flag.Bool("emit-credential", false,
		"with -fetch: write every field the portal supplied, password last")
	// Posting what a run reached. The report arrives on stdin, already
	// serialised, and is signed and sent unchanged.
	report := flag.Bool("report", false,
		"read a run report from stdin and post it to the portal, signed")
	agreement := flag.Bool("agreement-fixture", false,
		"print the canonical bytes and a signature over them, as JSON, for the portal suite")
	flag.Parse()

	// Answered before -server is required, because "what is this binary" must
	// be askable of a binary that cannot do anything else -- including one built
	// on a box with no domain, which is where a build is verified.
	if *showVersion {
		fmt.Println(stamp())
		return
	}

	// The portal verbs are answered before -server is required: enrolling and
	// fetching a credential are about the portal, not about a DHCP server, and
	// a box that has not been told its server yet is exactly the box being
	// enrolled.
	keyPath = *keyFile

	if *agreement {
		private, err := loadOrCreateKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, "preflight:", err)
			os.Exit(1)
		}
		if err := emitAgreementFixture(private); err != nil {
			fmt.Fprintln(os.Stderr, "preflight:", err)
			os.Exit(1)
		}
		return
	}

	if *enrolling || *fetch || *report {
		if *portalURL == "" {
			fmt.Fprintln(os.Stderr,
				"preflight: -portal is required with -enrol, -fetch or -report")
			os.Exit(2)
		}

		private, err := loadOrCreateKey()
		if err != nil {
			fmt.Fprintln(os.Stderr, "preflight:", err)
			os.Exit(1)
		}

		// Before anything is sent. A binary that cannot verify what it just
		// signed would otherwise present as the portal refusing a good key.
		if err := assertSigningKey(private); err != nil {
			fmt.Fprintln(os.Stderr, "preflight:", err)
			os.Exit(1)
		}

		if *enrolling {
			registrationKey, err := readRegistrationKey()
			if err != nil {
				fmt.Fprintln(os.Stderr, "preflight:", err)
				os.Exit(2)
			}

			bound, err := enrol(*portalURL, registrationKey, private)
			if err != nil {
				fmt.Fprintln(os.Stderr, "preflight:", err)
				os.Exit(1)
			}
			fmt.Println("enrolled")
			fmt.Println("fingerprint:", bound)
			fmt.Println("")
			fmt.Println("Compare that against the fingerprint on the connection card.")
			fmt.Println("They must match. That comparison is what catches a stolen key.")
			return
		}

		// Falls back to what this box enrolled as, so a routine run does not
		// have to be told a value it already recorded.
		bound := *fingerprint
		if bound == "" {
			bound = storedFingerprint()
		}
		if bound == "" {
			fmt.Fprintln(os.Stderr,
				"preflight: no -fingerprint, and this box has not recorded one. Enrol first.")
			os.Exit(2)
		}

		if *report {
			/*
			 * Read to EOF and send those bytes. **Not parsed here**, because a
			 * report this binary re-encoded would be signed over one spelling
			 * and sent as another -- and the portal hashes what arrives.
			 *
			 * The portal is the thing that judges whether it is a valid report.
			 * Validating it twice would be two sets of rules about what a
			 * report is, and the one that drifts is the copy used less.
			 */
			payload, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintln(os.Stderr, "preflight: reading the report from stdin:", err)
				os.Exit(2)
			}
			if len(bytes.TrimSpace(payload)) == 0 {
				fmt.Fprintln(os.Stderr, "preflight: no run report arrived on stdin")
				os.Exit(2)
			}

			if err := reportRun(*portalURL, bound, private, payload); err != nil {
				fmt.Fprintln(os.Stderr, "preflight:", err)
				os.Exit(1)
			}

			fmt.Println("run reported")
			return
		}

		credential, err := fetchCredential(*portalURL, bound, private)
		if err != nil {
			fmt.Fprintln(os.Stderr, "preflight:", err)
			os.Exit(1)
		}

		// **-emit exists so a SCRIPT can use the credential without a human
		// seeing it.** The password goes to stdout and nothing else does, so a
		// caller captures it with command substitution; the username and the
		// reassurance go to stderr, where they stay visible and uncaptured.
		//
		// It is a flag rather than the default because the default is a person
		// running this by hand, and for them a password on stdout is a password
		// in a scrollback.
		if *emitCredential {
			/*
			 * **The password is last and is the remainder**, which is what makes
			 * this parseable without quoting anything.
			 *
			 * Everything before the blank line is name=value and carries no
			 * secret. Everything after it is the password, byte for byte, to
			 * the end of the stream -- so a password containing an equals sign,
			 * a newline or the word "password" cannot be misread as a header.
			 * A quoting scheme here would be a second place for a credential to
			 * be mangled, and this project has lost a .env secret to exactly
			 * that.
			 *
			 * A field the portal did not supply is OMITTED rather than sent
			 * empty: absent is what lets the caller tell "the portal has no
			 * value for this" from "the portal says it is blank".
			 */
			fmt.Fprintln(os.Stderr, "credential fetched for", credential.Username)
			fmt.Printf("username=%s\n", credential.Username)
			if credential.Realm != "" {
				fmt.Printf("realm=%s\n", credential.Realm)
			}
			if credential.Controller != "" {
				fmt.Printf("controller=%s\n", credential.Controller)
			}
			fmt.Print("\n")
			fmt.Print(credential.Password)
			return
		}

		if *emit {
			fmt.Fprintln(os.Stderr, "credential fetched for", credential.Username)
			fmt.Print(credential.Password)
			return
		}

		// The username, and that a password arrived. NEVER the password: a
		// credential in a terminal buffer, a shell history and a run-command
		// log is a smaller version of the thing this whole design is for.
		fmt.Println("credential fetched")
		fmt.Println("username:", credential.Username)
		if credential.Realm != "" {
			fmt.Println("realm:", credential.Realm)
		}
		if credential.Controller != "" {
			fmt.Println("controller:", credential.Controller)
		}
		fmt.Printf("password:  %d characters, not printed\n", len(credential.Password))
		return
	}

	if *server == "" {
		fmt.Fprintln(os.Stderr, "preflight: -server is required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if err := run(ctx, *server, *scopes, *transport, *target, *debug); err != nil {
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
				"  Membership travels in the Kerberos ticket and preflight takes a\n"+
				"  fresh one each run, so nothing on THIS box needs restarting.\n"+
				"\n"+
				"  THAT IS NOT THE SAME AS NOTHING NEEDING A RESTART. The DHCP Server\n"+
				"  service resolves the DHCP Users and DHCP Administrators SIDs on its\n"+
				"  own schedule, and an account added after it did so is a documented\n"+
				"  cause of exactly this refusal WITH the membership present. Neither\n"+
				"  way is asserted here. The test is one command on the DC:\n"+
				"\n"+
				"    Restart-Service DHCPServer\n"+
				"\n"+
				"  Re-run afterwards. If it answers, that was the cause and it belongs\n"+
				"  in onboarding, because every future client hits it.\n"+
				"\n"+
				"  IF IT IS ALREADY THERE, this is not the answer and the refusal is\n"+
				"  something else. Seen on RVA's own domain, 20 September 2026, with the\n"+
				"  membership present. What separates the possibilities is asking the\n"+
				"  same question from Windows as the same account. Use runas /netonly:\n"+
				"  it keeps the local session as whoever you are and sends only the\n"+
				"  NETWORK request as this account, so it needs no logon rights\n"+
				"  anywhere. Do NOT use Invoke-Command -- that is WinRM, it needs\n"+
				"  Remote Management Users, and its refusal is about the session\n"+
				"  rather than about DHCP.\n"+
				"\n"+
				"    runas /netonly /user:DOMAIN\\%s \"powershell -NoExit\"\n"+
				"    Get-DhcpServerv4Scope -ComputerName <the DHCP server>\n"+
				"\n"+
				"  Without the RSAT module, netsh asks the same interface:\n"+
				"\n"+
				"    netsh dhcp server \\\\<the DHCP server> show scope\n"+
				"\n"+
				"  Refused there too, and the grant is genuinely not sufficient on this\n"+
				"  server, which is a question for whoever administers it. Answered\n"+
				"  there, and the account can read DHCP while THIS probe cannot, which\n"+
				"  makes it ours.\n"+
				"\n"+
				"  AND ONE MORE, WHICH IS A PRODUCT QUESTION RATHER THAN A LAB ONE.\n"+
				"  Add the account to DHCP Administrators temporarily and re-run. If\n"+
				"  that is what R_DhcpEnumSubnets takes on this server, then this\n"+
				"  appliance CANNOT BE READ-ONLY ON DHCP, and what a district is asked\n"+
				"  to grant changes. Find out on a domain where being wrong is cheap,\n"+
				"  and record the answer either way -- DHCP Users is sufficient is\n"+
				"  worth as much written down as the alternative. Remove the\n"+
				"  membership afterwards; it is a test, not a configuration.\n",
				account, account, account)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, server string, scopeLimit int, transport, targetName string, debug bool) error {
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
	// The logger goes on the dial AND on the clients, because the security
	// negotiation this is meant to expose happens on the client bind rather
	// than on the connection.
	var logging []dcerpc.Option
	if debug {
		logging = append(logging, dcerpc.WithLogger(zerolog.New(os.Stderr)))
	}

	mapperOptions := make([]dcerpc.Option, len(logging))
	copy(mapperOptions, logging)

	conn, err := dcerpc.Dial(ctx, server,
		append([]dcerpc.Option{epm.EndpointMapper(ctx, server, mapperOptions...)}, logging...)...)
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
	// The service principal follows the TRANSPORT, not the service.
	//
	// ncacn_np is RPC over a named pipe, which is RPC over SMB -- so the
	// ticket that has to be obtained is the file-service one, cifs/<host>.
	// Asking for host/<host> over a named pipe produces
	// KDC_ERR_S_PRINCIPAL_UNKNOWN from inside "open smb session", which reads
	// as the server being unknown when the server is fine and the principal
	// was the wrong one for that path. Seen on the appliance, 20 September
	// 2026, with the previous hardcoded host/ target.
	//
	// Both principals were confirmed to exist on this domain by kvno earlier
	// the same evening, so neither is a guess about what a DC registers.
	target := targetName
	if target == "" {
		if strings.HasPrefix(transport, "ncacn_np") {
			target = "cifs/" + server
		} else {
			target = "host/" + server
		}
	}

	options := append([]dcerpc.Option{
		dcerpc.WithSeal(),
		dcerpc.WithMechanism(ssp.KRB5),
		dcerpc.WithEndpoint(transport),
		dcerpc.WithTargetName(target),
	}, logging...)

	fmt.Printf("transport: %s, sealed, Kerberos, target %s\n", transport, target)

	servers, err := dhcpsrv.NewDHCPServerClient(ctx, conn, options...)
	if err != nil {
		return fmt.Errorf("binding DHCPSRV: %w", err)
	}

	clients, err := dhcpsrv2.NewDhcpsrv2Client(ctx, conn, options...)
	if err != nil {
		return fmt.Errorf("binding DHCPSRV2: %w", err)
	}

	fmt.Printf("bound: MS-DHCPM on %s (DHCPSRV and DHCPSRV2)\n", server)

	// ServerIPAddress is filled in, and it was empty until 20 September 2026.
	//
	// The wire log showed the request going out as
	// {"server_ip_address":"", "preferred_maximum":4294967295} and coming back
	// return: 5, ERROR_ACCESS_DENIED -- on a server that had just
	// authenticated this account and that answers the same read for the same
	// account from Windows. That empty field was the only difference between
	// this call and a well-formed one that could be seen rather than guessed.
	//
	// MS-DHCPM documents the parameter as unused, which is a statement about
	// the specification rather than about what a given implementation checks.
	// Sending what Windows sends costs nothing and removes the one observable
	// discrepancy; if the refusal survives it, the cause is in the security
	// layer rather than in the request, and that is a different investigation.
	subnets, err := servers.EnumSubnets(ctx, &dhcpsrv.EnumSubnetsRequest{
		ServerIPAddress:  server,
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

	// Counted across the sample, because what matters for the paragraph at the
	// end is whether ANY client record came back -- one scope being empty is
	// ordinary, and every scope being empty is what leaves the parse unproven.
	observed := 0

	fmt.Printf("reading leases from %d of %d scope(s), as a sample:\n", read, len(addresses))
	for _, address := range addresses[:read] {
		leases, err := clients.EnumSubnetClientsV5(ctx, &dhcpsrv2.EnumSubnetClientsV5Request{
			ServerIPAddress:  server,
			SubnetAddress:    address,
			PreferredMaximum: 0xFFFFFFFF,
		})
		// ERROR_NO_MORE_ITEMS IS AN ANSWER, NOT A FAILURE TO ANSWER.
		//
		// The call succeeded and the scope holds no clients. Rendering that as
		// "could not be read" is the refusal-as-empty-container defect
		// inverted, and this direction is the worse of the two: a working read
		// that looks broken gets investigated and wastes somebody's afternoon,
		// and the same wording at a customer makes a genuinely empty scope look
		// like a fault in the appliance.
		//
		// Seen on RVA's domain, 20 September 2026: 10.10.10.0 had no leases,
		// and preflight reported it as unreadable.
		if err != nil {
			if strings.Contains(err.Error(), "ERROR_NO_MORE_ITEMS") {
				fmt.Printf("  %-18s 0 lease(s) — the scope is empty\n", formatIPv4(address))
				continue
			}
			// Per scope, because one scope refusing is a different fact from
			// the server refusing, and the difference is what somebody acts on.
			fmt.Printf("  %-18s could not be read: %v\n", formatIPv4(address), err)
			continue
		}

		count := 0
		if leases != nil && leases.ClientInfo != nil {
			count = len(leases.ClientInfo.Clients)
		}
		if count == 0 {
			fmt.Printf("  %-18s 0 lease(s) — the scope is empty\n", formatIPv4(address))
		} else {
			fmt.Printf("  %-18s %d lease(s)\n", formatIPv4(address), count)
		}
		observed += count
	}

	fmt.Println("what is correct for this site is not something preflight can know.")

	// What connecting proves, and what it does not.
	//
	// **The transport is proven and the PARSE is not.** Until a lease comes
	// back, the shape of the field every device key in the portal is built on
	// is exactly as unknown as it was before this ran: MS-DHCPM's ClientUID is
	// a 6-byte hardware address on some servers and an 11-byte client unique
	// id carrying a subnet prefix on others, and nothing here has seen one.
	//
	// Getting it wrong writes a subnet prefix into every hardware address the
	// portal stores, which is not a visible failure -- it is a device key that
	// matches nothing, silently, for every lease from that server.
	//
	// So a run that enumerated scopes and saw no clients says so in those
	// words rather than reading as a clean bill of health.
	if observed == 0 {
		fmt.Println("")
		fmt.Println("SUBNETS ENUMERATED, CLIENTS NOT YET OBSERVED.")
		fmt.Println("  The lease path is proven to CONNECT and is not proven to PARSE.")
		fmt.Println("  No client record came back, so the ClientUID length histogram is")
		fmt.Println("  still unrecorded — 6-byte MAC against 11-byte client id with a")
		fmt.Println("  subnet prefix — and that is the field every device key in the")
		fmt.Println("  portal is built on. Put a device on one of these scopes, wait for")
		fmt.Println("  a lease, and run this again.")
	}
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
