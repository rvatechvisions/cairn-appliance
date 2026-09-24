# Cairn collection appliance

A Linux host inside a customer's network that reads Active Directory, the DNS
zones held in it, and DHCP — and submits what it reads to Cairn.

**`preflight.sh` answers what a host can reach. It collects nothing** —
no device, no lease, no address — and an enrolled box reports which
capabilities answered, to the portal, at the end of a run. The collector
is a separate thing and is not here.

---

## What has been proven, against a real domain

**20 September 2026, RVA Tech Visions' own production domain**, from a Debian 13
host that is **not joined to it**, with an ordinary domain user whose only extra
membership is `DHCP Users`. **All six capabilities answered.**

| | |
| --- | --- |
| Nothing durable on the box | **Proven** — no keytab, no stored password |
| Appliance key | **Proven** — generated locally, 600 root:root, never transmitted |
| Kerberos | **Proven** — ticket issued and read back from a tmpfs cache |
| Active Directory over LDAP | **Proven** — bound read, SASL SSF 256 |
| DNS zones in the directory | **Proven** — 2 zones readable |
| Authorised DHCP servers | **Proven** — `CN=NetServices` read, 2 entries |
| DHCP over MS-DHCPM | **Proven** — both interfaces bound, `R_DhcpEnumSubnets` answered, one scope enumerated |

### `DHCP Users` is sufficient, and that is now evidence rather than belief

**The finding, with what established it.** It mattered because the appliance's
whole read-only position on DHCP rested on it and nothing had ever tested it:

| | |
| --- | --- |
| `svc-cairn` in `DHCP Users`, nothing else | preflight refused, `ERROR_ACCESS_DENIED` |
| `Restart-Service DHCPServer`, **nothing else changed** | preflight answered, one scope enumerated |

**The DHCP Server service resolves the `DHCP Users` and `DHCP Administrators`
SIDs on its own schedule**, so an account added afterwards is refused while its
membership sits plainly in the directory.

**`DHCP Administrators` is not required and should not be granted.** It is
named here because that refusal invites somebody to add a wider role *to be
safe*, and that one is write-capable — granting it would end this appliance's
read-only position on DHCP for nothing.

**Every client will hit this, so it is onboarding rather than troubleshooting.**
`LAB-BUILD.md` carries the wording, framed to cost the client least: the
membership takes effect at the next DHCP service restart, **a normal patch
window is enough**, and an immediate restart is only needed if you want it
working today. That matters where the DHCP server is a production domain
controller — at Floyd it holds 3,405 leases, and a restart there gets announced
rather than done quietly mid-install.

### Proven to connect. Not proven to parse.

**The distinction the result depends on.** `R_DhcpEnumSubnets` answered and the
scope was empty, so **no client record has ever come back** — and the shape of
`ClientUID` is exactly as unknown as it was before any of this ran.

MS-DHCPM returns it as a 6-byte hardware address on some servers and an
**11-byte client unique id carrying a subnet prefix** on others. **That is the
field every device key in the portal is built on.** Getting it wrong writes a
subnet prefix into every hardware address stored from that server — not a
visible failure, but a device key that silently matches nothing, for every
lease.

So the honest line is: **subnets enumerated, clients not yet observed, the
length histogram still unrecorded.** Preflight says so itself when a run sees no
clients rather than printing a clean bill of health. A device on one of the
scopes, a lease, and one more run settles it.

**This answers the question `SPIKE-LINUX-DHCP-2026-09-19.md` was reopened for.**
A Linux box outside the trust boundary can read a directory a district actually
uses. The credential model held throughout: the password existed in one
process, the ticket in one tmpfs cache removed at exit, and nothing on the
domain was changed by any of it.

**What six of six does not mean.** Every capability answered; **one of them
answered emptily.** The lease read connected and returned no clients, so the
parse above remains open. Six of six is a claim about reach, not about the data
that will come back.

**Five findings from those runs worth keeping**, none discoverable from
documentation and each of which cost an hour:

- **An MIT `MEMORY:` ticket cache is private to the process that creates it.**
  `kinit` succeeds, exits, and takes the cache with it; every later process
  inherits a variable naming something that is gone.
- **OpenLDAP canonicalises the server name itself**, by reverse-resolving the
  address, separately from Kerberos's `rdns`. It asks for `ldap/<whatever the
  PTR says>`, so a host holding a perfectly good ticket is told the server is
  not in the Kerberos database. `SASL_NOCANON on` is what fixed it, and
  `kvno` is what proved the principal had been there all along.
- **The DHCP service does not listen on a fixed port.** It registers with the
  endpoint mapper and takes what is free, so a client asks the mapper where the
  interface lives. Dialling 135 and offering it MS-DHCPM authenticates happily
  and is then refused *abstract syntax not supported* — a bind that succeeded
  against the wrong door.
- **A named pipe needs `cifs/`, not `host/`**, because `ncacn_np` is RPC over
  SMB. And supplying it is not enough: `dcerpc.WithTargetName` configures the
  RPC security while **SMB session setup negotiates separately**, which needs
  `WithSMBDialer`. Not pursued — TCP works.
- **`ERROR_NO_MORE_ITEMS` is an empty answer, not a failure to read.** The call
  succeeded and the scope holds no clients. Rendering it as *could not be read*
  is the refusal-as-empty-container defect inverted, and this direction is
  worse: it makes a genuinely empty scope look like a fault in the appliance,
  at a customer, where nobody can tell the difference.

---

## Before you start: what the lab needs

Read this first. Every one of these is a prerequisite rather than a
recommendation, and three of them are the reason a preflight run produces a
result nobody can trust when they are missing.

| | |
| --- | --- |
| **A Windows domain** | One domain controller is enough. It must hold DNS, and DHCP must be running somewhere you can name |
| **A service account** | An **ordinary domain user**, plus membership of **DHCP Users**. Nothing else. No Domain Admin, no delegation, no rights on the DCs |
| **No keytab** | **There is deliberately none.** The credential is held in the portal and fetched per run; `preflight.sh` refuses to start if it finds a keytab or a stored password. This row said to generate one with `ktpass` until 20 September 2026 and was left behind when the design changed |
| **The DHCP service restarted since the account joined `DHCP Users`** | It caches the group SIDs. A normal patch window is enough — see `LAB-BUILD.md` |
| **A Linux host** | Debian or Ubuntu. **Single-homed** — one interface carrying one address |
| **One resolver** | The customer's DNS, and nothing else in `/etc/resolv.conf` |
| **Clock within five minutes** | Kerberos refuses a ticket outside its skew, and the error does not say so in those words |

### Why single-homed, and why one resolver

An appliance with two interfaces or two resolvers produces preflight results
that mean nothing. A lookup that quietly answers from a public resolver reads
as the domain being reachable; a second interface means the route a probe took
is not the route the collector will take. **Neither failure announces itself** —
they both look like success — so the shape of the host is a prerequisite rather
than a preference, and `bootstrap.sh` prints what it finds without correcting
it.

### The credential: held in the portal, never on this box

**Jackie's design, 20 September 2026. It replaces both the hand-placed keytab
and the domain join that was briefly proposed to fix it.**

- The customer enters a read-only service credential **into the portal**.
- This appliance connects **out** to the portal and fetches it at run time.
- It `kinit`s into a **memory-backed** credential cache — a private directory
  on `tmpfs`, removed when the run ends — uses it, and drops it. **Nothing
  durable on the box.**

  > This was `KRB5CCNAME=MEMORY:` until 20 September 2026, and that **did not
  > work**, in a way that looked like working. An MIT `MEMORY:` cache lives in
  > the address space of the process that made it, so `kinit` exited 0 and took
  > the ticket with it; every later process inherited a variable naming a cache
  > that was gone. `tmpfs` is still RAM and still never touches persistent
  > storage — what it adds is that a second process can read it, which is what
  > was actually needed. The claim is narrowed rather than defended: the ticket
  > exists only in RAM, only for the run, in a directory only root can enter.
- **Revocation is one action in the portal**, not a site visit.
- **We never handle the customer's credential** — not in a ticket, not in a
  message, not in a file we place. That rule has stood all week on discipline;
  this is the first arrangement that enforces it rather than relying on it.

`preflight.sh` checks the durability claim rather than asserting it: it refuses
to run if it finds a keytab or a password in the settings file, because a
design whose central property is *there is no copy here* is worth exactly what
checking it is worth.

### The appliance authenticates with a keypair, not a bearer token

Generated on this box at enrolment by `enroll.sh`. The public half is
registered with the portal; **the private half is never transmitted.**

The reasoning is about copies rather than about consequences. A bearer token
exists in at least two places — the portal minted it, it travelled in a
response, somebody pasted it somewhere, and a backup or a configuration system
may hold it. Any of those can leak without anybody touching this machine. A
private key generated here exists in one place, and the portal cannot leak what
it never had.

**What it does not change, said plainly:** an attacker with root on this box
gets the key and can then ask the portal for the credential, exactly as a
stolen token would let them. The difference is the number of copies and the
paths they travelled. Both are revocable centrally, which is the other half of
why either beats a credential file.

### Why not join the domain

It was the obvious fix for a keytab nobody manages, and it is **withdrawn**: a
collector must not be a member of the trust boundary it reads.

A joined appliance is a computer object inside the directory it is measuring —
subject to that domain's policy, inside its blast radius, and, if it is
compromised, a foothold *within* the domain rather than a read-only credential
held outside it. It also keeps a durable machine credential on the box, which
is the property this design exists to remove.

### The residual, which is the floor rather than a flaw

**While a run is happening the credential is in this appliance's memory, so a
compromised appliance can capture it.** No arrangement removes that: the box
has to hold the credential to use it.

It is equally true of the Windows alternative — a domain-joined collector under
a group Managed Service Account can be made to use that identity by anybody who
owns the machine. And what is captured is read-only: an ordinary domain user
plus `DHCP Users` can enumerate and cannot change a scope, a lease, an account
or a policy, which the customer's own administrator can verify from the account
rather than from our description of it.

### ~~The keytab is a deferral — and the domain join that was to fix it~~

> **Superseded 20 September 2026, and kept rather than deleted.** Claude's
> record under Jackie's standing authority, traced to `6995e71`. **The design
> change it records is Jackie's**, 20 September 2026; the decision to keep the
> superseded section rather than delete it is an editorial act and is Claude's.
> A tie is not resolved toward Jackie. Everything
> below was true when written and describes the two arrangements this design
> replaced. It stays because the *reasoning* is what the new design is measured
> against — in particular the paragraph explaining why file permissions are not
> a solution, which is still the argument, and which the new design answers by
> removing the file rather than by protecting it better.
>
> **The domain join is withdrawn**, on a ground the text below never considered:
> a collector must not be a member of the trust boundary it reads.

On Windows, a group managed service account is the better credential in every
respect that matters: the domain generates and rotates its password, nothing is
ever written to disk, and no human sees the secret at any point. **A Linux host
cannot hold one.** It authenticates with a keytab, which is a file, on disk,
containing long-term key material for the account.

**That difference is why the 19 September spike chose Windows**, and the
reasoning was sound. This appliance exists because Jackie asked for one, which
is the event that spike named as its own condition for reopening — **not
because anybody found a hole in the argument.**

So what this repository ships today has to be described accurately:

**A keytab at mode 600 in a directory at mode 700, with `preflight.sh`
refusing to run if either is wider, is a lab-acceptable deferral. It is not a
solution.** Those are the words, and they are chosen. File permissions
constrain which local users can read the file. Every objection the spike raised
still stands against it: the credential is long-lived, the client's domain does
not manage it, it does not rotate, it fails silently when somebody changes the
account's password, and revoking it means knowing it exists. Nothing about
`chmod` would satisfy a review that objected to the thing itself.

### The candidate answer, to be tested in the lab

**Join the appliance to the domain with `realmd` and `adcli`.**

The host gets a **machine account**. The join tooling creates and rotates the
keytab rather than a person placing it. Revocation becomes *disable the
computer object in Active Directory* — one action, in the client's own
directory, on an object beside every other machine they own.

**It is still a keytab on disk. It is not a gMSA**, and this README does not
claim otherwise. What changes is who manages the file: it moves Linux from *a
secret nobody manages* to *a domain member like any other*, which is exactly
the axis the Windows decision turned on.

Two honest outcomes, and neither is assumed:

- **If the join works**, the objection is answered rather than standing, and
  the Windows-versus-Linux question genuinely changes — it becomes a decision
  about operating systems on their merits.
- **If it does not**, the objection holds as written and **this appliance stays
  a lab instrument** rather than becoming a product. The four capabilities
  would still have been answered, which is worth having either way.

**`preflight.sh` step 0 reports which of the two this host is** — joined, and
by what mechanism, or authenticating from a keytab somebody placed. It blocks
nothing: a hand-placed keytab is a perfectly good lab instrument. What it
changes is what a passing run is worth as a *product* rather than as an
experiment, and that distinction is invisible from the rest of the output.

### What bounds the credential either way

The account is an ordinary domain user plus DHCP Users. It can read; it cannot
change anything, anywhere, and the client's own administrator can read that off
the account rather than taking our word for it.

If a customer's security review will not accept a keytab on disk even under a
machine account, that is a reasonable position and the answer is a Windows
collector rather than an argument.

---

## Installing

**Running it for the first time? Read `LAB-BUILD.md` instead.** One Linux VM,
one read-only account, three commands, and what every line of preflight's
output means — written for somebody who has read none of this.

**Building the Go probe on its own? `BUILD.md`.** `preflight.sh` always
rebuilds it, so a normal run needs nothing extra — that document is for when
you want the compiler's output without a domain read after it, and it carries
the three reads that tie a binary to the commit it came from.

### The first run is against RVA Tech Visions' own production domain

Not a built lab forest. **RVA becomes the first customer of its own
appliance** — it is already an organization in Cairn with five connections and
has never had a collector one.

**That changes what the read-only constraints are for, and it is worth saying
where somebody will read it.** Until now they protected a hypothetical
customer. The first real run points this software at Jackie's own Active
Directory, DNS and DHCP — the directory his business runs on. Every scan that
forbids a state-changing cmdlet, every enumeration that is a read, and the
`DHCP Users`-and-nothing-more grant are now protecting the estate of the person
who wrote the rules.

It also raises what a passing run is worth. A toy forest with one scope and two
objects answers *does the protocol work*. A directory somebody actually uses,
with real accumulated history, answers the question that decides whether this
becomes a product.

The appliance writes nothing, anywhere. The one change to the directory is the
service account, created by hand by the person who owns the domain — the same
distinction this project already draws for `create-app-registration.ps1`.

Three steps, in order, and the first contacts nothing.

**All three are written to run as root**, because a minimal Debian or Ubuntu
image ships no `sudo` — and there `sudo ./bootstrap.sh` fails with *command not
found*, which reads as the script being missing when it is `sudo` that is. As a
normal user, prefix each with `sudo`, and use **`sudo -E`** for `preflight.sh`
or the credential does not survive into the elevated environment. No script
calls `sudo` itself, and `bootstrap.sh` checks `id -u` and refuses if you are
not root.

```
./bootstrap.sh
```

Installs `krb5-user`, `ldap-utils`, Go and `jq`; creates `/etc/cairn-appliance`
mode 700; writes a settings template; and prints the host's resolvers and
interfaces so you can see whether it is shaped the way the table above
requires.

**It is idempotent and no step aborts the run.** Run it twice and the second
run changes nothing. A step that fails does not stop the ones after it, and the
summary at the end names each failure — a host with no Go in its repositories
should still end up with Kerberos and LDAP working, and you should be told
exactly which piece is missing rather than being left with a half-prepared
machine.

**`settings.env` does not ship in this repository**, so it will not be in a
clone. `bootstrap.sh` writes it and leaves an existing one alone. It is absent
by design: the filled-in file names a customer's domain controllers and service
account, and a template carried here is the file somebody eventually fills in
and commits.

Then fill in `/etc/cairn-appliance/settings.env` — realm in **upper case**,
host names in lower — and give this appliance its identity:

```
./enroll.sh
```

It generates the keypair here and prints the public half. **The portal side of
enrolment is not built**, so it says so rather than implying it registered.

```
./preflight.sh
```

**It prompts for the password**, so there is no variable to arrange first and
nothing to paste. That is not only convenience: a `read` inside a pasted block
consumes the *next line of the paste* as the password, hands the KDC a word
nobody typed, and earns a failed-logon event against the account for it.

The value is read without echo and held in preflight's own process rather than
in the shell's environment, where an exported variable would stay readable from
`/proc` long after the run. `CAIRN_PASSWORD` is still honoured when it is
already set, for an unattended run; with neither a terminal nor the variable,
preflight refuses rather than waiting for input nobody can supply.

This is the **lab** path throughout. In production the appliance authenticates
with the key `enroll.sh` generated, fetches the credential from the portal per
run, and holds it in memory. There is deliberately no password in
`settings.env` — preflight refuses to start if it finds one there.

---

## What preflight answers

Six things, asked and answered **separately**, because they fail for different
reasons and one verdict sends somebody to fix whichever they thought of first.

| | What it asks | What a failure usually means |
| --- | --- | --- |
| **0. Where the credential comes from** | The appliance key, `CAIRN_PORTAL`, and whether a credential was supplied for this run | Not a failure. It reports whether this run is the lab path or the portal path |
| **1. Kerberos** | `kinit` into a memory-backed cache | The password, the realm's case, or a clock more than five minutes out |
| **2. AD over LDAP** | One bound read of the domain head | The account cannot read the directory |
| **3. DNS in the directory** | `CN=MicrosoftDNS` under `DomainDnsZones` | The site's DNS is not directory-integrated — a normal state, not a failure |
| **4. Authorised DHCP servers** | `CN=NetServices` in the configuration partition | Rare: this needs only an authenticated user |
| **5. DHCP over MS-DHCPM** | `R_DhcpEnumSubnets`, then leases from a sample of scopes | The account is not in **DHCP Users** |

### Partial credit, which is why nothing stops at the first failure

**Steps 4 and 5 need different rights.** Reading the authorised-server list
needs an authenticated user; the DHCP interface needs DHCP Users. So a host can
pass everything up to and including step 4 and be refused at step 5 — and that
is a useful result, not a failed run. It says the credential works, the
directory is readable, and **one right is missing**, which is a different
conversation from *this host cannot do the job*.

The spike this came from ran its four steps in order and stopped at the first
failure. That was right for a question of *does any of this work at all* and is
wrong for a preflight, so every capability here is asked on its own and the
summary says plainly when a run is partly proven.

### Three states, not two

`found`, `refused`, and **not asked**. A capability that was never asked —
because something it depends on failed, or because nothing configured it — is
not a capability that was tried and refused, and only one of those is evidence
about the customer's network. Collapsing them is how a missing setting gets
reported as a broken domain.

### It reports what it found and never asserts an expected count

There is no line in `preflight.sh` that says a district should have six DHCP
servers, or four hundred leases, or any zones at all. **Preflight cannot know
what is correct for a site it has never seen**, and a check that invents an
expectation produces a confident wrong verdict about somebody else's network.
It prints what answered, what refused, and what each one said. The person
reading it is the one who knows what the site is meant to look like.

### It collects nothing, and reports only what it reached

**This section said "no outbound call of any kind" and that is withdrawn
rather than reworded.** An enrolled box makes two calls, both to the
portal and to nowhere else: it fetches the directory credential at the
start of a run, and at the end it posts what the run reached.

What that report carries is the name of each capability, one of three
states, and a reason where it did not answer. **No device, no lease, no
address, no account name, no part of the directory.** Inventory has its
own door with its own paging and its own retirement rules; nothing in
`preflight.sh` writes through it.

Output still goes to the screen, and it writes a file only if you ask for
one — that file is in `.gitignore` because it contains a customer's host
names and addresses.

**A box that is not enrolled, or has not been told a portal, sends
nothing at all** and says so at the end of the run.

---

## Read-only, and how that is bounded

Every call this repository makes is a read.

- **Kerberos**: obtains a ticket. Nothing else.
- **LDAP**: `ldapsearch`. No `ldapmodify`, no `ldapadd`, no `ldapdelete`.
- **DHCP**: `R_DhcpEnumSubnets` and `R_DhcpEnumSubnetClientsV5`, both
  enumerations. No `R_DhcpSetSubnetInfo`, no `R_DhcpDeleteSubnet`, no
  `R_DhcpCreateClientInfo`.

The account cannot do more than this even if the code asked, which is the
half a customer can check for themselves: an ordinary domain user plus DHCP
Users has no rights to change anything, and their own administrator can read
that off the account rather than taking our word for it.

---

## The DHCP probe has never been compiled

`preflight/main.go` was written on a workstation with no Go toolchain. The
module path is the one specified; **every symbol below it is unread** — the
sub-package, the client constructor, the request and response types, and the
fields the results are read out of.

The design is two documented MS-DHCPM reads over Kerberos and that part is
sound. The **identifiers** are the part to distrust, and a compiler settles
them — **somewhere other than an appliance.**

**This used to print the build command here, and that is withdrawn.** As of
24 September 2026 the appliance neither compiles nor obtains a compiler:
the first timed run rebuilt and replaced the collector’s own executable
because a compiler had been installed on the box, and a document telling an
installer to build is **the same defect with a person as the interpreter**.

Build on a workstation, from this repository, and install the binary. The
names are corrected against the module’s own source, and the notice at the
top of `main.go` is deleted in the same commit — a warning that outlives the
thing it warns about is read as noise the next time one is genuinely needed.

---

## What is not here

- **The collector.** Preflight answers whether a host *can* read; collecting
  and submitting is a separate piece of work and a separate decision.
- **Any credential.** `.gitignore` refuses keytabs, and it was written before
  the first commit rather than after the first mistake. A credential that
  reaches a repository is not removed by deleting it — it is in the history,
  and the remedy is rotation at the domain.
- **Anything that writes.** See above, and it is a property of the account as
  well as of the code.
