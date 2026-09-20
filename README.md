# Cairn collection appliance

A Linux host inside a customer's network that reads Active Directory, the DNS
zones held in it, and DHCP — and submits what it reads to Cairn.

**Nothing in this repository is in front of a customer yet.** `preflight.sh`
answers what a host can reach; it collects nothing and submits nothing. The
collector is a separate thing and is not here.

---

## Before you start: what the lab needs

Read this first. Every one of these is a prerequisite rather than a
recommendation, and three of them are the reason a preflight run produces a
result nobody can trust when they are missing.

| | |
| --- | --- |
| **A Windows domain** | One domain controller is enough. It must hold DNS, and DHCP must be running somewhere you can name |
| **A service account** | An **ordinary domain user**, plus membership of **DHCP Users**. Nothing else. No Domain Admin, no delegation, no rights on the DCs |
| **A keytab for it** | Generated on a domain-joined Windows host with `ktpass`, copied to the appliance, `chmod 600`, owned by root |
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

### The trade this makes against a gMSA, stated plainly

On Windows, a group managed service account is the better credential in every
respect that matters: the domain rotates its password, nothing is ever written
to disk, and no human sees the secret at any point. **A Linux host cannot hold
one.** It authenticates with a keytab, which is a file, on disk, containing
long-term key material for the account.

So the trade is real and it is this:

- **What is lost.** The credential is a file. Anybody who can read it can
  authenticate as that account without a password and without a prompt. It does
  not rotate on its own, and it stops working silently when somebody changes
  the account's password.
- **What bounds it.** The account is an ordinary domain user plus DHCP Users.
  It can read; it cannot change anything, anywhere, and that is checkable in
  the customer's own directory rather than on our word. The keytab is mode 600,
  owned by root, in a directory that is mode 700, and `preflight.sh` **refuses
  to run** if either is wider.
- **Why it is worth making.** The alternative is a Windows host inside every
  customer's network, which is a machine somebody has to patch, licence and
  own. This is the same read, from a host that does less.

If a customer's security review will not accept a keytab on disk, that is a
reasonable position and the answer is a Windows collector rather than an
argument.

---

## Installing

Two steps, in order, and the first contacts nothing.

```
sudo ./bootstrap.sh
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

Then fill in `/etc/cairn-appliance/settings.env`, put the keytab where it says,
and:

```
sudo ./preflight.sh
```

---

## What preflight answers

Four capabilities, asked and answered **separately**, because they fail for
four different reasons and one verdict sends somebody to fix whichever they
thought of first.

| | What it asks | What a failure usually means |
| --- | --- | --- |
| **1. Kerberos** | `kinit -k -t` with the keytab | The account's password was changed, or the clock is out |
| **2. AD over LDAP** | One bound read of the domain head | The account cannot read the directory |
| **3. DNS in the directory** | `CN=MicrosoftDNS` under `DomainDnsZones` | The site's DNS is not directory-integrated — a normal state, not a failure |
| **4. DHCP** | `R_DhcpEnumSubnets`, then leases from a sample of scopes | The account is not in **DHCP Users** |

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

### It submits nothing

No portal, no token, no upload, no outbound call of any kind beyond the
customer's own domain controllers. Output goes to the screen. It writes a file
only if you ask for one, and that file is in `.gitignore` because it contains a
customer's host names and addresses.

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
sound. The **identifiers** are the part to distrust, and the compiler settles
them in one command:

```
cd preflight && go mod tidy && go build .
```

Expect names to need correcting on that first build. Correct them against the
module's own source, and delete the notice at the top of `main.go` in the same
commit — a warning that outlives the thing it warns about is read as noise the
next time one is genuinely needed.

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
