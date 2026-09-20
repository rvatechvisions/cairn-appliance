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

### The keytab is a deferral, not a solution — and it is the open question

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

Six things, asked and answered **separately**, because they fail for different
reasons and one verdict sends somebody to fix whichever they thought of first.

| | What it asks | What a failure usually means |
| --- | --- | --- |
| **0. Domain membership** | `realm list`, `adcli`, `/etc/krb5.keytab` | Not a failure. It reports whether the credential is managed by the domain or placed by hand |
| **1. Kerberos** | `kinit -k -t` with the keytab | The account's password was changed, or the clock is out |
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
