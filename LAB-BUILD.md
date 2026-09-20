# Building the lab

**Start here. This is the guide to the environment; `README.md` is the guide to
the appliance that runs inside it.** It assumes you have read neither that file
nor anything else, and it does not send you to another document to find a value
you need.

You will build two virtual machines, create one account, run three commands,
and read one page of output. Budget two hours the first time, most of it
waiting for Windows to install.

---

## Why this exists at all

Cairn reads a customer's device inventory. For a school district, the two
sources that actually say what is on the network are **Active Directory** and
**DHCP**, and both live on Windows servers inside the district.

The question this lab answers is whether a small Linux box, sitting on the
network but **not joined to the domain**, can read them with an ordinary
read-only account. If it can, districts get an appliance instead of a Windows
server they have to patch, licence and own.

**Nobody has run this yet.** The code exists and has been exercised against
made-up data; it has never met a domain controller. That is what the lab is
for, and it is why the output matters more than whether it passes.

---

## What you need before you start

| | |
| --- | --- |
| A hypervisor | Hyper-V, VMware Workstation, Proxmox or VirtualBox. Anything that runs two VMs on one network |
| Windows Server ISO | **2022**, Standard, *Desktop Experience*. The Microsoft evaluation ISO is fine — 180 days, no key |
| Debian ISO | **Debian 12 (bookworm)**, netinst |
| Disk | About 60 GB total: 40 for Windows, 20 for Debian |
| Memory | 4 GB for Windows, 2 GB for Debian |
| Time | ~90 minutes of Windows installation and promotion, ~20 minutes of everything else |

### The one network rule that matters

**Both VMs go on the same isolated virtual network, and that network has no
other DHCP server on it.** Not your home network, not the office LAN — an
internal-only virtual switch. You are about to stand up a DHCP server and a
DNS server, and putting either on a network that already has one is how you
spend an afternoon debugging somebody else's router.

In Hyper-V that is a switch of type *Internal*. In VMware it is a *Host-only*
network. In VirtualBox it is an *Internal Network*.

### Why Debian 12 specifically

Three reasons, in the order they matter:

1. **`bootstrap.sh` installs with `apt` and names Debian package names.** On
   anything RPM-based it fails immediately.
2. **Everything needed is in bookworm's own repositories** — `krb5-user`,
   `ldap-utils`, `golang-go`, `jq`. No third-party repository, no backports,
   nothing to trust beyond Debian.
3. **It is the platform Cairn already runs on.** The portal's container is
   built on `node:24-bookworm-slim`, so bookworm is a userland this project
   already keeps working. One fewer unfamiliar variable when something breaks.

**Ubuntu Server 24.04 LTS works identically** and is a fine substitute if you
already have the ISO — same package names, same commands. Do not use a
desktop-edition Linux: `systemd-resolved` and NetworkManager both rewrite
`/etc/resolv.conf`, and this appliance needs exactly one resolver that stays
put.

---

## Part 1 — the Windows Server VM

Install Windows Server 2022, Desktop Experience, and set an Administrator
password. Nothing unusual.

### 1.1 Give it a fixed address and a name

Open PowerShell **as Administrator** on the Windows VM. Everything in Part 1
and Part 2 runs there.

```powershell
Rename-Computer -NewName DC1 -Restart
```

After it reboots, set a static address. Replace `Ethernet` if your adapter is
named something else — `Get-NetAdapter` tells you.

```powershell
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress 10.99.0.10 `
  -PrefixLength 24 -DefaultGateway 10.99.0.1
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 127.0.0.1
```

There is no gateway on an isolated switch and that is fine — nothing in this
lab needs the internet once the ISOs are in.

### 1.2 Promote it to a domain controller

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Install-ADDSForest -DomainName cairnlab.test -DomainNetbiosName CAIRNLAB `
  -InstallDns -Force
```

It will ask for a **Directory Services Restore Mode password**. Write it down;
you will not need it in this lab, but a DC without one recorded somewhere is a
bad habit.

The VM reboots and comes up as a domain controller for `cairnlab.test`.

> **Why `.test`.** It is reserved by RFC 2606 for exactly this, so it can never
> collide with a real domain anybody owns. Do not use `.local` — it collides
> with multicast DNS — and do not use a real company's name.

### 1.3 Add the DHCP role, authorise it, and create a scope

```powershell
Install-WindowsFeature DHCP -IncludeManagementTools

Add-DhcpServerInDC -DnsName dc1.cairnlab.test -IPAddress 10.99.0.10

Add-DhcpServerv4Scope -Name "Lab Clients" `
  -StartRange 10.99.0.100 -EndRange 10.99.0.200 `
  -SubnetMask 255.255.255.0 -State Active

Set-DhcpServerv4OptionValue -ScopeId 10.99.0.0 `
  -DnsServer 10.99.0.10 -DnsDomain cairnlab.test
```

`Add-DhcpServerInDC` is the one that matters for the appliance: it writes this
server into the directory's list of authorised DHCP servers, which is one of
the things preflight reads.

### 1.4 Create a computer object that is not the DC

```powershell
New-ADComputer -Name LAB-WS01 -SamAccountName LAB-WS01 `
  -Description "Lab computer object, never logged on"
```

One is enough. It gives the directory read something to return besides the
domain controller itself.

### 1.5 Check the clock

```powershell
w32tm /query /status
```

Kerberos refuses any request more than five minutes away from the KDC, and the
error it gives says nothing about clocks. If the Windows VM's time is wrong,
fix it here rather than wondering later.

---

## Part 2 — the read-only service account

Still in PowerShell as Administrator on the Windows VM.

### 2.1 Create it

```powershell
New-ADUser -Name "svc-cairn" -SamAccountName "svc-cairn" `
  -UserPrincipalName "svc-cairn@cairnlab.test" `
  -AccountPassword (Read-Host -AsSecureString "Password for svc-cairn") `
  -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true
```

Choose a password you are willing to type into a terminal later, and one you
would not mind being disclosed — this is a lab domain and it protects nothing
real.

### 2.2 Give it exactly one right, and no others

```powershell
Add-ADGroupMember -Identity "DHCP Users" -Members "svc-cairn"
```

**That is the whole grant.** `DHCP Users` is read-only on the DHCP service;
`Domain Users`, which every account gets automatically, is what lets it read
the directory and the DNS zones.

### 2.3 Verify it, because this is the claim the whole design rests on

```powershell
Get-ADPrincipalGroupMembership svc-cairn | Select-Object -ExpandProperty Name
```

**It must print exactly two lines:** `Domain Users` and `DHCP Users`.

If anything else appears — `Domain Admins`, `DHCP Administrators`, `Account
Operators`, `Server Operators` — remove it and run the check again. The
sentence *this account can read and cannot change anything* is what a
customer's security review will be told, and it is only true if this command
says so.

---

## Part 3 — the Linux appliance VM

Install Debian 12 from the netinst ISO. At the software selection screen,
**untick everything except "standard system utilities"** — no desktop, no web
server. Give it **one** network adapter on the same isolated switch.

### 3.1 Let it take a DHCP lease from the lab

Leave its networking on DHCP. That is deliberate and does two things at once:
it proves the DHCP server works, and it puts a **live lease** in the scope for
the appliance to read later. The lease of the machine doing the reading is a
perfectly good first lease.

After it boots, check what it got:

```bash
ip -brief address show
cat /etc/resolv.conf
```

**You want one address in `10.99.0.100–200` and exactly one `nameserver`
line, reading `10.99.0.10`.** If you see two addresses or two resolvers, fix
that before going further: a second interface lets a lookup leave by one path
towards a resolver configured for the other, and the symptom is not an error —
it is a delay that reads as the portal being slow. This project has already
lost an evening to exactly that.

Confirm the domain resolves:

```bash
getent hosts dc1.cairnlab.test
```

### 3.2 Get the appliance onto the box

The repository is `github.com/rvatechvisions/cairn-appliance`, private. Either
clone it with a token, or — simpler for an isolated lab — copy the folder in
from the hypervisor's shared folder or a USB image.

```bash
sudo apt-get update && sudo apt-get install -y git
git clone https://github.com/rvatechvisions/cairn-appliance.git
cd cairn-appliance
```

---

## Part 4 — the credential, and the one decision that is not mine

This is the part of the design that changed on 20 September 2026, and it is
worth understanding before you run anything.

**The appliance is not joined to the domain and never will be.** A collector
must not be a member of the trust boundary it reads. Instead:

- the customer enters the read-only credential **into the portal**;
- the appliance connects **out** to the portal and fetches it when it runs;
- it authenticates to the portal with a **keypair generated on the appliance
  at enrolment** — the public half is registered, the private half never
  leaves the box;
- the credential is used from a **memory-backed Kerberos cache** and dropped;
- revocation is one action in the portal, not a visit to the site.

### The portal half of that is not built

There is no page to enter a credential into and no endpoint to fetch it from.
Saying so plainly matters more than it might seem: a guide that told you to
"enter the credential in the portal" would have you looking for a screen that
does not exist.

**So the lab uses a stand-in, and it is honest about what it is.** You type the
password into the appliance's shell for one run:

```bash
read -rs CAIRN_PASSWORD && export CAIRN_PASSWORD
```

`read -rs` does not echo it and `-s` keeps it out of your shell history. It
lives in one environment variable and one in-memory ticket cache, and nothing
writes it to disk — so the *durability* property the design is about is
genuinely tested. What is **not** tested is the portal round trip, and what is
**not** acceptable is doing this at a customer: their credential must never
pass through anybody's terminal, ours least of all.

### The decision for you, Jackie — I am not making this one

**Does the lab appliance talk to production Cairn with a lab organization, or
to a portal running locally?**

It does not arise today, because there is nothing to talk to. It arises the
moment the portal half is built, and the answer shapes how that gets written,
so it is better decided now.

**My recommendation: production, with a lab organization** — with two
conditions below. The reasoning:

- **The thing under test is the round trip.** Enrolment, a signed request, a
  credential fetched over real TLS from the real host, and revocation taking
  effect. A local portal exercises *a* portal; it does not exercise the one
  clients use, and the difference is exactly where this kind of thing breaks.
- **It is the same argument the project already accepted elsewhere.** Figures
  carried into a room come from the host that will be shown, not from a probe
  against an embedded database.

**The two conditions, because the cost is real:**

1. **The lab organization sits beside two paying clients.** It must be named
   so nobody could mistake it — *Cairn Lab (test)* rather than anything
   district-shaped — and the credential stored against it must be this lab
   domain's, which protects nothing.
2. **Its identifiers must not collide with the demonstration's.** `build.sh`
   refuses a demo seed sharing a site code, hostname prefix, OUI, /24 or
   organization name with any production tenant, and it reads production's own
   rows to do it. A lab tenant in production joins that comparison. This guide
   uses `cairnlab.test`, `10.99.0.0/24` and `LAB-` / `DC1`, none of which the
   demonstration uses — keep it that way and the build stays green.

**The case for a local portal, stated fairly:** nothing test-shaped ever
touches the production database, and you can break it freely. If either
condition above feels uncomfortable, that is the better answer and the cost is
that the credential path gets tested against a portal nobody else uses.

---

## Part 5 — the three commands

On the appliance, in this order.

```bash
sudo ./bootstrap.sh
```

Installs `krb5-user`, `ldap-utils`, Go and `jq`; creates `/etc/cairn-appliance`
at mode 700; writes a settings template; and prints this host's resolvers and
interfaces so you can see its shape. **It contacts no domain.** It is
idempotent, and a failing step does not stop the ones after it — read the
summary at the end rather than the first error.

Now fill in the settings file:

```bash
sudo nano /etc/cairn-appliance/settings.env
```

```
CAIRN_REALM=CAIRNLAB.TEST
CAIRN_DC=dc1.cairnlab.test
CAIRN_PRINCIPAL=svc-cairn@CAIRNLAB.TEST
CAIRN_DHCP_SERVERS=dc1.cairnlab.test
CAIRN_PORTAL=
```

**The realm is upper case and the host names are lower case.** Kerberos treats
the realm as case-sensitive and it is the single most common reason step 1
fails in a new lab.

```bash
sudo ./enroll.sh
```

Generates this appliance's keypair and prints the public half. Since the portal
side does not exist, it tells you so rather than pretending it registered.

```bash
read -rs CAIRN_PASSWORD && export CAIRN_PASSWORD
sudo -E ./preflight.sh
```

**`sudo -E`, not plain `sudo`** — without `-E` the password does not survive
into the elevated environment and step 1 reports it had no credential.

---

## Part 6 — reading the result

Preflight asks six things separately and answers each in **three** states:
**found**, **refused**, and **not asked**. The third is not a failure of the
host — it means something the check depended on did not happen, or nothing
configured it, and telling it apart from a refusal is the whole point.

| What you see | What it means | What to do |
| --- | --- | --- |
| `no keytab, no stored password` | Nothing durable on the box, which is the design's central claim | Nothing. This is the good outcome |
| `REFUSING TO CONTINUE. A durable credential is on this appliance` | A keytab or a stored password was found | Remove it. If it was a password, treat it as disclosed |
| `not enrolled: no appliance key` | `enroll.sh` has not been run | Run it |
| `CREDENTIAL SOURCE: this operator's shell` | The lab path, working as intended | Nothing — but never do this at a customer |
| `FOUND: a ticket was issued` | **Step 1 passed.** Kerberos works from an unjoined Linux host | This is the first real result of the exercise |
| `REFUSED: no ticket` | Wrong password, wrong realm case, or a clock more than five minutes out | Check the realm is upper case, then `w32tm /query /status` on the DC |
| `FOUND: the directory answered a bound read` | **Step 2 passed.** The account can read AD over LDAP | — |
| `FOUND: N zone(s) readable` | **Step 3 passed.** DNS is directory-integrated and readable | — |
| `NOT PRESENT: no directory-integrated DNS` | A normal state at some sites, not a failure | Nothing. In this lab it should be present; if it is not, DNS was installed separately from AD |
| `FOUND: the container answered` | **Step 4 passed.** The authorised-server list is readable | — |
| `bound: MS-DHCPM on dc1…` then scopes | **Step 5 passed.** This is the answer the whole spike was about | Read the scope list and the lease counts |
| `REFUSED by dc1…` | Almost always: the account is not in `DHCP Users` | Re-run the check in 2.3 |
| `NOT ASKED` | Something it depends on failed, or nothing configured it | Fix what it names. It is not evidence about the domain |
| `PARTLY PROVEN: N answered and M refused` | **A result, not a failed run** | Read it. Steps 4 and 5 need different rights, so one refusal does not stand in for the others |

### What a good first run looks like

Kerberos, LDAP, DNS and the authorised-server list all answering, and DHCP
either answering with scopes or refusing with a rights error. **Either of those
last two is a successful lab run** — one proves the appliance can read DHCP
from an unjoined host, the other proves it cannot with the rights we thought
were enough, and both are worth more than the guess we have now.

### Two things it will not do, so you are not waiting for them

**It asserts no expected count.** It will not tell you the lab is missing a
scope or a zone. It cannot know what is correct for a site, and a check that
invents an expectation produces a confident wrong verdict.

**It submits nothing.** No upload, no portal call, no outbound connection
beyond the domain controller. The output is the deliverable.

---

## The residual risk, stated rather than buried

**While a run is happening, the credential is in that appliance's memory. A
compromised appliance can capture it.** There is no arrangement of this design
that removes that — the box has to hold the credential to use it.

Two things bound it, and neither is a dodge:

- **It is true of the Windows alternative too.** A domain-joined collector
  running under a group Managed Service Account can be made to use that
  identity by anybody who owns the box. Holding a credential in memory to use
  it is the floor for any collector, not a flaw in this one.
- **What is captured is read-only.** An ordinary domain user plus `DHCP Users`
  can enumerate; it cannot change a scope, a lease, an account or a policy. The
  customer's own administrator can verify that from the account, without
  trusting our description of it.

What this design *does* remove is everything that outlives the run: no keytab,
no password in a file, no credential in a ticket or a chat message, and nothing
for the next person with a shell on the box to find.
