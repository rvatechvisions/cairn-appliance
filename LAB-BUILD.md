# Running the appliance against RVA's own domain

**Start here. This is the guide to the environment; `README.md` is the guide to
the appliance.** It assumes you have read neither that file nor anything else.

You are not building a domain. **RVA Tech Visions already has one** — Active
Directory, DNS and DHCP, real and in use. This guide adds one Linux VM to it,
creates one read-only account, and runs three commands.

**Budget half an hour.** Most of it is the Debian install.

---

## What this is, and why it is RVA's own domain rather than a built one

Cairn reads a customer's device inventory. For a district the two sources that
actually say what is on the network are **Active Directory** and **DHCP**, and
both live on Windows servers inside the customer's building.

The question is whether a small Linux box, on the network but **not joined to
the domain**, can read them with an ordinary read-only account. If it can,
customers get an appliance instead of a Windows server they have to patch,
licence and own.

**Testing it against a built toy forest would prove less than it looks.** A
forest with one scope and two objects answers *does the protocol work*; it does
not answer *does this work on a directory somebody actually uses*, which is the
question. RVA's domain has real objects, real leases, real DNS and real
accumulated history — the same shape as a customer's, at a smaller size.

**So RVA Tech Visions becomes the first customer of its own appliance.** It is
already an organization in Cairn with five connections — Microsoft, Google,
Meraki, UniFi and CrowdStrike — and has never had a collector one. This is the
sixth, and it is the same path a district would take.

That also disposes of a question that was open: there is no fake organization
sitting beside two paying clients, no naming games, and no risk of a test
tenant's identifiers colliding with the demonstration's. The round trip is
genuinely the round trip because the tenant is genuinely a tenant.

### What that means for care, said plainly

**This runs against RVA's production domain.** Every read-only constraint in
the appliance now protects Jackie's own business rather than a hypothetical
one — which is the right way round, and is worth knowing before you type
anything.

Nothing in this guide changes the domain except **one account you create
yourself**, by hand, in section 2. The appliance itself never writes: every
call it makes is a bind, a search or an enumeration.

---

## 1 — one Linux VM

**Debian 12 (bookworm)**, netinst, on RVA's network. 2 GB memory, 20 GB disk.

At the software selection screen, **untick everything except "standard system
utilities"** — no desktop, no web server.

### Three things about the network, and they are not preferences

- **One network adapter.** A second active interface lets a DNS query leave by
  one path towards a resolver configured for the other and wait out its
  retries. Neither failure announces itself; the symptom is a delay that reads
  as the portal being slow. This project has already lost an evening to exactly
  that.
- **One resolver, and it is RVA's DC.** Not a public resolver, not a router
  that forwards to one. If the box resolves the domain anywhere other than the
  DC, everything below still runs and means nothing.
- **Not joined to the domain, and it will not be.** A collector must not be a
  member of the trust boundary it reads. There is no `realm join` step in this
  guide and there is not going to be one.

Take a DHCP lease from RVA's own server — that is what a customer's appliance
would do, and it is one more live lease for the appliance to read later. After
it boots:

```bash
ip -brief address show
cat /etc/resolv.conf
```

**One address, and exactly one `nameserver` line pointing at the DC.** If you
see two of either, fix that before going further.

Then check the domain resolves and the clock is close:

```bash
getent hosts DC_HOSTNAME
timedatectl status
```

**Placeholders in this guide are bare uppercase words, and that is deliberate.**
`<dc-hostname>` reads as a placeholder and parses as a *redirection* — in bash
it is a syntax error about an unexpected token, and in PowerShell it is an
error about the `<` operator being reserved. Either way the message is about
redirection and says nothing about the thing you were meant to substitute.

Kerberos refuses any request more than five minutes from the KDC, and the error
it gives says nothing about clocks.

### Get the appliance onto it

**Copy it from the workstation. Do not clone it onto the appliance**, and the
reason is the design rather than convenience.

This repository is private, and GitHub stopped accepting passwords over HTTPS,
so `git clone https://…` prompts and then fails whatever you type — it is not
asking for something you have. The ways to make that work all end the same way:
a GitHub credential, sitting on the box.

**That box is the one machine in this design that is supposed to hold nothing.**
*A collector must not be a member of the trust boundary it reads*, and the
credential model underneath it is that nothing durable lives on the appliance —
the client's credential arrives per run, is used from memory, and is dropped.
A long-lived token for our own source control would be the only durable secret
on a machine whose whole argument is that it has none.

It is also 73 KB of shell scripts that are already on the machine you are
sitting at.

**On the workstation. Both shells are given, because this machine has two and
the commands are not interchangeable** — `/tmp` is not a path in PowerShell and
`sha256sum` is not a command there.

PowerShell:

```powershell
cd C:\dev\cairn-appliance
git archive --format=tar.gz -o C:\dev\cairn-appliance.tgz HEAD
Get-FileHash C:\dev\cairn-appliance.tgz -Algorithm SHA256
scp C:\dev\cairn-appliance.tgz VM_USER@VM_ADDRESS:/tmp/
```

Git Bash:

```bash
cd /c/dev/cairn-appliance
git archive --format=tar.gz -o /c/dev/cairn-appliance.tgz HEAD
sha256sum /c/dev/cairn-appliance.tgz
scp /c/dev/cairn-appliance.tgz VM_USER@VM_ADDRESS:/tmp/
```

`git archive` takes the tracked files at `HEAD` and nothing else — no `.git`,
no scratch files — and writes the bytes the index holds, which is what keeps
the line-ending check below true.

**`Get-FileHash` prints uppercase and `sha256sum` prints lowercase.** It is the
same hash. Compare them without regard to case, or a good copy reads as a
corrupt one.

**On the VM:**

```bash
sha256sum /tmp/cairn-appliance.tgz
mkdir -p ~/cairn-appliance && tar -xzf /tmp/cairn-appliance.tgz -C ~/cairn-appliance
cd ~/cairn-appliance
```

**Check the two hashes match before going on.** A truncated copy extracts
without complaining and is indistinguishable from a good one until something
halfway through behaves oddly.

**Then check the line endings, because this failure lies about its cause:**

```bash
file *.sh
```

Every one must read `Bourne-Again shell script`. If any says **`with CRLF line
terminators`**, re-copy rather than continuing — a carriage return on the
shebang makes Linux report *no such file or directory* for a file that is
plainly there, and the hour goes on the path rather than on the byte.
`.gitattributes` pins `*.sh` to LF so `git archive` cannot produce this; a copy
made some other way can.

<details>
<summary>If you would rather have git on the box anyway</summary>

Then it is a deliberate choice with a cost rather than a default. `gh auth
login` completes headless through a device code entered on another machine, and
`gh repo clone rvatechvisions/cairn-appliance` works afterwards. The cost is
the credential above, so remove it when you are finished:

```bash
gh auth logout
```

The other option is to make this repository public, which removes the friction
permanently and is **your call rather than a step in a guide**. Nothing in here
is a secret — `.gitignore` was written before any other file and no keytab,
password or client name has ever been in it — but it is still a published
description of how we read a customer's directory, and publishing is not
reversible in the way deleting a file is.

</details>

---

## 2 — the read-only account, in RVA's domain

**This is the only change anybody makes to the directory.** You make it, by
hand, in your own domain — the same distinction this project already draws for
`create-app-registration.ps1`, where a technician makes a one-off change with
their own credentials and the collector that follows only reads.

On a domain-joined Windows machine, PowerShell as a Domain Admin:

```powershell
New-ADUser -Name "svc-cairn" -SamAccountName "svc-cairn" `
  -UserPrincipalName "svc-cairn@YOUR_DOMAIN" `
  -AccountPassword (Read-Host -AsSecureString "Password for svc-cairn") `
  -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true

Add-ADGroupMember -Identity "DHCP Users" -Members "svc-cairn"
```

**That is the whole grant.** `DHCP Users` is read-only on the DHCP service;
`Domain Users`, which every account gets automatically, is what lets it read
the directory and the DNS zones. Nothing else is added and nothing else is
needed.

### Verify it, because this is the claim the whole design rests on

```powershell
Get-ADPrincipalGroupMembership svc-cairn | Select-Object -ExpandProperty Name
```

**It must print exactly two lines: `Domain Users` and `DHCP Users`.**

If anything else appears — `Domain Admins`, `DHCP Administrators`, `Account
Operators`, `Server Operators`, `Backup Operators` — remove it and run the
check again. *This account can read and cannot change anything* is what a
customer's security review will be told, and it is only true if this command
says so.

### Where to put it

Put it in whichever OU RVA uses for service accounts. It does not matter to the
appliance, and it matters to whoever audits the directory in six months.

---

## 3 — the credential, and what is not built

The design: the customer enters the credential **into the portal**, the
appliance connects **out** and fetches it per run, `kinit`s into a
**memory-backed** cache, and drops it. Nothing durable on the box. Revocation
is one action in the portal.

**The portal half does not exist yet** — there is no page to enter a credential
into and no endpoint to fetch it from. Saying so plainly matters: a guide that
told you to enter it in the portal would have you hunting for a screen that is
not there.

**Preflight needs none of it.** It reads and submits nothing, so for this run
you type the password into the appliance's shell:

```bash
read -rs CAIRN_PASSWORD && export CAIRN_PASSWORD
```

`read -rs` does not echo and keeps it out of shell history. It lives in one
environment variable and one in-memory ticket cache, and nothing writes it
down — so the *durability* property is genuinely tested. What is **not** tested
is the round trip, and what is **not** acceptable is doing this at a customer.

### What Cairn needs from you for this run: nothing

No connection to create, no token to issue, no organization to set up.
Preflight makes no outbound call beyond RVA's own domain controllers.

**Cairn becomes involved at the next step, not this one** — when the appliance
submits. That needs a `collector` connection on RVA Tech Visions and a token,
which is the mechanism the existing DHCP collector at a live district already uses, plus the credential
path above. Both are work, and neither blocks the run below.

---

## 4 — the three commands

```bash
sudo ./bootstrap.sh
```

Installs `krb5-user`, `ldap-utils`, Go and `jq`; creates `/etc/cairn-appliance`
at mode 700; writes a settings template; prints this host's resolvers and
interfaces. **It contacts no domain.** It is idempotent, and a failing step
does not stop the ones after it — read the summary at the end rather than the
first error.

Fill in the settings:

```bash
sudo nano /etc/cairn-appliance/settings.env
```

```
CAIRN_REALM=<YOUR-DOMAIN-IN-UPPER-CASE>
CAIRN_DC=<dc-hostname.your-domain>
CAIRN_PRINCIPAL=svc-cairn@<YOUR-DOMAIN-IN-UPPER-CASE>
CAIRN_DHCP_SERVERS=<dhcp-hostname.your-domain>
CAIRN_PORTAL=
```

**The realm is upper case and host names are lower case.** Kerberos treats the
realm as case-sensitive, and this is the single most common reason step 1 fails
on a first run.

`CAIRN_DHCP_SERVERS` takes a comma-separated list. If RVA runs DHCP on more
than one server, name them all — each is asked and answered separately.

```bash
sudo ./enroll.sh
```

Generates this appliance's keypair and prints the public half. The private half
never leaves the box. Since the portal side does not exist, it says so rather
than implying it registered.

```bash
read -rs CAIRN_PASSWORD && export CAIRN_PASSWORD
sudo -E ./preflight.sh
```

**`sudo -E`, not plain `sudo`.** Without `-E` the password does not survive
into the elevated environment and step 1 reports it had no credential — which
is true, and is not what you were trying to find out.

---

## 5 — reading the result

Six things, asked separately, each answered in **three** states: **found**,
**refused**, and **not asked**. The third is not a failure of the host — it
means something a check depended on did not happen, or nothing configured it,
and telling it apart from a refusal is the whole point.

| What you see | What it means | What to do |
| --- | --- | --- |
| `no keytab, no stored password` | Nothing durable on the box, which is the design's central claim | Nothing. This is the good outcome |
| `REFUSING TO CONTINUE. A durable credential is on this appliance` | A keytab or a stored password was found | Remove it. If it was a password, treat it as disclosed |
| `not enrolled: no appliance key` | `enroll.sh` has not been run | Run it |
| `CREDENTIAL SOURCE: this operator's shell` | Expected for this run | Nothing — but never at a customer |
| `FOUND: a ticket was issued` | **Step 1 passed.** Kerberos works from an unjoined Linux host against a real domain | This is the first real result of the exercise |
| `REFUSED: no ticket` | Wrong password, realm not upper case, or a clock more than five minutes out | Check the realm's case first — it is usually that |
| `FOUND: the directory answered a bound read` | **Step 2 passed.** The account can read AD over LDAP | — |
| `FOUND: N zone(s) readable` | **Step 3 passed.** DNS is directory-integrated and readable | Check N against what RVA actually has |
| `NOT PRESENT: no directory-integrated DNS` | A normal state at some sites, not a failure | If RVA's DNS *is* AD-integrated and this says otherwise, that is a finding worth keeping |
| `FOUND: the container answered` | **Step 4 passed.** The authorised-server list is readable. Needs only an authenticated user | Compare the list against the DHCP servers you believe exist |
| `bound: MS-DHCPM on <dc>` then scopes | **Step 5 passed.** This is the answer the whole exercise was about | Read the scope list and the lease counts against what you know is there |
| `REFUSED by <server>` | Almost always: the account is not in `DHCP Users` | Re-run the verification in section 2 |
| `NOT ASKED` | Something it depends on failed, or nothing configured it | Fix what it names. It is not evidence about the domain |
| `PARTLY PROVEN: N answered and M refused` | **A result, not a failed run** | Steps 4 and 5 need different rights, so one refusal does not stand in for the others |

### What a good first run looks like

Kerberos, LDAP, DNS and the authorised-server list answering, and DHCP either
answering with scopes or refusing with a rights error. **Either of those last
two is a successful run** — one proves the appliance can read DHCP from an
unjoined host, the other proves it cannot with the rights we thought were
enough. Both are worth more than the guess we have now.

### The part only you can check

Preflight **asserts no expected count**. It will not tell you a scope or a zone
is missing, because it cannot know what is correct for a site. You can: you
know how many DHCP servers RVA has and roughly how many leases. **Compare what
it printed against what you know is there** — that comparison is the actual
result of this exercise, and nobody else can make it.

---

## The residual risk, stated rather than buried

**While a run is happening, the credential is in that appliance's memory. A
compromised appliance can capture it.** No arrangement removes that — the box
has to hold the credential to use it.

Two things bound it, and neither is a dodge:

- **It is true of the Windows alternative too.** A domain-joined collector
  running under a group Managed Service Account can be made to use that
  identity by anybody who owns the box. Holding a credential in order to use it
  is the floor for any collector, not a flaw in this one.
- **What is captured is read-only.** `svc-cairn` can enumerate; it cannot
  change a scope, a lease, an account or a policy — and section 2's
  verification is what makes that checkable rather than asserted.

What this design removes is everything that outlives a run: no keytab, no
password in a file, no credential in a ticket or a message, and nothing for the
next person with a shell on the box to find.

## When you are finished

If the appliance is not staying, disable `svc-cairn` rather than deleting it —
a disabled account leaves the audit trail of what it did, and deleting one is a
change nobody can review afterwards. If it is staying, leave it and move on to
the collector connection in Cairn.
