# Answer sheet

One page. What to set up, what to run, and what each answer means.

**First run? Read `LAB-BUILD.md`.** It is one Linux VM against RVA's own
domain, not a forest you build.

---

## Set up

| | |
| --- | --- |
| Domain | **RVA's own** — AD, DNS and DHCP, already there. Nothing to build |
| Service account | Ordinary domain user **+ DHCP Users**. Nothing else. Verify with `Get-ADPrincipalGroupMembership` — exactly two lines |
| Credential | **Not on the appliance.** Held in the portal, fetched per run, used from memory. In the lab, typed into the shell for one run |
| Appliance | Debian 12 / Ubuntu 24.04, **one interface**, **one resolver** (the customer's DNS), **not domain-joined** |
| Clock | Within five minutes of the DC |

## Run

**As root.** A minimal image ships no `sudo`, and `sudo ./bootstrap.sh` there
fails with *command not found* — which reads as the script being missing rather
than `sudo`. As a normal user, prefix each with `sudo`, and use `sudo -E` if you
set `CAIRN_PASSWORD` yourself, or it does not survive into the elevated
environment.

```
./bootstrap.sh                             # installs, creates /etc/cairn-appliance (700)
vi /etc/cairn-appliance/settings.env       # realm UPPER CASE, hosts lower
./enroll.sh                                # keypair generated here, never transmitted
./preflight.sh                             # prompts for the password itself
```

**Preflight asks for the password.** There is no variable to arrange first and
nothing to paste. `CAIRN_PASSWORD` is still read if it is already set, for an
unattended run; a run with neither a terminal nor the variable refuses rather
than waiting for input nobody can supply.

## What each answer means

| Line | Means |
| --- | --- |
| `no keytab, no stored password` | Nothing durable on the box. **The good outcome** |
| `REFUSING TO CONTINUE. A durable credential is on this appliance` | A keytab or stored password was found. Remove it; if a password, treat it as disclosed |
| `not enrolled: no appliance key` | Run `enroll.sh` |
| `CREDENTIAL SOURCE: this operator's shell` | The lab path, working as intended. **Never at a customer** |
| `CREDENTIAL SOURCE: the portal` | The real path. The portal half is not built, so step 1 will report it had none |
| `FOUND: a ticket was issued` | Kerberos works from an unjoined host, from a memory-backed cache |
| `REFUSED: no ticket` | Password, realm case, or a clock more than five minutes out |
| `FOUND: the directory answered` | The account can read AD |
| `REFUSED` on LDAP | The bind or the read failed. The reason is printed above the line |
| `FOUND: N zone(s)` | DNS is directory-integrated and readable |
| `NOT PRESENT` on DNS | The site's DNS is not AD-integrated. **A normal state, not a failure** |
| `FOUND: the container answered` | The authorised-server list is readable. Needs only an authenticated user |
| `bound: MS-DHCPM` then scopes | DHCP works. The account is in DHCP Users |
| `REFUSED by <server>` with `ERROR_ACCESS_DENIED` | **The server answered.** Mapper, bind, Kerberos and dispatch all worked — see below |
| `NOT ASKED` | Something it depends on failed, or nothing configured it. **Not the same as refused** |
| `PARTLY PROVEN` | Some answered, some refused. **A result, not a failed run** — they need different rights, so one refusal does not stand in for the others |

## `ERROR_ACCESS_DENIED` on DHCP: what it is, and the two open candidates

**Read this before concluding anything from the word REFUSED.** On RVA's own
domain, 20 September 2026, every layer under the read worked: the endpoint
mapper resolved the dynamic port, DHCPSRV **and** DHCPSRV2 bound, Kerberos
sealed the transport, and `R_DhcpEnumSubnets` was dispatched. **The DHCP
service then made an authorization decision.** That is an access check, not a
protocol failure — go-msrpc does this, and Linux does this.

**The account is not obviously the cause**, which is what makes the rest open:
`svc-cairn` holds `Domain Users` and `DHCP Users` and nothing else, and the
same credential reads the same server from Windows over the network.

**Two candidates, neither asserted, both one command to test.**

**1. The DHCP service has not re-read its group SIDs.** Membership travels in
the Kerberos ticket and preflight takes a fresh one each run — so nothing on
the appliance needs restarting. **That is not the same as nothing needing a
restart.** The DHCP Server service resolves the `DHCP Users` and `DHCP
Administrators` SIDs on its own schedule, and an account added afterwards is a
documented cause of exactly this refusal *with the membership present*.

```powershell
Restart-Service DHCPServer     # on the DHCP server
```

Re-run preflight. **If it answers, that is the cause and it belongs in the
onboarding runbook**, because every future client hits it.

**2. `DHCP Users` may not be sufficient for the enumerate calls.** Add the
account to `DHCP Administrators` temporarily and re-run.

```powershell
Add-ADGroupMember -Identity "DHCP Administrators" -Members svc-cairn
# ... re-run preflight, then ...
Remove-ADGroupMember -Identity "DHCP Administrators" -Members svc-cairn
```

**If that is what it takes, this is a product constraint rather than a lab
detail.** The read-only story rests on `DHCP Users` being enough; if
`R_DhcpEnumSubnets` needs `DHCP Administrators`, **the appliance cannot be
read-only on DHCP** and what a district is asked to grant changes. Find out
where being wrong is cheap, and **record the answer either way** — *`DHCP
Users` is sufficient* is worth as much written down as the alternative.

## Three things to expect

**The DHCP probe will not build first time.** It has never been compiled —
no Go toolchain on the machine that wrote it. `cd preflight && go mod tidy &&
go build .` and correct the names the compiler objects to.

**Preflight asserts no expected count.** It will not tell you the site is
missing a DHCP server or a zone. It cannot know. It prints what answered.

**Nothing is submitted anywhere.** Preflight reads. It does not collect and it
does not upload.

## The credential, in four lines

**It is not on this box.** The customer enters it in the portal; the appliance
fetches it per run, holds it in a memory-backed Kerberos cache, and drops it.
Revocation is one action in the portal.

**The appliance authenticates with a keypair generated here at enrolment**, not
a bearer token. The public half is registered; the private half never leaves.
A token would exist in several places and could leak from any of them; a key
generated here exists in one, and the portal cannot leak what it never had.

**It is not joined to the domain, and will not be.** A collector must not be a
member of the trust boundary it reads.

**The residual, which is the floor rather than a flaw:** during a run the
credential is in memory, so a compromised appliance can capture it. That is
equally true of a gMSA on Windows, and what is captured is read-only.
