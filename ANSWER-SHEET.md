# Answer sheet

One page. What to set up, what to run, and what each answer means.

**Building the lab from nothing? Read `LAB-BUILD.md`.** This page assumes the
environment exists.

---

## Set up

| | |
| --- | --- |
| Domain controller | Holds DNS. DHCP running somewhere you can name |
| Service account | Ordinary domain user **+ DHCP Users**. Nothing else |
| Credential | **Not on the appliance.** Held in the portal, fetched per run, used from memory. In the lab, typed into the shell for one run |
| Appliance | Debian 12 / Ubuntu 24.04, **one interface**, **one resolver** (the customer's DNS), **not domain-joined** |
| Clock | Within five minutes of the DC |

## Run

```
sudo ./bootstrap.sh                        # installs, creates /etc/cairn-appliance (700)
sudo vi /etc/cairn-appliance/settings.env  # realm UPPER CASE, hosts lower
sudo ./enroll.sh                           # keypair generated here, never transmitted
read -rs CAIRN_PASSWORD && export CAIRN_PASSWORD   # lab only
sudo -E ./preflight.sh                     # -E or the credential does not survive
```

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
| `REFUSED by <server>` | Usually not in DHCP Users. The error text names the call that failed |
| `NOT ASKED` | Something it depends on failed, or nothing configured it. **Not the same as refused** |
| `PARTLY PROVEN` | Some answered, some refused. **A result, not a failed run** — they need different rights, so one refusal does not stand in for the others |

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
