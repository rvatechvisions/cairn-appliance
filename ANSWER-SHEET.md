# Answer sheet

One page. What to set up, what to run, and what each answer means.

---

## Set up

| | |
| --- | --- |
| Domain controller | Holds DNS. DHCP running somewhere you can name |
| Service account | Ordinary domain user **+ DHCP Users**. Nothing else |
| Keytab | `ktpass` on a domain-joined Windows host → copy to appliance → `chmod 600`, `chown root:root` |
| Appliance | Debian/Ubuntu, **one interface**, **one resolver** (the customer's DNS) |
| Clock | Within five minutes of the DC |

## Run

```
sudo ./bootstrap.sh                      # installs, creates /etc/cairn-appliance (700)
sudo vi /etc/cairn-appliance/settings.env
sudo cp cairn.keytab /etc/cairn-appliance/ && sudo chmod 600 /etc/cairn-appliance/cairn.keytab
sudo ./preflight.sh
```

## What each answer means

| Line | Means |
| --- | --- |
| `FOUND: joined through realmd` | The domain manages this credential. Revoking it is disabling the computer object |
| `NOT JOINED` | A keytab somebody placed. Fine for a lab instrument; **not** a solution to the credential problem. Blocks nothing |
| `FOUND: a ticket was issued` | Kerberos works. The keytab matches the account and the clock is close enough |
| `REFUSED: no ticket` | Password changed since the keytab was made, or clock skew. Regenerate the keytab first |
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

## The keytab, and the one thing worth testing in the lab

**What ships is a deferral, not a solution.** A keytab at 600 in a 700
directory, with preflight refusing to run if either is wider, constrains which
local users can read it. It does not make the credential managed: it is
long-lived, the client's domain does not manage it, it does not rotate, and
revoking it means knowing it exists.

**The candidate answer is a real domain join** — `realmd` and `adcli`. The host
gets a machine account, the join tooling creates and rotates the keytab, and
revocation is disabling the computer object in AD. **Still a keytab on disk,
still not a gMSA**, but managed by the domain rather than by nobody.

Test it alongside the four capabilities. If it works, the objection that chose
Windows is answered and the decision genuinely changes. If it does not, the
objection holds and this stays a lab instrument.

If a review will not accept a keytab even under a machine account, the answer
is a Windows collector, not an argument.
