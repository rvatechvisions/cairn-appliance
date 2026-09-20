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
| `FOUND: a ticket was issued` | Kerberos works. The keytab matches the account and the clock is close enough |
| `REFUSED: no ticket` | Password changed since the keytab was made, or clock skew. Regenerate the keytab first |
| `FOUND: the directory answered` | The account can read AD |
| `REFUSED` on LDAP | The bind or the read failed. The reason is printed above the line |
| `FOUND: N zone(s)` | DNS is directory-integrated and readable |
| `NOT PRESENT` on DNS | The site's DNS is not AD-integrated. **A normal state, not a failure** |
| `bound: MS-DHCPM` then scopes | DHCP works. The account is in DHCP Users |
| `REFUSED by <server>` | Usually not in DHCP Users. The error text names the call that failed |
| `NOT ASKED` | Something it depends on failed, or nothing configured it. **Not the same as refused** |

## Three things to expect

**The DHCP probe will not build first time.** It has never been compiled —
no Go toolchain on the machine that wrote it. `cd preflight && go mod tidy &&
go build .` and correct the names the compiler objects to.

**Preflight asserts no expected count.** It will not tell you the site is
missing a DHCP server or a zone. It cannot know. It prints what answered.

**Nothing is submitted anywhere.** Preflight reads. It does not collect and it
does not upload.

## If a security review objects to the keytab

That is a reasonable objection: it is long-term key material in a file, where a
gMSA on Windows would rotate itself and never touch disk. The bounds are that
the account is an ordinary user plus DHCP Users — it cannot change anything
anywhere, checkable in their own directory — and the file is 600 in a 700
directory, with preflight refusing to run if either is wider.

If that is not enough for them, the answer is a Windows collector, not an
argument.
