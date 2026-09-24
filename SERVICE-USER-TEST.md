# Proving "nothing needs root", before changing anything

**Written 20 September 2026. Jackie runs these on the lab box; nothing here
changes the box.**

**The premise is still reasoning.** The design — code in `/opt/cairn`,
root-owned and read-only to the service user; key readable by that user only; a
separate root-owned updater; the service user runs — rests on *nothing in a
collection run needs root*. **That has not been measured**, and this project's
own rule is that a claim about behaviour is a read rather than an argument.

**So: run it as an unprivileged user against RVA, as the box stands today, and
report what refuses.** Anything that refuses is a finding. **Name it; do not
route around it.**

---

## The commands

Run as root to set up, then as the unprivileged user to test.

```sh
# A throwaway user with no privileges and no shell login.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin cairn-test

# Let it READ the repository where it currently sits. Nothing is moved, and
# this is the smallest change that lets the test run at all.
sudo chmod o+rx /root                      # traversal only
sudo chmod -R o+rX /root/cairn-appliance

# The run. Everything it cannot do will refuse.
cd /root/cairn-appliance
sudo -u cairn-test ./preflight.sh 2>&1 | tee /tmp/preflight-as-cairn-test.txt
echo "exit: $?"
```

**Put `/root` back afterwards**, because the traversal bit above is the one
thing here that loosens the box:

```sh
sudo chmod o-rx /root
sudo userdel cairn-test
```

---

## What to watch for, named in advance so a refusal is recognised

**Named rather than discovered, because a refusal that arrives in the middle of
forty lines of output reads as noise.** Four are expected. **A fifth is the
interesting result.**

| | What | Why it should refuse |
| --- | --- | --- |
| 1 | Reading `/etc/cairn-appliance/appliance.key` | Mode 600, owned by root. The service user cannot read it, and **preflight also refuses to continue unless the key is `600 root:root`** — so this may fail twice, once on the permission and once on the check |
| 2 | The `/dev/shm` ccache directory | `mktemp -d` there should work for any user, and `chmod 700` makes it private to whoever created it. **This one is expected to PASS**, and if it refuses the design needs a different place for the cache |
| 3 | ~~The build step~~ **WITHDRAWN 24 September 2026** | It wrote into the module cache and into the probe, and the repository being root-owned was the thing expected to refuse it. **There is no build step any more**: the appliance neither compiles nor obtains a compiler, so the row it was testing is gone rather than passing |
| 4 | Any write under the repository | Same cause as 3 |
| 5 | **Anything else** | The point of running it |

---

## What each result means, decided before the run rather than after

**Because a result you interpret afterwards is one you interpret to suit.**

- **Only 1, 3 and 4 refuse** — the premise holds. Each has a place in the
  design already: the key's mode changes to the service user, and the build
  leaves the appliance entirely.
- **The ccache refuses** — the design needs a different private directory, and
  that is a real change rather than a detail.
- **Something in the Kerberos, LDAP, DNS or DHCP path refuses** — **the premise
  is wrong** and the design has to answer why. Those four are the actual work;
  if any of them needs root, "Cairn does not run as root" is not a claim we can
  make.

**Report what refused, not whether it worked.** A run that ends with six found
is not the question — the question is the list.

---

## Sequencing, because two changes touch the same files

**The self-compilation removal and the service-user change both edit
`preflight.sh`, and the lab box must not be half-migrated overnight.**

So: **the service-user change waits for the signed binary.** Reasons, in order
of weight:

1. **Finding 3 is removed by the signed binary rather than worked around.** If
   the service user cannot build, and the appliance stops building at all, the
   refusal disappears instead of being accommodated. Doing the user change
   first would mean inventing a permission arrangement for a build that is
   about to be deleted.
2. **The test above needs no change to run**, so nothing is blocked by waiting.
3. **A half-migrated box is worse than either state**, and the RVA run has to
   happen against something whose arrangement is understood.

**What is not waiting: this test.** It can run tonight, and it is the thing
that decides whether the design survives contact.

---

## Recorded with the design: Atera runs as root regardless

**RVA's Atera agent runs as root on this box, and that is not changed by any of
this.** It is RVA's management channel and is stated as such rather than
quietly excluded from the claim.

**The claim is narrower and is the one we can defend: *Cairn* does not run as
root.** A client asking *what does your box run as* is asking about the thing
we are placing there, and the honest answer names both — ours, unprivileged,
and the management agent that is there for the same reason it is on every other
machine they let us manage.

**A narrower sentence that is true beats a broader one that needs a
footnote**, which is the same move as the assessment script's *read-only
against the domain*.

### Verified against Atera’s own documentation, 20 September 2026

**This entry was written from what Jackie said and is now backed by the
vendor**, which is the difference between a recollection and a citation. What
Atera documents:

| | |
| --- | --- |
| Where it runs | A systemd unit, `/etc/systemd/system/AteraAgent.service` |
| What it needs | Administrative privileges; the installer must be run with admin permissions |
| Under a local user account | **Not supported** |
| Prerequisites | `sudo` and `lshw` installed and enabled |
| Officially supported | Debian 11 and above, Ubuntu 18 and above, CentOS Stream, RHEL 8 and above |
| Other distributions | May work. No guarantee, no support, no bug fixes, no security patches |

**So the root claim is the vendor’s, not ours.** *Running the agent under a
local user account is not supported* is Atera’s sentence about Atera’s
software. Nothing in this design can change it, and a proposal that assumed
otherwise would have been arguing with a supplier rather than making a
decision.

### What this does to the premise of the unprivileged-user work

**The premise was never *nothing on this box runs as root*, and it is worth
being exact about that before the work is done.** On a box carrying RVA’s
management agent, something already does, by the supplier’s design. A client
auditing the appliance will find a root-privileged systemd unit whatever we
do with ours.

**That does not retire the work; it fixes what the work is for.** The claim
being bought is not *this box runs nothing as root* — which would be false on
the day it was made — but *the thing Cairn puts here does not need root, and
does not have it*. That is a claim about our own software, it is one a client
can check with `systemctl show`, and it survives the agent sitting beside it.

**A premise corrected before the work is cheaper than one corrected after**,
and this is the *revisited decision* rule applied early: the reasoning for an
unprivileged collector is sound and it was resting on a stated premise that
is false. The argument is re-run against the real situation rather than
discarded, and it comes out narrower and defensible.

### The limit on this read, stated rather than promoted

**Debian 13 is not named by Atera. It is covered by *and above*, which is my
reading rather than their sentence.** The lab box runs 13. Two independent
searches returned the same supported list and neither quoted a version 13, so
what is established is that 13 falls inside the documented range — not that
Atera has tested it.

**Atera’s support pages refuse an automated fetch** — HTTP 403 on both the
install article and the blog post — so this is read from search summaries of
those pages rather than from the pages. **A one-click confirmation from
inside Atera beats all of it**, and that is Jackie’s to make: the install
screen names what it supports.

**And `lshw` is a prerequisite nothing here installs.** `bootstrap.sh`
installs what the *collector* needs, which is correct — the management agent
is not Cairn’s dependency and must not become one. Named so that an agent
that installs and then reports nothing has an obvious first thing to check.
