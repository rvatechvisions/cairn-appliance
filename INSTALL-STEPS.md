# Installing a Cairn appliance on a client's network

**Steps a person follows once, at a client's site, with a shell on the box.**

Written 23 September 2026, after the schedule design was ruled on — deliberately
in that order, because these steps are a description of what that design
decided, and a numbered list written first is a numbered list somebody executes
after it has stopped being true.

> **What this is.** A Linux VM on the client's network that reads their
> directory, DNS and DHCP, and reports what it reached. It collects nothing
> else, it changes nothing on the domain, and it holds no credential on disk.
>
> **What it is not.** It is not joined to the domain. *A collector must not be
> a member of the trust boundary it reads* — a joined box takes that domain's
> policy and sits inside its blast radius, which turns a reader into a
> foothold.

---

## Before you go

**Have these, or the visit stalls:**

| | |
| --- | --- |
| A Linux VM on the client's network | Debian or Ubuntu. Two cores and 2 GB is plenty |
| Reachability | It must reach the client's domain controllers, and it must reach the portal over https |
| A service account in the client's directory | Read-only. **You never see the password** — see below |
| A registration key | Generated in the portal, on the client's collector card, **when you are already at the box** |

**You never handle the client's credential.** Not in a ticket, not in a
message, not in a file you place. The client's administrator enters it into the
portal themselves; the box fetches it per run, uses it from memory and drops
it. If somebody offers you the password, the arrangement has already gone
wrong — stop and say so.

---

## 1. Get the code onto the box

```
sudo mkdir -p /opt/cairn-appliance
sudo git clone https://github.com/rvatechvisions/cairn-appliance /opt/cairn-appliance
```

It is a public repository on purpose: the client can read every line of what
you are asking them to run.

## 2. Prepare the host

```
cd /opt/cairn-appliance
sudo bash bootstrap.sh
```

`bootstrap.sh` installs the packages a run needs (Kerberos, LDAP and DNS
tools, `jq`) and creates `/etc/cairn-appliance`. **It builds nothing.** The
appliance has had no compiler since 24 September 2026 and never obtains one;
if `bootstrap.sh` reports a `go` on the box, that is a finding, not a
prerequisite.

**If it refuses, read the refusal and stop.** It is written to say what it
could not do rather than to carry on with less.

> **CORRECTED 1 October 2026 (WO-1001-D item 5).** This step said
> *`bootstrap.sh` installs what the build needs and builds
> `preflight/preflight`*. It had not built anything since 24 September, and a
> runbook naming a step that cannot work is setup guidance invented after the
> fact. The binary is installed by step 2b.

## 2b. Install the binary the portal publishes

**The portal publishes, you carry, the box verifies.** The appliance never
compiles and never fetches executable code from anywhere but the portal; you
carrying the portal's published file onto the box makes it fetch nothing, and
the box checks the file against the digest the portal published before it is
put where anything runs it.

**On your own machine, signed in to the portal as staff:**

1. Open the client's collector card on **Integrations**. Under *Appliances* it
   says *The binary Cairn offers is built from …, SHA-256 …* and prints the
   digest **whole**.
2. Press **Download it**. The file is named `preflight-` and the first twelve
   characters of that digest.
3. Copy the file to the box (for example with `scp`, into `/tmp`). Leave the
   card open: you will type the digest from it.

**On the box:**

```
cd /opt/cairn-appliance
sudo ./install-binary.sh /tmp/preflight-<first twelve> <the whole SHA-256 from the card>
```

**Read the two lines it prints, one above the other** — the digest you typed
and the digest of the file you carried. They must be the same.

- **If they match**, it says `INSTALLED`, prints what the binary now says
  about itself and its SHA-256, and keeps the binary it replaced beside it as
  `preflight/preflight.previous`.
- **If they do not match, it refuses, loudly, and installs nothing.** The
  binary already on the box is left exactly as it was, and the refusal says
  which one that is. The file is not the one the portal published, or it was
  damaged on the way: download it again from the card. **Do not run it, and do
  not work around the refusal** — the comparison is the whole of what makes the
  file trustworthy.

It also refuses a matching binary too old to read the consent list the portal
sends, because `preflight.sh` would refuse to run it.

> **`-update` is the maintenance path, not the install path.** Once a box
> runs a published binary that has it, `preflight/preflight -portal <url>
> -update` fetches the current binary over the box's own signed channel and
> checks it against the published digest itself. A box whose binary predates
> `-update` cannot reach a newer one that way, which is why this step exists
> and why it stays.

## 3. Tell the box which portal it reports to

```
sudo ./set-portal.sh https://portal.rvatechvisions.com
```

It prints the line it wrote. Read it back before moving on.

## 4. Generate a key in the portal, and redeem it here

**In the portal**, on this client's collector card, press **Generate a
registration key**. It appears once, in that response.

**Do not mail it, paste it into a ticket, or write it to a file.** Type it at
the box.

**On the box:**

```
sudo ./enroll.sh
```

It asks for the key rather than taking it on the command line, so it does not
land in shell history. It generates this box's keypair here; only the public
half is ever sent.

**Then compare the fingerprints by eye** — the one the card shows and the one
the box printed. **That comparison is the only thing standing between a stolen
key and an appliance nobody placed.** If they differ, stop.

## 5. Run it once, by hand, and read what it says

```
sudo ./preflight.sh
```

**This is the step that tells you whether the visit worked.** It prints what it
reached, what refused it, and what it was never asked to do — three states, and
the third is not a failure.

**A refusal here is a finding about the client's network, not a broken
install.** Take the refusal text with you; it is the conversation to have with
their directory administrator.

**It reports to the portal**, and the card stops saying *Not yet verified*.

> **This run declares no schedule, and that is correct.** A hand run is not a
> schedule. The card will say no collection schedule is recorded — nothing is
> due and nothing is late — until step 6.

## 6. Put it on the timer

```
sudo cp systemd/cairn-preflight.service /etc/systemd/system/
sudo cp systemd/cairn-preflight.timer   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cairn-preflight.timer
```

**The timer runs the same script you just ran by hand**, at the same path. What
you tested is what runs at five in the morning.

**Check it took:**

```
systemctl list-timers cairn-preflight.timer
```

It prints when it next runs. **Daily, early, in this box's own time zone**,
with up to forty-five minutes of random delay so that every appliance across
every client does not hit the portal in the same second.

**If the box is off overnight it runs once when it comes back**, rather than
skipping to the next morning.

## 7. Confirm in the portal, the following day

The collector card should now say when the box last submitted **and that it is
expected daily**. That second half is what step 6 bought: the box tells the
portal its schedule, so the portal can say whether it is late.

**If the card still says no schedule is recorded**, the timer has not run yet —
it declares the schedule when it runs, not when it is enabled. Either wait for
the morning or force one:

```
sudo systemctl start cairn-preflight.service
```

---

## Changing the schedule later

**Two files, and they must move together:**

- `cairn-preflight.timer` — `OnCalendar`, which is when it actually runs;
- `cairn-preflight.service` — `CAIRN_INTERVAL_MINUTES`, which is what the box
  tells the portal.

A timer moved to weekly with the service still declaring daily would have the
portal call the box late six days out of seven. **The portal records when the
declared number last changed and the card prints it**, so a change is visible
rather than silent — but it cannot notice a change nobody made to the half that
is declared.

```
sudo systemctl daemon-reload
sudo systemctl restart cairn-preflight.timer
```

---

## Taking it out

**In the portal**, revoke the appliance on the card. The box stops being able
to fetch a credential from the next run.

**On the box:**

```
sudo systemctl disable --now cairn-preflight.timer
```

**Revoking is the half that matters**, and it is one action in a system we
control. The box can be left switched off; it cannot do anything without a
credential it can no longer fetch.

---

## If something is wrong

| What you see | What it means |
| --- | --- |
| `enroll.sh` refuses | A key already exists here. Revoke on the card first, then re-enrol with a **new** key. A revoked registration is never re-armed |
| preflight refuses on the key's permissions | The appliance key must be `600 root:root`. A key any local user can read is this box's identity readable by anybody with a shell |
| A capability says *refused* | The client's directory said no. That is a finding, and it is the conversation to have with their administrator |
| A capability says *not asked* | Nothing told the box to try. That is a gap in what it was told, not a failure of the box |
| The card says *Not yet verified* after step 5 | The run did not reach the portal. The run itself still stands — what it reached printed on your screen |
| preflight says *NOT RUN: the installed binary is too old to hear the consent list* | The binary predates the scripts. Install the published one by step 2b. Nothing was asked of the portal or the domain, and nothing about the client is implied |
| `install-binary.sh` refuses: *THE FILE DOES NOT MATCH* | The file you carried is not the one the portal published. Download it again. The installed binary was not touched |

**Nothing in this list is fixed by running it again and hoping.** Each line is
a different thing to go and look at.
