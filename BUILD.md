# Building the probe

**Written 20 September 2026, at Jackie's instruction, because the Go half of
this appliance has changes that have never been through a compiler.**

The probe is the only part of `cairn-appliance` that is not a shell script.
Everything else runs as text; this is a binary, and a binary has to be built
somewhere.

---

## THE RULE: the appliance never compiles, and never holds push access

**Jackie's decision, 20 September 2026, and it is a rule rather than a
description of how things happen to be.**

- **The build machine is the GEEKOM workstation.** It has the toolchain, the
  repository and the tests.
- **The appliance never compiles.** It receives a binary whose digest the
  portal named, and refuses bytes that do not match.
- **The appliance never holds push access to its own repository.** A box on a
  customer's network that can write to the source of what every other box
  runs is a supply chain with a foothold in it.

**What this replaces.** Until now `preflight.sh` built the probe on every run,
on the appliance, from a checkout the appliance could also modify. That was
right while the appliance was a lab experiment and is wrong for a device we
place inside a client network: it means the bytes that read a directory were
produced on the box being trusted, from source nobody pinned, by a toolchain
nobody recorded.

**It is also what makes the digest pin mean anything.** *A binary nobody can
reproduce from a commit cannot be pinned to one* — and a binary the appliance
built itself cannot be pinned at all, because the thing being verified is the
thing that made it.

**The sections below are the build as it runs today**, on a machine with a
toolchain. They stay, because the build still has to happen somewhere and
these are the steps — what changes is **where**, and that the appliance is no
longer one of the answers.

---

## Build on the CAIRN VM, not on the workstation

**The workstation has no Go toolchain.** That is the whole reason this document
exists: wording changes were written into `preflight/main.go` and committed
without ever being compiled, which is a stronger version of *built, never run*
than the finding catalogue's entry 6 — there the code had at least been
exercised against fixtures.

**The CAIRN VM in the RVA lab is Linux and already runs the appliance**, and the
probe has compiled on it before: on 20 September 2026 it built, ran, and
returned subnets from a live DHCP server. So the toolchain, the module cache and
the outbound path to the module proxy are all known to work there.

**That is why a compile failure on that host is a statement about the code**,
which is what preflight's own refusal already says in terms: *THIS IS THE CODE,
NOT THIS HOST.*

---

## The steps

Run these on the CAIRN VM, as `azureuser`, from wherever the repository is
checked out.

### 1. Check whether Go is already there

```sh
go version
```

If it prints a version, skip to step 3. **It printed one on 20 September 2026**,
so the expected case is that this is already installed.

### 2. Install Go, only if step 1 found nothing

```sh
sudo apt-get update
sudo apt-get install -y golang-go
go version
```

**If you install from the upstream tarball instead, PREPEND to PATH — do not
append.**

```sh
export PATH=/usr/local/go/bin:$PATH     # correct
export PATH=$PATH:/usr/local/go/bin     # WRONG: an older go already on PATH wins
```

**This failed silently on the lab VM and looked like a failed install.** The box
already had go1.24.4 ahead on PATH, so appending left 1.24.4 winning and
`go version` reported the **old** toolchain after a successful install — the
install worked and the check said it had not. Corrected from the run rather than
rediscovered: an absence of change reads as a failure, and nothing in the output
named PATH.

**Do not download the tarball into the repository.** It leaves a ~70MB untracked
file in the working tree, which is how a dirty tree happens by accident on the
very build you want clean — and `deploy/build.sh` refuses untracked files for
exactly that reason. Fetch it to `/tmp`.

`go.mod` declares `go 1.22`. **Read what step 1 or step 2 actually printed
against that**: a toolchain older than the declared version fails the build with
a message naming both, which is a clear failure rather than a subtle one. If
Debian's packaged Go is older, install from the upstream tarball instead — and
record which was used, because *a build nobody can reproduce from a commit
cannot be pinned to one*.

### 3. Build

```sh
cd preflight        # THE MODULE IS HERE, NOT THE REPOSITORY ROOT
go build -o preflight .
```

**DO NOT RUN `go mod tidy`. Corrected 21 September 2026, after it cost an
hour in the middle of the first production enrolment.**

This step used to say `go mod tidy` and then `go build`, and that was right
while `go.mod` pinned nothing. **It stopped being right at `5fad13c`**, which
resolved the versions once and committed `go.mod` and `go.sum` — which is what
turns a resolution into a pin. `go.mod` says so in its own comment, directly
above the require blocks: *do not hand-edit go.sum*.

**What running it now costs.** `tidy` rewrites `go.mod` from the local module
cache, so the file differs from the committed one and the next `git pull
--ff-only` aborts with *your local changes would be overwritten by merge*.
On the lab box it also left an untracked `go.sum` that blocked the same pull a
second way. **Neither error mentions `tidy`**, so the reader is looking at git
while the cause is three lines up in this document.

**It is the superseded-instruction class in a numbered step**, which is the
worst place for it: somebody setting a box up runs the steps and reads the
paragraphs only when one fails. The pin landed, the prose around it was
rewritten, and the command in the fence was not.

**If you have already run it**, keep your copies rather than deleting them and
restore the committed ones:

```sh
mkdir -p ~/cairn-tidy-artifacts
cp preflight/go.mod ~/cairn-tidy-artifacts/go.mod.local
mv preflight/go.sum ~/cairn-tidy-artifacts/ 2>/dev/null || true
git checkout -- preflight/go.mod
git pull --ff-only
```

**When `tidy` is genuinely needed**: only when an import changes, and then the
rewritten `go.mod` and `go.sum` are committed in the same breath, so the pin
moves deliberately rather than drifting per machine.

**Every `go` command runs from `preflight/`.** From the repository root,
`go build ./...` answers *directory prefix . does not contain main module*,
which reads like a broken repository rather than a wrong directory. Observed on
the lab VM.

**`go.mod` pins every version and `go.sum` is committed beside it**, so a
build needs the network only to fetch modules it does not already have, and
never to decide which ones. That is the reverse of what this paragraph said
before `5fad13c`: it read *`go.mod` deliberately pins nothing*, which was
true of the design it described and false of the repository it sat in.

The failure it warned about is still real and now has a different cause:
`go build` refusing with *missing go.sum entry* for five correctly-imported
packages means `go.sum` is missing or was moved aside, not that a step was
skipped. Restore it from the repository rather than regenerating it.

These are the same two commands `preflight.sh` runs, in the same order, from the
same directory. **Running `preflight.sh` builds the probe too** — it always
rebuilds, deliberately, because a run that used yesterday's binary reports on
code it did not execute. Building by hand is for when you want the compiler's
output on its own, without a domain read after it.

### 4. Read the artifact rather than the exit code

```sh
ls -l preflight
./preflight -h
```

**The binary lands at `preflight/preflight`** — inside the `preflight`
directory, named the same as it. A build that reports success and leaves no file
is a state preflight already refuses on, and it is worth knowing the shape:
`-o preflight` writes relative to the working directory, so running the build
from the repository root puts it somewhere nothing looks for it.

### 5. Verify the build matches the commit

```sh
git --no-pager rev-parse HEAD
git --no-pager status --porcelain
sha256sum preflight/preflight
```

**`git --no-pager`, and it is not cosmetic.** On the lab VM a `git diff` opened
`less`, which **swallowed every queued command after it** — the session looked
hung and then executed fragments of what had been typed into the pager. Anything
in this document is written to be pasted as a block, so every git command here
disables the pager. `-c core.pager=cat` does the same job.

**All three, and the middle one is the one that matters.** A clean
`git status` is what makes the first line meaningful: a hash with a dirty tree
names a commit the binary was not built from, which is the `v1.59`-to-`v1.63`
failure in a smaller medium.

**Record the three together.** The commit says what the source was, the porcelain
says the source was only that, and the checksum names the bytes that came out.

---

## OPEN: what user does the appliance run as, and why

**Raised 20 September 2026 as an open item, not a change. Do not alter it
tonight — the RVA run must happen against the box as it stands.**

**The clone lives in `/root`, mode 700, and the build runs as root.** The
unprivileged `cairn` user on the same VM cannot reach it. **Nobody decided
that**: it is where the bootstrap happened to put it.

**Why it is a question rather than a tidy-up.** For a device we place inside a
client's network, *what user does this run as and why* is a security-review
question we will be asked — and the current answer is **"root, by accident"**,
which is a bad answer even where the arrangement turns out to be right. It is
the same shape as a default branch: correct for the case that exists, invisible
at the point it was chosen, and nobody wrote it down.

**It also sits awkwardly beside a decision already taken.** *A collector must
not be a member of the trust boundary it reads* was argued on where the
collector sits; this is the same question one level in — what it can reach on
its own host. The appliance holds a directory credential in memory during a
run, so the blast radius of the account it runs as is part of the same
argument.

### The options, so the decision is one step

| | Arrangement | What it costs |
| --- | --- | --- |
| **A** | **Leave it.** Root, `/root`, mode 700 | Nothing to do. The honest defence is that a collector reading a directory needs its credential protected from other local users, and 700 under root does that. The weakness is that it was never argued — and *safe by arrangement* is a class this project already names |
| **B** | **Run as `cairn`**, clone under its home | Least privilege, and the answer a reviewer expects. Costs: the Kerberos cache in `/dev/shm` and every file mode has to be re-reasoned for a non-root user, and `preflight.sh` currently refuses unless the key is `600 root:root` |
| **C** | **Root for the run, `cairn` for the service** | Closest to how a Windows collector under a gMSA is described. Most work, and the split has to be real rather than cosmetic |

**No recommendation is offered, deliberately.** The reasoning above is about
the shape of the question rather than the answer, and the person who has to
defend it in a review is the one who should pick. What it must not be is
undecided at the point a client asks.

---

## Why the checksum is in this document rather than a nicety

**It is the input to the update decision.** The appliance's update channel is a
pinned **digest**, not a tag: the portal names an artifact, and the appliance
**refuses to run** bytes whose digest does not match, submitting the mismatch as
a finding. See `APPLIANCE-DAILY.md`.

**A binary nobody can reproduce from a commit cannot be pinned to one**, so the
build step and the digest pin are one piece of work rather than two. A checksum
taken from a dirty tree, or from a toolchain nobody recorded, pins bytes to
nothing.

**What is not claimed here:** that these steps produce a *byte-identical* binary
on two different hosts. Reproducible Go builds need the toolchain version, the
module versions and the build flags all held, and none of that has been
established for this project. What step 5 gives is weaker and still useful — the
bytes that a named commit produced on a named host, written down.

---

## What this document has done, and the four things the first run corrected

**~~Nobody has run these steps as written.~~ Somebody has.** Jackie ran a build
on the lab VM on 20 September 2026, and the four corrections below are folded in
above — each **observed in that run** rather than reasoned about afterwards.

**The thing it set out to prove is proven**: `preflight` on go1.27.1 answered
**6 found, 0 refused, 0 not asked** — the same six as the go1.24.4 run. The
uncompiled wording changes compile, and `go vet` was silent and
`go mod verify` reported all modules verified.

**The caveat is struck rather than deleted**, because a document that quietly
stops disclaiming looks the same as one that was always right. What is *still*
not claimed is byte-identical reproducibility across hosts — that needs the
toolchain version, module versions and build flags all held, and none of that is
established.

### And it confirmed the rebuild is unconditional

From the run, verbatim:

```text
--- 5. DHCP over MS-DHCPM ---
building the DHCP probe...
  built: 2026-09-20 18:48:24
```

**It rebuilt on a box that already had a current binary.** That is the property
`preflight.sh` claims in its own comment — always build, because a run that used
yesterday's binary reports on code it did not execute — and it is now read
rather than asserted.
