# Building the probe

**Written 20 September 2026, at Jackie's instruction, because the Go half of
this appliance has changes that have never been through a compiler.**

The probe is the only part of `cairn-appliance` that is not a shell script.
Everything else runs as text; this is a binary, and a binary has to be built
somewhere.

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

`go.mod` declares `go 1.22`. **Read what step 1 or step 2 actually printed
against that**: a toolchain older than the declared version fails the build with
a message naming both, which is a clear failure rather than a subtle one. If
Debian's packaged Go is older, install from the upstream tarball instead — and
record which was used, because *a build nobody can reproduce from a commit
cannot be pinned to one*.

### 3. Build

```sh
cd preflight
go mod tidy
go build -o preflight .
```

**`go mod tidy` comes first and it needs the network once.** `go.mod`
deliberately pins nothing — the require line and the checksums are written from
the imports on first build, which is the only way a version here is read rather
than recalled. Without it, `go build` refuses with *missing go.sum entry* for
every import, naming five packages that are all correct, and sends the reader to
the imports instead of to the missing step.

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
git rev-parse HEAD
git status --porcelain
sha256sum preflight/preflight
```

**All three, and the middle one is the one that matters.** A clean
`git status` is what makes the first line meaningful: a hash with a dirty tree
names a commit the binary was not built from, which is the `v1.59`-to-`v1.63`
failure in a smaller medium.

**Record the three together.** The commit says what the source was, the porcelain
says the source was only that, and the checksum names the bytes that came out.

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

## What this document has not done

**Nobody has run these steps as written.** They are the commands `preflight.sh`
already executes, plus the reads around them, assembled into an order a person
can follow — and assembling is not running. *A validator passing is not the same
as the thing being right*, and neither is a document.

**The first run is the proof**, and the thing it proves first is whether the
uncompiled wording changes in `preflight/main.go` compile at all.
