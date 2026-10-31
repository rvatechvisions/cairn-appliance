# Release 5: publish steps

Staged by WO-1031-N138 item 4 on 31 October 2026. **Not before 4 November
2026**, and that date is the whole reason this is a staged document rather than
a published release — see the next section. Every step runs from the build
machine, in `C:\dev\portal`, by the builder. Nothing here is Jackie's.

## Why it is staged and not published

**WO-1031-N138 item 4 orders the release published. CLAUDE.md's batching rule
forbids it today, and the rule holds.**

- **The rule** (WO-1018-N62 item 5, the order author's): *appliance releases
  are batched so that Jackie is asked for at most one release signature a week.
  A release goes sooner only for a Warden finding rated high or medium, and the
  card says so.*
- **Release 4 was recorded 2026-10-28T12:57:59.587Z**, read from production on
  31 October 2026. A week from there is **4 November 2026**.
- **What release 5 carries is not a Warden finding.** It is one commit,
  `a917f3b`, the ClientUID length histogram — WO-1030-N137 item 6, a defect in
  Cairn's own reporting of a probe, built on fixtures. Nothing in it is rated
  high or medium by Warden, and no card says so.

So the exception does not apply and the cadence does. *Report the contradiction,
do not resolve it*: the order and the rule disagree, the rule is the absolute
one, and **both were written by the order author**, so it is theirs to settle.
**It costs nothing to wait.** The deadline Jackie set is Friday 6 November, and
4 November is inside it.

**If the order author wants release 5 sooner, that is one line from them** and
every figure below is already measured, so publishing is the commands in
*Publish, hold, record* and nothing else.

## What release 5 is

| | |
| --- | --- |
| Commit | `614a2cf6963e0fd2c32d88caf27f2808129e5a33`, branch `held/wo-1021-n113-authorizations` |
| Binary | `HELD-preflight-614a2cf`, sha256 `007e1669a34c83cd765de6f9cfe31b67fa6c0065c2ec89cd29cfff89b64f49ee`, 19,980,987 bytes, built twice, byte-identical |
| Manifest | `HELD-release-5-614a2cf.json`, sha256 `8a32e11c191d9efd26e921e54b35640f3e47488c02933fe0d8f87aeed4c60b9e`, `cairn-release/2`, sequence 5, expiring 2026-11-15T00:00:00Z |
| Where they are kept | the Releases folder of the Cairn Build folder |

## The first attempt at release 5 was withdrawn, and this is why

**A release was staged on `a917f3b` and withdrawn the same hour**, kept in the
Releases folder as `WITHDRAWN-spellcheck-preflight-a917f3b` and
`WITHDRAWN-spellcheck-release-5-a917f3b.json` rather than deleted, the way
release 4's CRLF attempt is kept.

`a917f3b` fails `spellcheck-test.sh`. Its histogram heading printed
`CLIENTUID` in capitals, and cspell cannot split an all-caps compound the way
it splits `ClientUID` in the body text two lines below, so an operator-facing
word was not US English. The commit's own message said it was built on
fixtures and said nothing about the suite.

**It was found by running the suite before staging, and by nothing else.** The
binary had already been built twice, byte-identical, and the manifest written
— every digest in the first attempt was correct and the commit underneath it
was not. *A reproducible build of a commit that fails its tests is a
reproducible wrong answer.*

So the lesson is the order of the steps rather than the fix, which was one
character of case: **run the appliance's own suite against the commit before
building a release from it.** `bash run-tests.sh` (30 of 30) and
`go test ./...` (ok), both from the appliance checkout, both green at
`614a2cf` on 31 October 2026.

**And the batching rule is what bought the time to find it.** Had release 5
gone out today as item 4 asked, the suite would have been run after publishing
or not at all.

**What it carries:** two commits — `a917f3b`, the ClientUID length histogram,
and `614a2cf`, the heading's spelling. The
probe reported the histogram as unrecorded *because no lease had come back*,
and nothing would have recorded it if one had — so the sentence was true and
the reason was wrong. Each length now carries how many parsed and how many were
refused, **because 11 bytes can be both**.

**It is the first binary-only release.** The five listed files are byte for byte
what release 4 holds — verified from a clean detached worktree of `614a2cf` on
31 October 2026, every digest and size equal to release 4's table:

| Path | sha256 | Bytes |
| --- | --- | --- |
| `consent.sh` | `a3b8a6b70a81849444bf886c96363eed00c9b6491c633e75a7410dab9c45785b` | 4,192 |
| `preflight.sh` | `8977249a956c6434c2cdaec665a63a1154dc8a576152e5f123858c8ab37b7e48` | 154,660 |
| `run-window.sh` | `cc98cf2117267cbe0ece81d80519fbce02f1f183dd460f43cff61688d0d5ee00` | 3,461 |
| `systemd/cairn-preflight.service` | `1bb54c84c97ebe743ef1f2bfbbe88562af14fef5a76e0441e269c56201787031` | 3,601 |
| `systemd/cairn-preflight.timer` | `c8cd0d460991f41e445ec8d949890f45eef8581888193db5773a1e89a9173623` | 2,455 |

**So step 6 is a no-op for every file**, since the portal already holds all five
at these digests from release 4 and the hold command takes a digest it holds as
a no-op. The manifest still lists them, because a release names every file the
box runs rather than only the ones that changed — a box staging release 5 must
be able to check its whole set.

**The expiry is given, never computed**, as the manifest writer requires. It is
release 4's expiry, unchanged: **2026-11-15T00:00:00Z**. Said plainly because
it is short — published on 4 November it leaves **eleven days** — and extending
it is a decision for whoever publishes, not an arithmetic step. Nothing here
computes a date from a start and a duration.

## Before anything is sent

1. **The date and the window.**
   - It is 4 November 2026 or later. **If it is not, stop** and read the section
     above.
   - It is outside the box's **declared** run window, not a UTC figure: box
     `3131a26a` declares 05:00 for 75 minutes in `America/New_York`, read
     31 October 2026. `src/cli/run-window-check.ts` reads it from the box's own
     newest run; ask it rather than converting by hand. **US daylight time ends
     on 1 November 2026**, which is exactly why the declaration is read and not
     a span.
   - Nobody has said they are at the box.
2. **The appliance count.**
   - Read live rows of `appliance_bindings` (`revoked_at is null`) on
     production, and write the count in the report.
   - **One:** release 5 goes unsigned, under Jackie's waiver of 19 October 2026.
   - **More than one:** stop. The waiver is void, `recordRelease` would refuse
     it, and it needs Jackie's signature.
3. **The kept files.** Hash `HELD-preflight-614a2cf` and
   `HELD-release-5-614a2cf.json` and compare them with the table above. A
   difference stops everything.
4. **The actor.** Read the actor id from the `appliance.release_recorded` audit
   row of **sequence 4**, and use the same one. Do not type one from memory.

## Publish, hold, record

Each command rehearses first, then runs with `--apply`, as release 4's did.

5. **Publish the binary:** `npx tsx src/cli/upload-binary.ts <HELD-preflight-614a2cf> --actor <actor id>`.
   Read back that the portal's current binary is `007e1669…`.
6. **Hold the five files.** Every one is already held at its digest from
   release 4, so each send is a no-op — **run them anyway and read that each
   says so**, because *a check that only runs when things went well cannot see
   what goes wrong*, and a file silently absent from the portal's store would
   stop a box mid-stage.
7. **Record:** `npx tsx src/cli/vm-run.ts deploy/record-signed-release.sh --args <manifest base64> unsigned 8a32e11c191d9efd26e921e54b35640f3e47488c02933fe0d8f87aeed4c60b9e <actor id>`,
   then again with `--apply`. Read back release 5 as the newest row of
   `appliance_releases`, unsigned.
8. **The release row** in the portal repository's `APPLIANCE-BINARY-QUEUE.md`.

## Read back afterwards, run by run

Times are the box's own runs, from its run reports. None is assumed.

9. **The first run after publishing stages release 5.** Its report names the
   staged sequence.
10. **The run after that applies it.** The run report carries release 5's
    binary, `007e1669…`, and script commit `614a2cf`.
    - **The units do not change**, so nothing here should say it installed a
      new one. Release 4 already installed the current units and release 5's
      are the same bytes.
11. **The window stays declared.** Release 5 changes neither the timer nor the
    service, so the declaration read on 31 October should persist unchanged:
    05:00, 75 minutes, `America/New_York`. **A run that stops declaring one is
    a finding**, not a return to the fallback by design.
12. **The histogram is the point of the release, and it is read last.** The
    ClientUID length histogram should appear in the run's DHCP reporting with,
    per length, how many parsed and how many were refused. **Card
    1219426768519028 closes on that read and not on the publish** — a published
    release is not a reading, and *committed is not shipped* applies to a box
    exactly as it does to a container.
    - **If no lease comes back, the histogram is empty and that is not the
      fix failing.** The defect was that an empty histogram was reported as
      *unrecorded because no lease had come back* while nothing would have
      recorded one either way. The fix is that a lease which does come back is
      now counted. So the read that closes the card needs a run whose DHCP
      step returned at least one lease, and if none does, that is what the
      report says rather than calling the release unverified.

## What this release does not carry

The held branch holds nothing else unpublished: `614a2cf` is its tip, and
release 4 carried everything before it. So release 5 is two commits, and the
batching rule costs four days rather than a queue.
