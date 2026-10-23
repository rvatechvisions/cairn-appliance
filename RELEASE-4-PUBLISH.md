# Release 4: publish steps

Staged by WO-1023-N125 item 5 on 23 October 2026. **Not before 28 October
2026**: CLAUDE.md's batching rule (WO-1018-N62 item 5) allows one release a
week, and release 3 was recorded on 21 October 2026. Every step runs from the
build machine, in `C:\dev\portal`, by the builder. Nothing here is Jackie's.

## What release 4 is

| | |
| --- | --- |
| Commit | `23325fce734f7981378ea07ab854ffd50f310ba6`, branch `held/wo-1021-n113-authorizations` |
| Binary | `HELD-preflight-23325fc`, sha256 `493b8f9b05121af7a464c9419f2da4d62023799a328d6ea2742d2a6dc696d99f`, 19,971,790 bytes, built twice, byte-identical |
| Manifest | `HELD-release-4-23325fc.json`, sha256 `edef3a74ca5df2fe0c9c5ed4ec8528f13b4180301d5a751a724dd8342e8e9a85`, `cairn-release/2`, sequence 4, expiring 2026-11-15T00:00:00Z (release 3's expiry, given, not computed) |
| Where they are kept | the Releases folder of the Cairn Build folder |

**What it carries:**
- the two DHCP authorization findings (`19bcacd`);
- the release-units fix (`838ca3f`);
- a run inside a release installing its own release's units (`7631479`), without which the units would never reach a box already on releases;
- the systemd units forced to LF (`23325fc`).

**The five files it lists, each equal to its committed blob:**

| Path | sha256 | Bytes |
| --- | --- | --- |
| `consent.sh` | `a3b8a6b70a81849444bf886c96363eed00c9b6491c633e75a7410dab9c45785b` | 4,192 |
| `preflight.sh` | `8977249a956c6434c2cdaec665a63a1154dc8a576152e5f123858c8ab37b7e48` | 154,660 |
| `run-window.sh` | `cc98cf2117267cbe0ece81d80519fbce02f1f183dd460f43cff61688d0d5ee00` | 3,461 |
| `systemd/cairn-preflight.service` | `1bb54c84c97ebe743ef1f2bfbbe88562af14fef5a76e0441e269c56201787031` | 3,601 |
| `systemd/cairn-preflight.timer` | `c8cd0d460991f41e445ec8d949890f45eef8581888193db5773a1e89a9173623` | 2,455 |

## Before anything is sent

1. **The date and the window.**
   - It is 28 October 2026 or later.
   - It is outside 09:00 to 11:20 UTC, the fallback span the deploy guard holds for RVA's box until it declares a window.
   - Nobody has said they are at the box.
2. **The appliance count.**
   - Read live rows of `appliance_bindings` (`revoked_at is null`) on production, and write the count in the report.
   - **One:** release 4 goes unsigned, under Jackie's waiver of 19 October 2026.
   - **More than one:** stop. The waiver is void, `recordRelease` would refuse it, and it needs Jackie's signature.
3. **The kept files.** Hash `HELD-preflight-23325fc` and `HELD-release-4-23325fc.json` and compare them with the table above. A difference stops everything.
4. **The actor.** Read the actor id from the `appliance.release_recorded` audit row of sequence 3, and use the same one. Do not type one from memory.

## Publish, hold, record

Each command rehearses first, then runs with `--apply`, as release 3's did.

5. **Publish the binary:** `npx tsx src/cli/upload-binary.ts <HELD-preflight-23325fc> --actor <actor id>`. Read back that the portal's current binary is `493b8f9b…`.
6. **Hold the five files.**
   - Take them from a clean detached worktree of `23325fc`. Check out the worktree after `23325fc`'s `.gitattributes` is in force, so the units are LF.
   - Before sending each one, check it against its committed blob.
   - Send each with `bash deploy/send-release-file.sh <file> <sha256> <bytes> <actor id>`, then again with `--apply`, using the sha256 and size in the table.
   - `consent.sh` and `run-window.sh` are already held from release 3 at the same digests, and the hold command takes a digest it holds as a no-op.
7. **Record:** `npx tsx src/cli/vm-run.ts deploy/record-signed-release.sh --args <manifest base64> unsigned edef3a74ca5df2fe0c9c5ed4ec8528f13b4180301d5a751a724dd8342e8e9a85 <actor id>`, then again with `--apply`. Read back release 4 as the newest row of `appliance_releases`, unsigned.
8. **The release row** in the portal repository's `APPLIANCE-BINARY-QUEUE.md`: items 6 and 8 and the units fix say *published and recorded*, with the times read.

## Read back afterwards, run by run

Times are the box's own runs, from its run reports. None is assumed.

9. **The first run after publishing stages release 4.** Its report names the staged sequence, as release 3's did at 09:13 UTC on 21 October.
10. **The run after that applies it.**
    - The run report carries release 4's binary, `493b8f9b…`, and script commit `23325fc`.
    - The box's output says `release: installed cairn-preflight.service from the current release`, and the same for the timer.
    - That run started under the old unit, so it still declares no window.
11. **The run after that declares the window.**
    - Its run report carries `CAIRN_WINDOW_OPENS_AT` 05:00 and `CAIRN_WINDOW_MINUTES` 75, with the box's own zone.
    - From then, the fallback span of 09:00 to 11:20 UTC retires for this box, as RETIRES-WHEN.md says.
    - The deploy guard reads the declared window instead (`src/cli/run-window-check.ts`).
12. **If step 10 says `could not install`,** the box keeps the unit it has and declares no window. That is a finding about the box, reported with the box's own words, and the fallback span stays.

So the window is declared on **the third scheduled run after publishing**, at the earliest. A release published on 28 October declares no window before 31 October.
