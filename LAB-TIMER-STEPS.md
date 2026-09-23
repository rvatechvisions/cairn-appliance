# Putting the lab box on the timer

**For Jackie, at the lab box. 23 September 2026.**

> # THIS IS THE FIRST TEST OF THE SCHEDULE PATH ON REAL HARDWARE.
>
> Every part of it has been tested against an embedded database and against
> fixtures. **None of it has ever run on a timer on a real box, and no
> collection in this project's history has ever started without somebody
> starting it.**
>
> So the point of this is not to get a timer working. It is to find out what
> the schedule path does on hardware — and **a step that fails here is the
> whole return on doing it at the lab box rather than at a client.**

**This is the lab box only.** It is already enrolled and it already runs
`preflight.sh` by hand.

## What NOT to do

| | |
| --- | --- |
| **Not a client box.** | Not Floyd, not anywhere. The client install is a different document and it waits on this one |
| **Do not touch the enrolled key.** | No `enroll.sh`, no regenerating, no revoking. The binding this box already has is what makes the test meaningful — a fresh key would test enrolment instead |
| **Do not edit `preflight.sh`.** | If the run is wrong, that is the finding |

---

## 1. Get the new code onto the box

```
cd /opt/cairn-appliance
sudo git pull --ff-only
```

**Expect:** it fast-forwards and brings a new `systemd/` directory.

**If it refuses to fast-forward**, something has been edited on the box. Stop
and say so — that is worth knowing before anything else.

## 2. Copy the two unit files

```
sudo cp systemd/cairn-preflight.service /etc/systemd/system/
sudo cp systemd/cairn-preflight.timer   /etc/systemd/system/
sudo systemctl daemon-reload
```

**Expect:** silence. `daemon-reload` prints nothing when it works.

**If `daemon-reload` complains**, a unit file has a syntax error. The message
names the file and the line. That would be my mistake, not the box's.

## 3. Look at what the units say before enabling anything

```
systemctl cat cairn-preflight.timer
systemctl cat cairn-preflight.service
```

**Expect:** the timer says `OnCalendar=*-*-* 05:00:00`, `Persistent=true`,
`RandomizedDelaySec=45min`. The service says
`Environment=CAIRN_INTERVAL_MINUTES=1440` and
`ExecStart=/opt/cairn-appliance/preflight.sh`.

**Read that ExecStart line.** It is the same path you run by hand, deliberately
— what you have been testing is what the timer will run.

**If `CAIRN_INTERVAL_MINUTES` and the `OnCalendar` disagree**, stop. They are
two halves of one fact, and a timer running weekly while the service declares
daily would have the portal call this box late six days out of seven.

## 4. Enable it

```
sudo systemctl enable --now cairn-preflight.timer
```

**Expect:** a line saying a symlink was created. `--now` starts the *timer*, not
a run — nothing collects yet.

**If it fails to enable**, read the error. A missing `[Install]` section is the
usual cause and would be mine.

## 5. Confirm it is armed and see when it fires

```
systemctl list-timers cairn-preflight.timer
```

**Expect** a row with:

- **NEXT** — tomorrow at 05:00 plus up to 45 minutes;
- **LEFT** — how long until then;
- **LAST** and **PASSED** — a dash, because it has never run;
- **UNIT** and **ACTIVATES** — `cairn-preflight.timer` and
  `cairn-preflight.service`.

**If NEXT is blank or the row is missing**, the timer is not armed. Nothing
will happen overnight and the rest of this is moot.

**The random delay means NEXT is not 05:00 exactly.** That is correct and it is
the point: every appliance across every client firing in the same second is how
the submission endpoint starts refusing.

## 6. What the card says right now

**Open the portal, this box's collector card.**

**Expect, before the first timed run:**

> *No collection schedule is recorded for it yet, so nothing is due and nothing
> is late.*

**That is correct and it is not a failure of step 4.** The box declares its
schedule **when it runs**, not when the timer is enabled — because the thing
being declared is *what actually runs*, not what is configured. Every hand run
you have ever done declared nothing, which is why the card has always said
this.

**If the card says something else**, note the exact words. It should not be
claiming a schedule it has not been told about.

## 7. Wait for the morning

**Do nothing.** The point of the test is that nobody starts it.

**If you would rather not wait**, you can force one — but say which you did,
because they are not the same test:

```
sudo systemctl start cairn-preflight.service
```

That runs it **through the unit**, so it does get `CAIRN_INTERVAL_MINUTES` and
it does declare the schedule. What it does not test is the timer firing on its
own.

## 8. The morning after — what to look at

```
systemctl list-timers cairn-preflight.timer
journalctl -u cairn-preflight.service --since yesterday
```

**Expect:** `LAST` now has a time, and the journal has the whole run — the same
output you see by hand.

**Then the card. Expect, after the first timed run:**

> the time it last submitted, **and that it is expected daily**.

**That second half is the whole of what this change bought.** It is the
difference between *here is a reading* and *here is a reading, and I will tell
you if the next one does not arrive*.

---

## What a failure at each step means

| Step | If it fails | What it means |
| --- | --- | --- |
| 1 | Pull refuses | The box has local edits. A finding about the box, not the code |
| 2 | `daemon-reload` errors | A unit file is malformed. **Mine** |
| 3 | The two intervals disagree | I shipped two halves of one fact that do not match. **Mine** |
| 4 | Will not enable | Unit metadata is wrong. **Mine** |
| 5 | No NEXT, or no row | The timer is not armed. Nothing runs overnight |
| 6 | Card claims a schedule already | The portal is asserting something nobody told it. **Mine, and the worst of these** |
| 7→8 | Nothing ran overnight | The interesting one. Timer armed and did not fire, or fired and the run died. `journalctl` says which |
| 8 | Ran, but the card shows no schedule | The declaration did not survive the trip. **Mine**, and exactly what this test exists to find |

**The last row is the one I would bet on if any of them fail**, because it is
the only part that has never run end to end outside a test: the box setting an
environment variable, the script reading it, the payload carrying it, the
portal parsing it and writing it to the binding, and the card reading it back.
Five hand-offs, each tested alone.

---

## Undoing it, in one command

```
sudo systemctl disable --now cairn-preflight.timer
```

**That is the whole of it.** The box goes back to what it was: enrolled,
runnable by hand, declaring no schedule. The unit files can stay where they
are — a disabled timer does nothing.

**The portal will keep the last declared interval**, and the card will start
saying the box is silent once it misses two scheduled collections. That is
correct rather than a leftover: the portal is reporting that something it was
told to expect did not arrive. If you want it to stop saying that, tell me and
I will clear the declaration — it is a column, not a decision.
