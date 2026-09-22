#!/usr/bin/env bash
#
# What enroll.sh does when a key is already here, and what it says while doing
# it.
#
# ## Why the test is not "it never overwrites"
#
# That was the test asked for, and it could not fail: `enroll.sh` already
# refuses when `appliance.key` exists, so an assertion that it refuses would
# have been green against the unfixed script. **A proof that cannot fail has
# not proved anything**, so the test was withdrawn and these three were written
# against what is actually wrong.
#
# ## The three
#
# **a. The refusal exits ZERO.** A script that did nothing reports success to
# anything reading the status — a person, a pipeline, or the next line of a
# runbook. That is the fails-open shape: not-done and done print the same.
#
# **b. The refusal text is false as of v4.47.** It says, in capitals, that the
# portal holds no record and the enrolment endpoint is not built. The endpoint
# shipped on 21 September, an appliance enrolled through it, and it was revoked
# through the card on 22 September at 08:21:41 Eastern. The instruction a
# reader follows is the stale half, which is the half that gets executed.
#
# **c. The guard tests the PRIVATE half only.** With `appliance.key` absent and
# `appliance.key.pub` present — which is exactly the state a failed generation
# leaves — the guard passes and `openssl pkey -pubout` overwrites the orphan
# with no warning. One real silent overwrite, in the script whose whole subject
# is not overwriting things.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/enroll.sh"

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

if [ ! -r "$SCRIPT" ]; then
  printf 'FAIL: cannot read %s\n' "$SCRIPT"
  exit 2
fi

# ---------------------------------------------------------------------------
# a. The refusal exits non-zero, with a code the script names
# ---------------------------------------------------------------------------

if grep -qE '^ALREADY_ENROLLED_EXIT=[0-9]+' "$SCRIPT"; then
  ok "the script names its refusal exit code"
else
  bad "no named exit code for the already-has-a-key refusal"
fi

# The `exit` that ends the already-enrolled branch. Read as the first exit
# after the guard opens, which is what the branch actually does.
branch_exit="$(awk '
  /^if \[ -f "\$KEY" \]/ { inbranch = 1 }
  inbranch && /^  exit / { print $2; exit }
' "$SCRIPT")"

if [ -z "$branch_exit" ]; then
  bad "could not find the exit that ends the already-enrolled branch"
elif [ "$branch_exit" = "0" ]; then
  bad "the refusal exits 0, so doing nothing reports success"
else
  ok "the refusal exits non-zero (${branch_exit})"
fi

# ---------------------------------------------------------------------------
# b. The refusal tells the truth at stage 3
# ---------------------------------------------------------------------------
#
# Asserted as ABSENCE of the withdrawn sentences and PRESENCE of the real
# instruction, because either alone passes through the defect: removing the
# false text without saying what to do leaves a reader with no next step, and
# adding the next step without removing the false text leaves both on screen.

withdrawn=0
for phrase in \
  'enrolment endpoint is not built' \
  'THE PORTAL HOLDS NO RECORD OF IT YET' \
  'there is nothing to revoke and nobody to tell' \
  'when stage 3 lands'
do
  if grep -qF "$phrase" "$SCRIPT"; then
    bad "the refusal still says: ${phrase}"
    withdrawn=$((withdrawn + 1))
  fi
done

[ "$withdrawn" -eq 0 ] && ok "no withdrawn claim about the portal remains"

if grep -qiE 'revoke the appliance on the [a-z ]*card' "$SCRIPT"; then
  ok "the refusal names revoking on the card as the first step"
else
  bad "the refusal does not tell the reader to revoke on the card first"
fi

# ---------------------------------------------------------------------------
# c. Either half is enough to refuse, and the one found is named
# ---------------------------------------------------------------------------

if grep -qE 'if \[ -f "\$KEY" \] \|\| \[ -f "\$PUB" \]; then' "$SCRIPT"; then
  ok "the guard refuses if EITHER half is present"
else
  bad "the guard tests one half only, so an orphaned public key is overwritten"
fi

if grep -qE '^ *found="' "$SCRIPT" && grep -qE 'already has a key: \$\{found\}' "$SCRIPT"; then
  ok "the refusal names the half it found"
else
  bad "the refusal does not name which half it found"
fi

# ---------------------------------------------------------------------------
# And the behaviour itself, driven rather than read
# ---------------------------------------------------------------------------
#
# The script writes to /etc/cairn-appliance and requires root, so it cannot be
# run here in full. What CAN be driven is the guard, by evaluating it against a
# temporary directory — the same extraction `preflight-credential-test.sh`
# makes, and for the same reason: reading a script is not running it.

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

guard_refuses() {
  local key="$1" pub="$2"
  KEY="${work}/appliance.key"
  PUB="${work}/appliance.key.pub"
  rm -f "$KEY" "$PUB"
  [ "$key" = present ] && : > "$KEY"
  [ "$pub" = present ] && : > "$PUB"

  # The guard as the script spells it, read out of the script rather than
  # retyped -- a retyped guard agrees with the author's recollection.
  local line
  line="$(grep -m1 -E '^if \[ -f "\$KEY" \]' "$SCRIPT")"
  # The guard is one line by construction; if it ever wraps, this reads half of
  # it and would answer confidently about a condition it never saw.
  case "$line" in *then) : ;; *) return 2 ;; esac
  [ -n "$line" ] || return 2

  eval "${line%then}then return 0; fi; return 1"
}

if guard_refuses present absent; then ok "refuses with only the private half"; else bad "a lone private key was not refused"; fi
if guard_refuses present present; then ok "refuses with both halves"; else bad "a complete pair was not refused"; fi
if guard_refuses absent present; then
  ok "refuses with only the PUBLIC half, so the orphan is not overwritten"
else
  bad "an orphaned public half is not refused, and openssl pkey would overwrite it"
fi
if guard_refuses absent absent; then bad "refuses on an empty directory"; else ok "allows a fresh box"; fi

# ---------------------------------------------------------------------------

printf '\n%s\n' "checks: ${checks}, failures: ${fails}"

if [ "$checks" -eq 0 ]; then
  printf 'FAIL: nothing was checked, so this run is evidence about nothing.\n'
  exit 2
fi

if [ "$fails" -ne 0 ]; then
  printf 'FAIL: the already-enrolled refusal is not what it should be.\n'
  exit 1
fi

printf 'PASS: the refusal is loud, true and covers both halves.\n'
