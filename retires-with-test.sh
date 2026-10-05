#!/usr/bin/env bash
#
# What retires when the binary says whose an error is. WO-1004-W item 4.
#
# ## What this holds
#
# preflight.sh decides whose an error was -- the system being read, or Cairn's
# own portal -- by matching the binary's words, because the binary prints both
# through one line. Each such match is correct today and outlives its reason
# the day the binary says whose an error is as a field. A patch that outlives
# its reason is how a check ends up matching on a coincidence years later, with
# nobody left who knows why it was written.
#
# So each one carries a "RETIRES-WITH error-source:" marker, the set of markers
# is named here and asserted exactly, and **this fails once the binary's
# -speaks answer declares error-source while any marked arm is still in
# place.** Then somebody decides, arm by arm: remove it, or keep it for a box
# whose binary predates the field and say so in the arm.
#
# The binary is read as source, not run, so this needs no Go toolchain. The
# token is the one APPLIANCE-BINARY-QUEUE.md in the portal repository names.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/preflight.sh"
MAIN="${HERE}/preflight/main.go"

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

for file in "$SCRIPT" "$MAIN"; do
  if [ ! -r "$file" ]; then
    printf 'FAIL: cannot read %s, so there is nothing to check\n' "$file"
    exit 2
  fi
done

# The set, named. A new arm of this kind joins it here or the count fails.
EXPECTED="read_reader's connection refused arm
read_reader's portal arm
the DHCP read's not-sent arm"

markers="$(sed -n 's/^[[:space:]]*# RETIRES-WITH error-source: //p' "$SCRIPT" | sort)"
if [ "$markers" = "$EXPECTED" ]; then
  ok "the arms that retire with error-source are exactly the three named"
else
  bad "the marked arms are not the named set: found [${markers}]"
fi

# What the binary says it understands. The -speaks answer is built in speaks();
# if that function cannot be found, this check could not run.
speaks="$(sed -n '/^func speaks() string {$/,/^}$/p' "$MAIN")"
if [ -z "$speaks" ]; then
  printf 'FAIL: preflight/main.go defines no speaks(), so what the binary declares cannot be read\n'
  exit 2
fi
ok "the binary's -speaks answer was found and read"

if printf '%s\n' "$speaks" | grep -q 'error-source'; then
  bad "the binary declares error-source and these arms are still in place: $(printf '%s' "$markers" | tr '\n' ';'). Remove each, or keep it for an older binary and say so in the arm"
else
  ok "the binary does not yet declare error-source, so the arms still stand"
fi

echo
if [ "$fails" -ne 0 ]; then
  echo "FAIL: ${fails} of ${checks} retirement check(s) failed."
  exit 1
fi
echo "PASS: ${checks} checks; what retires with error-source is named, and still needed."
