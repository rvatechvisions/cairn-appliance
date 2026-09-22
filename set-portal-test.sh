#!/usr/bin/env bash
#
# Setting CAIRN_PORTAL in settings.env, in every state the file can be in.
#
# ## The step this replaces, and exactly how it failed
#
# The runbook said:
#
#     grep CAIRN_PORTAL /etc/cairn-appliance/settings.env || \
#       echo 'CAIRN_PORTAL=https://…' >> /etc/cairn-appliance/settings.env
#
# `grep CAIRN_PORTAL` matches the line `CAIRN_PORTAL=` -- a line that is
# PRESENT and EMPTY -- so the guard succeeds, nothing is appended, and the run
# falls to the lab path asking a human for a password. **A missing line and an
# empty one are both NOT SET, and only one of them looked like it.**
#
# That is the fails-open shape in a runbook: the check answers "already done"
# when the thing is not done, and the next step reports success.
#
# ## And a measured correction to why two lines are bad
#
# `preflight.sh` reads the file with `.`, which is shell SOURCING: assignments
# execute in order, so **the LAST one wins** -- observed, not reasoned about.
# So two lines do not silently take the wrong value the way a take-the-first
# reader would expect. What they do is worse in a quieter way: **the file lies
# to whoever reads it**, because somebody scanning from the top sees
# `CAIRN_PORTAL=` and concludes it is unset while the run uses a value further
# down.
#
# Exactly one line, always, is the only state a person and the shell agree
# about.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/set-portal.sh"
PORTAL='https://portal.rvatechvisions.com'

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

if [ ! -x "$SCRIPT" ] && [ ! -r "$SCRIPT" ]; then
  printf 'FAIL: %s does not exist — this test read nothing\n' "$SCRIPT"
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The value the file yields when preflight sources it, which is the only
# question that matters about the file.
sourced_value() {
  ( unset CAIRN_PORTAL
    # shellcheck disable=SC1090
    . "$1" 2>/dev/null
    printf '%s' "${CAIRN_PORTAL:-}" )
}

portal_lines() {
  grep -c '^CAIRN_PORTAL=' "$1" 2>/dev/null || echo 0
}

# One case: build a file, run the script against it, and check all three of
# the things the work order asks for -- the value, the count, and that nothing
# else in the file was disturbed.
drive() {
  local name="$1" before="$2"
  local file="${work}/${name}.env"

  printf '%s' "$before" > "$file"
  printf 'CAIRN_REALM=EXAMPLE.TEST\nCAIRN_DC=dc.example.test\n' >> "$file"

  if ! bash "$SCRIPT" "$PORTAL" "$file" >"${work}/${name}.out" 2>&1; then
    bad "${name}: the script refused (exit $?)"
    sed 's/^/      /' "${work}/${name}.out"
    return 1
  fi

  local value count
  value="$(sourced_value "$file")"
  count="$(portal_lines "$file")"

  [ "$value" = "$PORTAL" ] \
    && ok "${name}: sourcing the file yields the portal" \
    || bad "${name}: sourcing yields '${value}'"

  [ "$count" = "1" ] \
    && ok "${name}: exactly one CAIRN_PORTAL line" \
    || bad "${name}: ${count} CAIRN_PORTAL lines"

  grep -q '^CAIRN_REALM=EXAMPLE.TEST$' "$file" \
    && grep -q '^CAIRN_DC=dc.example.test$' "$file" \
    && ok "${name}: the other settings are untouched" \
    || bad "${name}: another setting was changed or lost"

  grep -q "CAIRN_PORTAL=${PORTAL}" "${work}/${name}.out" \
    && ok "${name}: the run printed the resulting line" \
    || bad "${name}: the run did not print the resulting line"
}

# ---------------------------------------------------------------------------
# The two defects the work order names, plus the two states around them
# ---------------------------------------------------------------------------

drive missing        ''
drive present_empty  'CAIRN_PORTAL=
'
drive already_set    "CAIRN_PORTAL=${PORTAL}
"
drive two_lines      "CAIRN_PORTAL=
CAIRN_PORTAL=${PORTAL}
"

# ---------------------------------------------------------------------------
# The OLD one-liner, pinned so the defect cannot come back by being forgotten
# ---------------------------------------------------------------------------
#
# This drives the snippet the runbook used to carry, against the state it got
# wrong. It asserts the OLD behaviour, so it documents rather than forbids --
# and it is here because a defect nobody can reproduce is a defect somebody
# reintroduces.

old="${work}/old.env"
printf 'CAIRN_PORTAL=\n' > "$old"
grep CAIRN_PORTAL "$old" >/dev/null || echo "CAIRN_PORTAL=${PORTAL}" >> "$old"

if [ -z "$(sourced_value "$old")" ]; then
  ok "the old one-liner leaves a present-but-empty line unset, as recorded"
else
  bad "the old one-liner no longer reproduces its defect — check this file"
fi

# ---------------------------------------------------------------------------
# And the observation that says why one line rather than two
# ---------------------------------------------------------------------------

order="${work}/order.env"
printf 'CAIRN_PORTAL=\nCAIRN_PORTAL=%s\n' "$PORTAL" > "$order"

[ "$(sourced_value "$order")" = "$PORTAL" ] \
  && ok "sourcing takes the LAST assignment, so a reader scanning from the top is misled" \
  || bad "sourcing did not take the last assignment — the reasoning above needs rechecking"

# ---------------------------------------------------------------------------

printf '\n%s\n' "checks: ${checks}, failures: ${fails}"

if [ "$checks" -eq 0 ]; then
  printf 'FAIL: nothing was checked, so this run is evidence about nothing.\n'
  exit 2
fi

if [ "$fails" -ne 0 ]; then
  printf 'FAIL: CAIRN_PORTAL is not reliably set.\n'
  exit 1
fi

printf 'PASS: every state ends with exactly one CAIRN_PORTAL line that sources.\n'
