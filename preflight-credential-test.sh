#!/usr/bin/env bash
#
# The portal is the only source of the domain, the controller, the account and
# the password — and a leftover in settings.env that disagrees stops the run.
#
# ## Why the functions are read out of preflight.sh rather than copied here
#
# **Two copies of one fact is what produced the miss this project keeps
# finding.** A test carrying its own version of the parser agrees with the
# author's recollection, the code agrees with nothing, and the two drift with
# nobody able to see it. So the definitions are extracted from the shipping
# script by name and evaluated, exactly as `preflight-output-test.sh` reads
# KINIT_PROMPT_STRIP out of it.
#
# The extraction is itself asserted: a function that cannot be found is a
# refusal here rather than a quiet zero-test pass. *A guard that cannot locate
# what it checks must refuse.*
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/preflight.sh"

fails=0
checks=0

ok()   { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad()  { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

if [ ! -r "$SCRIPT" ]; then
  printf 'FAIL: cannot read %s\n' "$SCRIPT"
  exit 2
fi

# Pull one function definition out of the script, from `name() {` to the
# closing brace at column zero.
extract() {
  local name="$1"
  sed -n "/^${name}() {/,/^}/p" "$SCRIPT"
}

for fn in agrees parse_credential_block json_safe; do
  body="$(extract "$fn")"
  if [ -z "$body" ]; then
    printf 'FAIL: %s is not defined in preflight.sh — this test read nothing\n' "$fn"
    exit 2
  fi
  eval "$body"
done

ok "the three functions were found in preflight.sh and evaluated"

# ---------------------------------------------------------------------------
# agrees: case-insensitively, because that is the fact
# ---------------------------------------------------------------------------
#
# **The realm a client types and the realm the portal stores differ in case by
# design.** The portal uppercases a domain into a Kerberos realm; a settings
# file written by hand says `rvatechvisions.com`. Those name the same realm, so
# refusing on the difference would stop a box whose two records agree about
# everything that matters — a comparison right about bytes and wrong about the
# fact.

if agrees "rvatechvisions.com" "RVATECHVISIONS.COM"; then
  ok "a lower-case realm agrees with the upper-case one the portal serves"
else
  bad "a lower-case realm was treated as a disagreement"
fi

if agrees "DC01.example.test" "dc01.example.test"; then
  ok "a host name agrees whatever its case"
else
  bad "a host name differing only in case was treated as a disagreement"
fi

if agrees "svc-cairn@EXAMPLE.TEST" "svc-old@EXAMPLE.TEST"; then
  bad "two different accounts were treated as agreeing"
else
  ok "two different accounts disagree"
fi

if agrees "dc01.example.test" "dc02.example.test"; then
  bad "two different controllers were treated as agreeing"
else
  ok "two different controllers disagree"
fi

# ---------------------------------------------------------------------------
# parse_credential_block
# ---------------------------------------------------------------------------

printf 'username=svc-cairn@EXAMPLE.TEST\nrealm=EXAMPLE.TEST\ncontroller=dc01.example.test\n\nhunter2\n' \
  > "${TMPDIR:-/tmp}/cairn-block.$$"
parse_credential_block < "${TMPDIR:-/tmp}/cairn-block.$$"

[ "$PC_USERNAME"   = "svc-cairn@EXAMPLE.TEST" ] && ok "the username is read"   || bad "username: got '${PC_USERNAME}'"
[ "$PC_REALM"      = "EXAMPLE.TEST" ]           && ok "the realm is read"      || bad "realm: got '${PC_REALM}'"
[ "$PC_CONTROLLER" = "dc01.example.test" ]      && ok "the controller is read" || bad "controller: got '${PC_CONTROLLER}'"
[ "$PC_PASSWORD"   = "hunter2" ]                && ok "the password is read"   || bad "password did not survive"

# **The password is the remainder, so it may contain anything.** A password
# with an equals sign in it is the case that would be misread as a header by a
# parser that kept looking for name=value after the blank line — and the
# failure would be a wrong password sent to a customer's KDC.
printf 'username=svc@E\n\nrealm=not-a-header=x\n' > "${TMPDIR:-/tmp}/cairn-block.$$"
parse_credential_block < "${TMPDIR:-/tmp}/cairn-block.$$"

[ "$PC_PASSWORD" = "realm=not-a-header=x" ] \
  && ok "a password containing name=value is not read as a header" \
  || bad "a password containing an equals sign was misread: got '${PC_PASSWORD}'"

[ "$PC_REALM" = "" ] \
  && ok "and it did not become the realm" \
  || bad "a password line was taken as the realm: got '${PC_REALM}'"

# A field the portal has none of is ABSENT, and reads as empty rather than as a
# blank value the caller would then present to a KDC.
printf 'username=svc@E\n\npw\n' > "${TMPDIR:-/tmp}/cairn-block.$$"
parse_credential_block < "${TMPDIR:-/tmp}/cairn-block.$$"

[ -z "$PC_REALM" ] && [ -z "$PC_CONTROLLER" ] \
  && ok "an omitted realm and controller read as absent" \
  || bad "an omitted field did not read as absent"

# A password spanning lines arrives whole.
printf 'username=svc@E\n\nfirst\nsecond\n' > "${TMPDIR:-/tmp}/cairn-block.$$"
parse_credential_block < "${TMPDIR:-/tmp}/cairn-block.$$"

[ "$PC_PASSWORD" = "$(printf 'first\nsecond')" ] \
  && ok "a password spanning two lines arrives whole" \
  || bad "a multi-line password was truncated: got '${PC_PASSWORD}'"

# **A password whose first line is blank**, which is the case that tells an
# empty accumulator from an accumulator holding an empty line. Without a
# flag the second line is written over the top of the first instead of
# appended, and the password silently loses its leading newline.
printf 'username=svc@E\n\n\nsecond\n' > "${TMPDIR:-/tmp}/cairn-block.$$"
parse_credential_block < "${TMPDIR:-/tmp}/cairn-block.$$"

[ "$PC_PASSWORD" = "$(printf '\nsecond')" ] \
  && ok "a password whose first line is blank keeps it" \
  || bad "a leading blank line was dropped from the password"

rm -f "${TMPDIR:-/tmp}/cairn-block.$$"

# ---------------------------------------------------------------------------
# json_safe
# ---------------------------------------------------------------------------
#
# **Characters are dropped rather than escaped**, and the assertion is that the
# two characters which could break the report are gone. A reason is a sentence
# from this script's own output; losing a quotation mark from it costs a reader
# one punctuation mark, where a mis-escaped one produces a report the portal
# reads as something else entirely.

safe="$(json_safe 'a "quoted" \thing')"

case "$safe" in
  *'"'*) bad "json_safe left a quotation mark in: ${safe}" ;;
  *)     ok "json_safe removes quotation marks" ;;
esac

case "$safe" in
  *'\'*) bad "json_safe left a backslash in: ${safe}" ;;
  *)     ok "json_safe removes backslashes" ;;
esac

[ -n "$safe" ] && ok "and it does not empty the reason" || bad "json_safe emptied the reason"

# ---------------------------------------------------------------------------
# The refusal is in the script, and it names both values
# ---------------------------------------------------------------------------
#
# Asserted over the source rather than by running it: the refusal calls `exit`,
# and the property that matters is that both strings reach the message. A
# refusal saying only "settings.env disagrees with the portal" is a sentence
# somebody has to go and investigate; the two values side by side is the
# investigation.

if grep -q 'refuse_disagreement "the service account"' "$SCRIPT" \
   && grep -q 'refuse_disagreement "the domain"' "$SCRIPT" \
   && grep -q 'refuse_disagreement "the domain controller"' "$SCRIPT"; then
  ok "all three fields are checked against the portal"
else
  bad "a field is not checked against the portal"
fi

if grep -q 'say "  the portal says:  \${portal_value}"' "$SCRIPT" \
   && grep -q 'say "  \${SETTINGS} says: \${local_value}"' "$SCRIPT"; then
  ok "the refusal prints both values"
else
  bad "the refusal does not print both values"
fi

# ---------------------------------------------------------------------------

printf '\n%s\n' "checks: ${checks}, failures: ${fails}"

if [ "$checks" -eq 0 ]; then
  printf 'FAIL: nothing was checked, so this run is evidence about nothing.\n'
  exit 2
fi

if [ "$fails" -ne 0 ]; then
  printf 'FAIL: the portal is not the only source of these fields.\n'
  exit 1
fi

printf 'PASS: the portal is the only source, and a disagreeing leftover is refused.\n'
