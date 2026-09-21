#!/usr/bin/env bash
#
# What the run prints about the credential must not contradict what it claims
# about it.
#
# ## The occurrence
#
# The first portal-sourced run, 21 September 2026 at 16:27 Eastern, printed
# this four lines below the claim that the credential was not typed:
#
#     CREDENTIAL SOURCE: the portal, fetched for this run.
#       It was not typed, is not on this disk, and goes no further than
#       this process and one memory-backed ticket cache.
#
#     --- 1. Kerberos ---
#       Password for svc-cairn@RVATECHVISIONS.COM:
#
# **Nothing was prompted.** `kinit` reads the password from a pipe here and
# prints its prompt LABEL anyway. The script's own prompt -- lower case,
# "password for ... (not echoed)" -- is correctly absent, which is the only way
# a reader can tell the two apart, and it is not a distinction anybody should
# have to make.
#
# It matters because this output is the evidence we hand a district's
# administrator that the box does not hold their credential. A reader who sees
# the line and not the case difference concludes the sentence above it is false.
#
# ## Why the label is stripped and the line is not
#
# `kinit`'s output is captured with `2>&1` because the refusal below it has to
# read what the KDC actually said -- piping the error stream away left every
# failure looking alike. The prompt carries no trailing newline, so **a refusal
# is frequently glued to the same line**:
#
#     Password for svc@REALM: kinit: Password incorrect while getting ...
#
# Dropping the whole line would therefore discard the error, which is the rule
# this project holds hardest. So the LABEL is removed and everything after it is
# kept.
#
# ## One source
#
# The expression is read out of `preflight.sh` rather than copied here. Two
# copies of one fact is what produced the detector miss recorded in the portal's
# KNOWN-FAILURES: the document held three wordings, the code held one, and the
# only copy that acted was the wrong one.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/preflight.sh"

failures=0

fail() {
  echo "FAIL: $*"
  failures=$((failures + 1))
}

pass() {
  echo "ok:   $*"
}

if [ ! -f "$SCRIPT" ]; then
  echo "FATAL: no preflight.sh beside this test at ${SCRIPT}."
  echo "       Refusing rather than reporting on a file that is not there."
  exit 2
fi

# --- the expression, read from the script rather than held here --------------

STRIP="$(sed -n "s/^KINIT_PROMPT_STRIP='\(.*\)'$/\1/p" "$SCRIPT")"

if [ -z "$STRIP" ]; then
  fail "preflight.sh defines no KINIT_PROMPT_STRIP, so nothing removes kinit's"
  echo "      prompt label and a portal-sourced run still prints 'Password for'."
else
  pass "preflight.sh defines KINIT_PROMPT_STRIP"

  # --- the real occurrence, copied from the run of 21 September 2026 ---------
  #
  # Copied rather than retyped. A retyped fixture agrees with the author's
  # recollection, the code agrees with the fixture, and neither agrees with the
  # tool -- which is how a capital letter survived being written, reviewed and
  # tested in the portal's own suite.
  real='Password for svc-cairn@RVATECHVISIONS.COM:'
  got="$(printf '%s' "$real" | sed "$STRIP")"

  if [ -n "$got" ]; then
    fail "the real prompt line survived the strip as: ${got}"
  else
    pass "the captured prompt label is removed entirely"
  fi

  # --- a refusal glued to the label -----------------------------------------
  #
  # CONSTRUCTED, and said so rather than claimed as a capture: no failed kinit
  # has been recorded from this box. The property is what matters -- if the
  # strip ever removes the whole line, a refusal disappears with it, and that
  # is a discarded error stream by another route.
  glued='Password for svc-cairn@RVATECHVISIONS.COM: kinit: Password incorrect while getting initial credentials'
  kept="$(printf '%s' "$glued" | sed "$STRIP")"

  case "$kept" in
    *'Password for'*)
      fail "the label survived on a glued line: ${kept}" ;;
    'kinit: Password incorrect while getting initial credentials')
      pass "a refusal glued to the label is kept in full" ;;
    *)
      fail "the refusal was altered or lost. got: ${kept}" ;;
  esac
fi

# --- the expression is actually applied to kinit's output --------------------
#
# A constant with no call site is not a fix. The portal's own NETWORK_STATE
# labels existed, had a test, and nothing rendered them for a release.
if grep -q 'kinit_out.*sed "\$KINIT_PROMPT_STRIP"' "$SCRIPT" \
  || grep -q 'KINIT_PROMPT_STRIP' <(grep -A 4 'kinit_out=' "$SCRIPT"); then
  pass "the strip is applied to kinit's captured output"
else
  fail "KINIT_PROMPT_STRIP is defined and never applied to kinit_out"
fi

echo
if [ "$failures" -eq 0 ]; then
  echo "PASS: a portal-sourced run prints no prompt label."
  exit 0
fi

echo "FAILED: ${failures} assertion(s)."
exit 1
