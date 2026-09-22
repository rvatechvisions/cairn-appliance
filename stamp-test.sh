#!/usr/bin/env bash
#
# The binary can say what it is: which commit, and which release.
#
# ## What was already true, and it is worth saying before the gap
#
# `preflight.sh` stamps `-X main.commit=` and **reads the stamp back**, refusing
# a build that reports `unstamped`. That is the half that matters most and it
# works: a linker flag fails silently -- a wrong symbol path, a renamed variable
# or a quoting slip all produce a clean build and an empty stamp -- so the build
# is not trusted to have done it.
#
# ## The gap
#
# `main.version` is never passed. Every binary reports `no-tag`, including one
# built from a tagged release, so the binary cannot say **which release** it is
# even when there is an answer.
#
# `no-tag` is honest about not knowing and that is why this was invisible: the
# output was never wrong, it was permanently uninformative. *Unknown is not
# zero* has a quieter sibling -- unknown that could have been known.
#
# ## Why both halves are asserted rather than the new one
#
# A test written only for the version would pass on a build that had stopped
# stamping the commit. The two travel in one flag list and break the same way.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE" || { printf 'FATAL: cannot enter %s\n' "$HERE"; exit 2; }

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

if ! command -v go >/dev/null 2>&1; then
  printf 'COULD NOT CHECK: go is not on PATH, so nothing was built.\n'
  printf '                 This is a broken check, not a clean result.\n'
  exit 2
fi

# ---------------------------------------------------------------------------
# 1. The build passes both stamps
# ---------------------------------------------------------------------------
#
# Asserted over preflight.sh rather than only through a build, because the
# build below uses flags this test chooses. What ships is what preflight.sh
# passes, and a test that only exercised its own flags would be reporting on
# itself.

for symbol in main.commit main.version; do
  if grep -q -- "-X ${symbol}=" preflight.sh; then
    ok "preflight.sh stamps ${symbol}"
  else
    bad "preflight.sh never passes -X ${symbol}=, so the binary cannot report it"
  fi
done

# ---------------------------------------------------------------------------
# 2. A stamped build reports what it was given
# ---------------------------------------------------------------------------

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

COMMIT="0123456789abcdef0123456789abcdef01234567"
VERSION="v9.9-test"

if (cd preflight && go build -trimpath \
      -ldflags "-X main.commit=${COMMIT} -X main.version=${VERSION}" \
      -o "${work}/preflight" . >/dev/null 2>&1); then
  reported="$("${work}/preflight" -version 2>&1)"

  case "$reported" in
    *"$COMMIT"*) ok "the commit is reported back" ;;
    *) bad "the commit did not come back: ${reported}" ;;
  esac

  case "$reported" in
    *"$VERSION"*) ok "the release is reported back" ;;
    *) bad "the release did not come back: ${reported}" ;;
  esac
else
  bad "the probe did not build, so neither stamp could be read"
fi

# ---------------------------------------------------------------------------
# 3. An unstamped build says so, in words, rather than printing a blank
# ---------------------------------------------------------------------------
#
# The half that makes the refusal in preflight.sh possible. A blank is not
# information and cannot be matched on; `unstamped` and `no-tag` can.

if (cd preflight && go build -trimpath -o "${work}/bare" . >/dev/null 2>&1); then
  bare="$("${work}/bare" -version 2>&1)"

  case "$bare" in
    *unstamped*) ok "an unstamped commit reads as 'unstamped'" ;;
    *) bad "an unstamped build did not say so: ${bare}" ;;
  esac

  case "$bare" in
    *no-tag*) ok "an unstamped release reads as 'no-tag'" ;;
    *) bad "an untagged build did not say so: ${bare}" ;;
  esac
else
  bad "the unstamped probe did not build"
fi

# ---------------------------------------------------------------------------
# 4. preflight.sh refuses an unstamped build, and the refusal is reachable
# ---------------------------------------------------------------------------

if grep -q 'STAMP DID NOT TAKE' preflight.sh; then
  ok "preflight.sh refuses a build whose stamp did not take"
else
  bad "the unstamped refusal is gone, so a silent linker failure would ship"
fi

# ---------------------------------------------------------------------------

# --------------------------------------------------------------------------
# The digest pin is claimed only if it exists
# --------------------------------------------------------------------------
#
# ## What this is for
#
# `preflight.sh` described a digest pin in the PRESENT TENSE -- *the appliance
# refuses to run bytes whose digest does not match what the portal named* --
# in two comments and in a refusal a technician reads. **There is no such
# control.** Nothing here or in the portal compares these bytes with anything.
#
# That is *product copy written from the design rather than from the thing
# that shipped*, and the remedy this project already gives is to assert the
# sentence and the control together, so either both move or this fails.
#
# It is worst in the operator-facing copy. A technician reading a refusal is
# being told the box has a protection it does not have, at the moment they
# are deciding whether to trust what it just built.
#
# ## What it will do when somebody builds the pin
#
# Nothing, quietly. Adding a real comparison satisfies the control side, and
# the sentence becomes sayable in the same commit -- which is the point: the
# claim is permitted exactly when it is true, rather than being remembered.

# A claim that the bytes are checked. Deliberately broad: it is the meaning
# that must not be asserted, not one phrasing of it.
claims_pin="$(grep -nE 'refuses? to run bytes|digest (does not |doesn'\''t )?match|digest pin (checks|compares|refuses)' preflight.sh || true)"

# The control itself: something that computes a digest of the binary and
# compares it with a value from somewhere else.
has_pin="$(grep -nE 'sha256sum|shasum|EXPECTED_DIGEST|expected_digest' preflight.sh || true)"

if [ -z "$claims_pin" ]; then
  ok "preflight.sh claims no digest pin, and there is none to claim"
elif [ -n "$has_pin" ]; then
  ok "preflight.sh claims a digest pin and computes one"
else
  bad "preflight.sh describes a digest check that does not exist"
  printf '%s\n' "$claims_pin" | sed 's/^/      /'
  printf '      Nothing in this script computes a digest or compares one.\n'
  printf '      Either build the control or stop claiming it: an operator reading\n'
  printf '      a refusal is being told the box protects them in a way it does not.\n'
fi

printf '\nchecks: %s, failures: %s\n' "$checks" "$fails"

if [ "$checks" -eq 0 ]; then
  printf 'FAIL: nothing was checked.\n'
  exit 2
fi

if [ "$fails" -ne 0 ]; then
  printf 'FAIL: the binary cannot fully say what it is.\n'
  exit 1
fi

printf 'PASS: the binary reports its commit and its release, and says so when it has neither.\n'
