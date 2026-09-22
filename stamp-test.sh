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
