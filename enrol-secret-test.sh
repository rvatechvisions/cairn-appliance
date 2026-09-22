#!/usr/bin/env bash
#
# The registration key must never need to reach a shell.
#
# ## What happened, 22 September 2026
#
# Jackie's shell history, line 356: `read -rs <24-character token>`. The key
# was pasted onto the COMMAND LINE rather than at `read`'s prompt, so it went
# into `.bash_history` in clear text. That key was redeemed at 08:28:00 and is
# inert, and the entry is being removed — but the key landing there at all is
# the finding, and **the procedure is what put it there.**
#
# ## The procedure came from this binary
#
# `readRegistrationKey` refused a bare `-enrol` and printed a remedy: read
# the key into a shell variable with echo off, pipe that variable into this
# command, then clear the variable.
#
# **Described rather than quoted.** The assertions below forbid that recipe
# by searching for its literal text, and a scan cannot tell an account of a
# pattern from an instance of it. Writing it out here would make this file
# fail its own check the day the search widens past the Go sources — which is
# where it belongs, and the reason it is written this way now rather than
# after.
#
# Three steps, a shell variable, and a paste — at exactly the moment somebody
# is holding a secret and wants to get on. **A procedure that asks a person to
# put a secret into a shell will eventually put it into their history**, and
# the instruction was printed by the thing that could simply have asked.
#
# It is the same lesson as the enrolment refusal one file over: *operators run
# the printed text verbatim*, so printed text is an instruction and its
# correctness is a correctness question rather than a wording one.
#
# ## What replaces it
#
# The binary prompts for the key itself, from the terminal, with echo off, when
# stdin is a TTY. A piped stdin still works, so automation is unaffected and
# nothing that exists today breaks.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${HERE}/preflight"

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

if [ ! -d "$SRC" ]; then
  printf 'FAIL: no %s — this test read nothing\n' "$SRC"
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

BIN="${work}/preflight"
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*) BIN="${BIN}.exe" ;;
esac

if ! ( cd "$SRC" && go build -o "$BIN" . ) 2>"${work}/build.err"; then
  printf 'FAIL: the probe did not build — this test could not run\n'
  sed 's/^/      /' "${work}/build.err"
  exit 2
fi

ok "the probe built from the current source"

# ---------------------------------------------------------------------------
# The flag spelling: -enroll documented, -enrol still working
# ---------------------------------------------------------------------------
#
# Both, because the lab box and the runbook have been using -enrol all week and
# a spelling change that broke a live procedure would be a worse defect than
# the one it fixes.

KEYFILE="${work}/appliance.key"

for flag in -enroll -enrol; do
  out="$(printf '' | "$BIN" "$flag" -portal https://example.invalid -keyfile "$KEYFILE" 2>&1)"
  case "$out" in
    *"flag provided but not defined"*)
      bad "${flag} is not a flag this binary accepts" ;;
    *)
      ok "${flag} is accepted" ;;
  esac
done

help="$("$BIN" -h 2>&1 || true)"
case "$help" in
  *-enroll*) ok "the help names -enroll" ;;
  *)         bad "the help does not name -enroll" ;;
esac

# ---------------------------------------------------------------------------
# Nothing tells anybody to put a key in a shell
# ---------------------------------------------------------------------------

for forbidden in 'read -rs KEY' 'unset KEY' 'read -rs CAIRN'; do
  if grep -rqF "$forbidden" "${SRC}"/*.go; then
    bad "the binary still prints or contains: ${forbidden}"
  else
    ok "no shell-variable recipe for: ${forbidden}"
  fi
done

# The refusal a person sees when nothing is piped and there is no terminal.
empty="$(printf '' | "$BIN" -enroll -portal https://example.invalid -keyfile "$KEYFILE" 2>&1)"

case "$empty" in
  *'read -rs'*) bad "the refusal still teaches the shell-history procedure" ;;
  *)            ok "the refusal teaches no shell-variable procedure" ;;
esac

case "$empty" in
  *"no registration key"*|*"nothing was typed"*|*"no terminal"*)
    ok "an empty stdin with no terminal refuses and names why" ;;
  *)
    bad "the empty-stdin refusal does not say why: ${empty}" ;;
esac

# ---------------------------------------------------------------------------
# The terminal path, asserted over the source
# ---------------------------------------------------------------------------
#
# A prompt cannot be driven here without a pseudo-terminal, and building one
# would be a second mechanism to get wrong. So the BEHAVIOUR under a pipe is
# driven above, and the terminal branch is asserted to exist and to restore
# what it changed — the property whose absence leaves an operator's terminal
# with echo off after an interrupt.

if grep -q 'ModeCharDevice' "${SRC}"/main.go; then
  ok "the binary still distinguishes a terminal from a pipe"
else
  bad "nothing distinguishes a terminal from a pipe"
fi

if grep -qE 'stty|termios|MakeRaw|echo off|-echo' "${SRC}"/main.go; then
  ok "the terminal branch turns echo off"
else
  bad "the terminal branch does not turn echo off, so the key would be displayed"
fi

if grep -qE '^[[:space:]]*restore := silenceEcho' "${SRC}"/main.go \
   && grep -qE '^[[:space:]]*defer restore\(\)' "${SRC}"/main.go; then
  ok "echo is restored on the way out, whatever happens"
else
  bad "echo is not restored with a defer, so an interrupt leaves the terminal silent"
fi

# ---------------------------------------------------------------------------

printf '\n%s\n' "checks: ${checks}, failures: ${fails}"

if [ "$checks" -eq 0 ]; then
  printf 'FAIL: nothing was checked, so this run is evidence about nothing.\n'
  exit 2
fi

if [ "$fails" -ne 0 ]; then
  printf 'FAIL: the documented enrolment procedure can still put a key in a shell.\n'
  exit 1
fi

printf 'PASS: the key is asked for, never pasted into a shell.\n'
