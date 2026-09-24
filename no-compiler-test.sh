#!/usr/bin/env bash
#
# THE APPLIANCE NEVER INVOKES A COMPILER AND NEVER ACQUIRES ONE.
#
# Two different things, and until 24 September 2026 only the first was
# written down. The box rebuilt its own executable on a timer because a
# distribution `go` had been installed by `bootstrap.sh` -- so the rule
# against compiling was kept by a script that had put the compiler there.
#
# ## Why the domain is every tracked file
#
# The first version of this assertion lived in `stamp-test.sh` and read
# `preflight.sh` alone. That is *a check scoped to one member of a set*: the
# rebuild could come back in `enroll.sh`, in `bootstrap.sh`, or in a document
# an installer follows -- and **a document that tells somebody to run a build
# is the same defect with a person as the interpreter.**
#
# ## What it cannot see, stated rather than discovered
#
# An ad-hoc command typed on the box leaves nothing in the tree. That is the
# same limit the portal records for its shell-payload rule, and it is why the
# control that matters is not this scan but the absence of a compiler.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE" || { printf 'FATAL: cannot enter %s\n' "$HERE"; exit 2; }

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

# **The index, not the directory.** A scratch file somebody left here is not
# part of this repository, and walking it would make the domain mean
# something else.
mapfile -t tracked < <(git ls-files)

if [ "${#tracked[@]}" -lt 15 ]; then
  printf 'COULD NOT CHECK: git ls-files named %s files, which is too few to be\n' "${#tracked[@]}"
  printf '                 this repository. A scan that walks nothing passes\n'
  printf '                 everything.\n'
  exit 2
fi

# ---------------------------------------------------------------------------
# The exemptions, each a claim, each asserted to still match something.
# ---------------------------------------------------------------------------
#
# `enrol-secret-test.sh` and `stamp-test.sh` build the probe to test it. They run on a developer
# machine and never on an appliance -- **and the residual is real and is
# stated rather than buried: `run-tests.sh` on an appliance would compile.**
# The control against that is that an appliance has no compiler, not that this
# file is careful.
#
# The three build documents record how the binary that exists was produced.
# They are history and they read as instructions, which is the finding in
# `APPLIANCE-REBUILD-REMOVAL.md` rather than something this test can fix.
#
# **`preflight/go.mod` is exempt from the FETCH refusal and from nothing else,
# and the exemption expires by itself.**
#
# Its `go 1.26.0` and `toolchain go1.27.1` lines are what fetched three
# compilers onto the lab box -- go1.26.8 and go1.26.0 on 20 September, and
# go1.27.1 at 05:44:30 on the 24th, three seconds into an unattended run. The
# lines are correct for the machine that BUILDS the probe and wrong for a
# machine that merely runs it.
#
# **The remedy is that this file leaves.** Jackie ruled on 24 September 2026
# that the appliance holds no repository and receives a verified binary, so
# `preflight/` belongs to a build machine rather than here. **The exemption is
# dated by the tree rather than by a calendar**: the loop below asserts every
# exempted file still exists, so the day `preflight/go.mod` leaves, this
# exemption fails and somebody has to delete it. An exemption that outlives its
# subject is a place to park the next failure.
exempt=(
  "enrol-secret-test.sh"
  "stamp-test.sh"
  "no-compiler-test.sh"
  "BUILD.md"
  "LAB-BUILD.md"
  "ANSWER-SHEET.md"
)

# Exempt from the FETCH refusal only. Everything else still applies to it.
fetch_exempt=(
  "preflight/go.mod"
)

is_fetch_exempt() {
  local file="$1" e
  for e in "${fetch_exempt[@]}"; do [ "$file" = "$e" ] && return 0; done
  return 1
}

is_exempt() {
  local file="$1" e
  for e in "${exempt[@]}"; do [ "$file" = "$e" ] && return 0; done
  return 1
}

for e in "${exempt[@]}" "${fetch_exempt[@]}"; do
  if [ -f "$e" ]; then
    ok "the exemption ${e} still names a file that is here"
  else
    bad "the exemption ${e} names a file that is gone: an exemption nobody needs is a place to park the next failure"
  fi
done

# ---------------------------------------------------------------------------
# 1. Nothing invokes a compiler
# ---------------------------------------------------------------------------
#
# Shape rather than a roster of one spelling: `go build`, `go install`,
# `go run`, `go get` and `go mod` all end with this repository compiling or
# fetching, and a check that held only the spelling that already failed
# catches nothing next time.
invoked=0
for file in "${tracked[@]}"; do
  is_exempt "$file" && continue
  [ -f "$file" ] || continue

  while IFS= read -r hit; do
    bad "${file}: invokes a compiler -- ${hit}"
    invoked=$((invoked + 1))
  done < <(grep -nE '(^|[^[:alnum:]_-])go[[:space:]]+(build|install|run|get|mod)([[:space:]]|$)' "$file" 2>/dev/null || true)
done

[ "$invoked" -eq 0 ] && ok "no tracked file invokes a compiler, outside the named exemptions"

# ---------------------------------------------------------------------------
# 2. Nothing ACQUIRES one
# ---------------------------------------------------------------------------
#
# The half that was never written down, and the one that made the rebuild
# possible. A package install, a tarball, or GOTOOLCHAIN telling go it may
# fetch a compiler are three ways to the same place.
acquired=0
for file in "${tracked[@]}"; do
  is_exempt "$file" && continue
  [ -f "$file" ] || continue

  while IFS= read -r hit; do
    bad "${file}: acquires a compiler -- ${hit}"
    acquired=$((acquired + 1))
  # **`[^\n]` was the first spelling and it matched nothing.** In a POSIX
  # bracket expression that is *not a backslash and not the letter n* -- and
  # `install` contains an n, so the pattern could never reach `golang` from
  # `apt-get`. A planted `apt-get install -y golang-go` went straight through.
  #
  # grep is line-based, so `.*` is the right thing and always was. *A detector
  # that fails to match is indistinguishable from a clean run*, and the plant
  # is the only reason this is not still silent.
  done < <(grep -nE '(apt-get|apt-cache|apt|yum|dnf|apk|pacman).*(golang|go-toolchain|\bgo\b)|GOTOOLCHAIN[[:space:]]*=|go[0-9]+\.[0-9]+(\.[0-9]+)?\.linux-[a-z0-9]+\.tar\.gz|curl.*go\.dev/dl|https?://[^ ]*golang\.org/(dl|toolchain)' "$file" 2>/dev/null || true)
done

[ "$acquired" -eq 0 ] && ok "no tracked file installs or downloads a compiler, outside the named exemptions"

# ---------------------------------------------------------------------------
# 3. Nothing FETCHES EXECUTABLE CODE from anywhere except the portal
# ---------------------------------------------------------------------------
#
# **The fourth refusal, and it is not implied by the other three.** Jackie’s
# ruling, 24 September 2026, after a directory listing showed three Go
# toolchains on the lab box -- go1.26.8 and go1.26.0 fetched on 20 September,
# and go1.27.1 at **05:44:30 on the 24th, three seconds into an unattended
# run.**
#
# **A toolchain acquisition is none of the first three.** It is not a compile,
# it is not a compiler we invoked, and it is not a binary we ran -- so a check
# that refuses `go build` and `apt-get install golang` walks straight past it.
# **IT WAS A FOURTH THING NOBODY HAD NAMED.**
#
# ## What a `go` or `toolchain` directive actually is
#
# Since Go 1.21 a `go` line higher than the installed compiler, or any
# `toolchain` line the installed compiler cannot satisfy, makes the build
# **download a compiler**. So two ordinary-looking lines in a `go.mod` are an
# instruction to fetch executable code, and neither of them contains a verb.
#
# `GOTOOLCHAIN=local` turns that into a refusal, and nobody had set it because
# nobody had noticed there were two compilers on the box.
#
# **This refuses the DIRECTIVE rather than the download**, because the download
# happens on a machine and the directive is the thing in the repository. A
# scan cannot see a fetch; it can see the line that causes one.
fetched=0
for file in "${tracked[@]}"; do
  is_exempt "$file" && continue
  is_fetch_exempt "$file" && continue
  [ -f "$file" ] || continue

  while IFS= read -r hit; do
    bad "${file}: can make a build fetch a compiler -- ${hit}"
    fetched=$((fetched + 1))
  done < <(grep -nE '^[[:space:]]*(toolchain[[:space:]]+go[0-9]|go[[:space:]]+1\.[0-9]+)' "$file" 2>/dev/null || true)
done

[ "$fetched" -eq 0 ] && ok "no tracked file carries a directive that would fetch a compiler"

# ---------------------------------------------------------------------------
# 4. The scan reached something
# ---------------------------------------------------------------------------
#
# *A scan that matches nothing passes everything.* The floor is over the files
# walked rather than over the hits, because zero hits is the good outcome and
# an empty domain produces it too.
walked=0
for file in "${tracked[@]}"; do
  is_exempt "$file" && continue
  [ -f "$file" ] && walked=$((walked + 1))
done

if [ "$walked" -ge 15 ]; then
  ok "walked ${walked} tracked files, so an empty domain did not pass this"
else
  bad "walked only ${walked} files: this scan is not reaching the repository"
fi

printf '\nchecks: %d, failures: %d\n' "$checks" "$fails"

if [ "$fails" -eq 0 ]; then
  printf 'PASS: the appliance neither compiles nor obtains a compiler.\n'
  exit 0
fi

printf 'FAIL: this repository can compile, or can obtain something that does.\n'
exit 1
