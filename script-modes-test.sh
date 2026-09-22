#!/usr/bin/env bash
#
# A script the runbook says to run as ./x must be committed executable.
#
# ## What happened, 22 September 2026
#
# The runbook said `sudo ./set-portal.sh https://…` and the box answered
# `sudo: ./set-portal.sh: command not found`. The file was committed 100644.
#
# **`set-portal-test.sh` did not catch it because it invokes the script as
# `bash set-portal.sh`**, which works whatever the mode is. The test proved
# every behaviour the script has and nothing about whether an operator could
# start it — a harness asking a different question from the page, in the
# smallest possible form.
#
# ## Why the COMMITTED mode rather than the file on disk
#
# `test -x` answers about this checkout. Git Bash on Windows emulates the
# execute bit and will happily run a 644 file, so a filesystem check here is
# green on the machine that produced the defect. **The mode that travels is the
# one in the index**, and it is the only one a district's box will see.
#
# So this reads `git ls-files -s` and refuses anything but 100755, and it says
# so rather than leaving somebody to wonder why it did not just use `-x`.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

cd "$HERE" || { printf 'FAIL: cannot enter %s\n' "$HERE"; exit 2; }

# **The set is named, not discovered.** A glob over *.sh would sweep in the
# test scripts, which are invoked as `bash x.sh` and do not need the bit --
# and asserting a mode nobody depends on is how an assertion becomes noise
# somebody edits away.
#
# These four are what a person types, or what a script tells them to type:
# three from the runbook, and enroll.sh because its own refusal prints `$0`.
OPERATOR_RUN='bootstrap.sh enroll.sh preflight.sh set-portal.sh'

wrong=0
counted=0

for script in $OPERATOR_RUN; do
  counted=$((counted + 1))

  if [ ! -f "$script" ]; then
    bad "${script} is named here and is not in the repository"
    wrong=$((wrong + 1))
    continue
  fi

  mode="$(git ls-files -s -- "$script" | awk '{print $1}')"

  if [ -z "$mode" ]; then
    bad "${script} is not tracked, so it has no committed mode"
    wrong=$((wrong + 1))
    continue
  fi

  if [ "$mode" = "100755" ]; then
    ok "${script} is committed executable"
  else
    bad "${script} is committed ${mode}; an operator running ./${script} gets command not found"
    wrong=$((wrong + 1))
  fi
done

printf '\n%s\n' "operator-run scripts checked: ${counted}, wrong mode: ${wrong}"

# ---------------------------------------------------------------------------
# And the way the runbook actually starts it
# ---------------------------------------------------------------------------
#
# **This is weaker than the mode check and is here anyway**, because it is the
# form the defect took. On Linux it fails on a 644 file, which is the point; on
# Git Bash it may pass regardless, because MSYS emulates the bit. It is
# reported as what it is rather than counted as proof.

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf 'CAIRN_REALM=EXAMPLE.TEST\n' > "${work}/settings.env"

if ./set-portal.sh https://portal.example.test "${work}/settings.env" >/dev/null 2>&1; then
  ok "./set-portal.sh runs the way the runbook writes it (on this platform)"
else
  bad "./set-portal.sh could not be started the way the runbook writes it"
fi

case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*)
    printf '      note: this platform emulates the execute bit, so the line above\n'
    printf '            is not evidence about a Linux box. The committed mode is.\n'
    ;;
esac

# ---------------------------------------------------------------------------

printf '\n%s\n' "checks: ${checks}, failures: ${fails}"

if [ "$checks" -eq 0 ]; then
  printf 'FAIL: nothing was checked, so this run is evidence about nothing.\n'
  exit 2
fi

if [ "$fails" -ne 0 ]; then
  printf 'FAIL: a script an operator is told to run cannot be started that way.\n'
  exit 1
fi

printf 'PASS: every operator-run script is committed executable.\n'
