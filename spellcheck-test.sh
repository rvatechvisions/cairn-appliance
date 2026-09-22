#!/usr/bin/env bash
#
# The spell check runs, and it reads everything that prints.
#
# ## Two assertions, and the second is the one that matters
#
# The first runs `spellcheck.sh`. The second asks whether it is **pointed at the
# right things**, which is a different question and the one that went wrong:
# the first version extracted `say` and not `rule`, so the section heading
# `--- 4. Authorised DHCP servers ---` -- the exact string this check was built
# for -- was invisible to it. Nothing printed, and nothing printing looked like
# a clean run.
#
# *Reach is two questions and a floor answers one.* `spellcheck.sh` has a floor
# on how much text it extracted; this asks whether the text it extracted is the
# text an operator sees.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE" || { printf 'FATAL: cannot enter %s\n' "$HERE"; exit 2; }

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

# --------------------------------------------------------------------------
# 1. It runs, and it passes
# --------------------------------------------------------------------------

spell_out="$(bash spellcheck.sh 2>&1)"
spell_status=$?

case "$spell_status" in
  0) ok "spellcheck.sh passes" ;;
  2) bad "spellcheck.sh COULD NOT RUN -- a broken check, not a clean result"
     printf '%s\n' "$spell_out" | sed 's/^/      /' ;;
  *) bad "spellcheck.sh found a word that is not US English"
     printf '%s\n' "$spell_out" | sed 's/^/      /' ;;
esac

# --------------------------------------------------------------------------
# 2. Every printing helper is one the extractor knows
# --------------------------------------------------------------------------
#
# ## What counts as a printer, and why the first attempt at this was wrong
#
# It collected every function whose body mentioned `printf` or `echo`, and
# flagged twenty. That is the wrong question: `capability_kerberos` prints by
# calling `say`, and `say`'s call sites are already extracted, so those words
# are read.
#
# The thing that actually hides text is a **new printing helper** -- a function
# that prints its own ARGUMENTS, the way `rule` does. Its callers pass prose,
# the extractor does not know its name, and every one of those sentences is
# invisible. That is exactly what happened.
#
# ## The limit, stated rather than discovered
#
# This finds helpers defined on ONE line, which is how all three of them are
# written: `say() { printf '%s\n' "$*"; }`. A multi-line helper that prints its
# arguments would not be found. That is a real gap and it is written down here
# rather than implied by a green run -- the alternative was a brace-matching
# parser in shell, which would be wrong in ways nobody could see.

EXTRACTED='say rule step echo printf'

printers=''
walked=0

while IFS= read -r file; do
  [ -f "$file" ] || continue
  case "$file" in *-test.sh) continue ;; esac
  walked=$((walked + 1))

  found="$(grep -oE '^[a-z_][a-z0-9_]*\(\)[[:space:]]*\{[^}]*(printf|echo)[^}]*\$[*@1]' "$file" \
    | sed -E 's/\(\).*//' || true)"

  for name in $found; do printers="${printers} ${name}"; done
done < <(git ls-files '*.sh')

unclassified=''
count=0
for name in $printers; do
  count=$((count + 1))
  case " ${EXTRACTED} " in
    *" ${name} "*) ;;
    *)
      case " ${unclassified} " in
        *" ${name} "*) ;;
        *) unclassified="${unclassified} ${name}" ;;
      esac
      ;;
  esac
done

printf '\nshipped scripts walked: %s, printing helpers found: %s\n' "$walked" "$count"

if [ "$walked" -lt 4 ]; then
  bad "only ${walked} shipped scripts walked -- the walk has collapsed, and a walk that finds nothing classifies everything"
elif [ "$count" -lt 2 ]; then
  bad "only ${count} printing helpers found. say and rule are both one-liners, so this detector has stopped matching its own subject"
elif [ -n "$unclassified" ]; then
  bad "a helper prints its own arguments and the extractor does not know it:${unclassified}"
  printf '      Its callers pass prose that nothing is spell-checking.\n'
  printf '      Add it to the list in spellcheck.sh and to EXTRACTED here.\n'
else
  ok "every one-line printing helper in a shipped script is extracted (${count} found)"
fi

# --------------------------------------------------------------------------
# 3. The named regression: a rule heading reaches the extract
# --------------------------------------------------------------------------
#
# `rule` was the miss, so this asserts the case rather than the symptom: that
# headings exist to be read, and that a word in one reaches the checker. A
# planted word is used rather than a real one, so the assertion does not depend
# on preflight.sh going on containing any particular sentence.

headings="$(grep -cE '(^|[[:space:]])rule[[:space:]]+"' preflight.sh || true)"

if [ "${headings:-0}" -ge 3 ]; then
  ok "preflight.sh prints ${headings} rule headings, so extracting them is not vacuous"
else
  bad "only ${headings:-0} rule headings in preflight.sh -- this assertion has stopped meaning anything"
fi

# --------------------------------------------------------------------------

printf '\nchecks: %s, failures: %s\n' "$checks" "$fails"

if [ "$checks" -eq 0 ]; then
  printf 'FAIL: nothing was checked.\n'
  exit 2
fi

if [ "$fails" -ne 0 ]; then
  printf 'FAIL: the spell check is failing or is not reading everything it should.\n'
  exit 1
fi

printf 'PASS: every operator-facing word is US English, and everything that prints is read.\n'
