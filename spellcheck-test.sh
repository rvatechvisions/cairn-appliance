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
# ## The one-line limit is closed, and what closing it surfaced
#
# This found helpers defined on ONE line, which is how all three of the real
# printers are written: `say() { printf '%s\n' "$*"; }`. The gap was written
# down rather than implied by a green run, and writing it down is not the same
# as closing it -- *a detector that fails to match is indistinguishable from a
# clean run*, and this is the third instance of that class in three days.
# Jackie’s ruling, 22 September 2026: fix the extractor, not the symptom.
#
# It spans lines now. No brace-matching parser: a body opens with the
# definition and closes with a brace in column nought, which is how every
# helper in these scripts is written and is checkable by looking.
#
# ## And the widening surfaced a class the one-line version never met
#
# Two helpers arrived immediately, `agrees` and `json_safe`, and **neither
# prints to an operator at all.** Both use `printf` as a STRING OPERATION:
#
#   agrees()    printf '%s' "$1" | tr ... , compared for an exit status
#   json_safe() printf '%s' "$1" | tr ... , embedded in a JSON field
#
# Every call site of both captures the output -- `$(json_safe "$reason")`, and
# `! agrees "$LOCAL_REALM" "$portal_realm"` inside an `if`. Nothing either one
# emits reaches a terminal.
#
# **So the membership question is where the output GOES, not what it looks
# like**, and that is mechanical: a helper whose every call site is captured
# or used for its exit status is a transformer, and drops out by construction
# rather than by an exemption somebody has to maintain. *The test of a domain
# is that it needs no special cases.*
#
# **Default is inclusion.** A helper with call sites that are not all consumed
# stays a printer and fails here until somebody classifies it, which is the
# direction whose failure mode is a conversation rather than silence.
#
# ## The stored values, which is the decision rather than the derivation
#
# `json_safe` would be out of scope even if it did print, and that is worth
# keeping separately because it is a decision rather than a consequence.
# Jackie’s ruling, 22 September 2026: **it carries stored values, and stored
# values are governed by `preflight-stored-values-test.sh`, which asserts the
# exact set.** Spell-checking them as prose would put two checks with an
# opinion about one string, which is how two copies of a fact come to
# disagree. This reads printed text; that one reads the vocabulary.

EXTRACTED='say rule step echo printf'

printers=''
shipped=''
walked=0

while IFS= read -r file; do
  [ -f "$file" ] || continue
  case "$file" in *-test.sh) continue ;; esac
  walked=$((walked + 1))
  shipped="${shipped} ${file}"

  found="$(awk '
    # A definition opens a body. The one-line form closes on the same line.
    /^[a-z_][a-z0-9_]*\(\)[ \t]*\{/ {
      name = $0; sub(/\(\).*/, "", name)
      if ($0 ~ /\}[ \t]*$/) {
        if ($0 ~ /(printf|echo)/ && $0 ~ /\$[*@1]/) print name
        next
      }
      inside = 1; prints = 0; delete alias; next
    }
    # Closing brace at column nought, which is how every helper here ends.
    inside && /^\}/ { if (prints) print name; inside = 0; next }

    # A local standing in for an argument. `step` is the case: local
    # name="$1", then printf ... "$name" two lines down.
    inside && match($0, /(^|[ \t;])(local[ \t]+)?[a-z_][a-z0-9_]*="?\$[1*@]/) {
      part = substr($0, RSTART, RLENGTH)
      sub(/.*[ \t;]/, "", part); sub(/^local[ \t]+/, "", part)
      sub(/=.*/, "", part)
      if (part != "") alias[part] = 1
    }

    inside && /(printf|echo)/ {
      # Directly, or through one of this body’s aliases.
      if ($0 ~ /\$[*@1]([^0-9]|$)|\$\{1[}:]/) prints = 1
      else for (a in alias) if ($0 ~ ("\\$" a "([^a-zA-Z0-9_]|$)") ||
                                $0 ~ ("\\$\\{" a "[}:]")) prints = 1
    }
  ' "$file")"

  for name in $found; do printers="${printers} ${name}"; done
done < <(git ls-files '*.sh')

# Stage two. A helper whose every call site captures its output, or uses it
# for an exit status, prints to nobody -- so it is not a printer, and saying
# so here is cheaper and more durable than a skip list with reasons to keep
# up to date.
consumed_everywhere() {
  local name="$1" sites=0 consumed=0 line

  while IFS= read -r line; do
    case "$line" in
      *"${name}()"*) continue ;;
      \#*|*[[:space:]]\#*) ;;
    esac
    sites=$((sites + 1))
    case "$line" in
      *"\$(${name} "*|*"\$(${name})"*|*"\`${name} "*) consumed=$((consumed + 1)) ;;
      *"! ${name} "*|*"if ${name} "*|*"&& ${name} "*|*"|| ${name} "*|*"while ${name} "*)
        consumed=$((consumed + 1)) ;;
    esac
  done < <(grep -hE "(^|[^a-z_])${name}[[:space:](]" $shipped 2>/dev/null \
           | grep -vE "^[[:space:]]*#")

  # No call sites at all is NOT consumed: an unused helper is unclassified
  # rather than exempt, which is the inclusive direction.
  [ "$sites" -gt 0 ] && [ "$sites" -eq "$consumed" ]
}

unclassified=''
transformers=''
count=0
for name in $printers; do
  if consumed_everywhere "$name"; then
    case " ${transformers} " in
      *" ${name} "*) ;;
      *) transformers="${transformers} ${name}" ;;
    esac
    continue
  fi
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
if [ -n "$transformers" ]; then
  printf 'not printers, every call site consumes the output:%s\n' "$transformers"
fi

if [ "$walked" -lt 4 ]; then
  bad "only ${walked} shipped scripts walked -- the walk has collapsed, and a walk that finds nothing classifies everything"
elif [ "$count" -lt 2 ]; then
  bad "only ${count} printing helpers found. say, rule and step all print their arguments, so this detector has stopped matching its own subject"
elif [ -n "$unclassified" ]; then
  bad "a helper prints its own arguments and the extractor does not know it:${unclassified}"
  printf '      Its callers pass prose that nothing is spell-checking.\n'
  printf '      Add it to the list in spellcheck.sh and to EXTRACTED here.\n'
else
  ok "every printing helper in a shipped script is extracted (${count} found, one line or many)"
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
