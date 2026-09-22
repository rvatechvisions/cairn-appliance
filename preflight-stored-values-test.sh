#!/usr/bin/env bash
#
# Every value this appliance SENDS and the portal STORES.
#
# ## Why these are different from the rest of the output
#
# What preflight prints is read once, by whoever ran it, on a screen. What it
# **sends** is written into `appliance_runs` and rendered on a client's
# connection card, for as long as the row lives. A word chosen carelessly in a
# printed line costs one reading; the same word in a capability name is a
# stored value with history behind it, and renaming it after the first real run
# means rows that disagree with each other.
#
# So the stored vocabulary is asserted here and the prose is not.
#
# ## Two things are checked, and the second is not about spelling
#
# **The set is exact.** A sixth capability fails this test until somebody
# decides what it is called, which is the remedy this project reaches for
# everywhere -- name the set, and make membership the thing asserted. It beats
# a list of forbidden words, because a list misses the next one.
#
# **Every reason is ASCII.** `json_safe` is `tr -cd '[:print:]'`, which deletes
# every non-ASCII byte -- so a typographic apostrophe in a reason does not
# arrive as an apostrophe, it arrives as nothing, and the portal stores
# "the portals answer". It is invisible on this box, because the screen prints
# the line before json_safe ever sees it.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/preflight.sh"

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

if [ ! -r "$SCRIPT" ]; then
  printf 'FAIL: cannot read %s\n' "$SCRIPT"
  exit 2
fi

# ---------------------------------------------------------------------------
# The capability names, which are the values a card will print
# ---------------------------------------------------------------------------
#
# US English, because the portal and its clients are American, and a stored
# token cannot be respelled later without splitting the history.

EXPECTED='dhcp dhcp-authorized dns-zones kerberos ldap'

actual="$(grep -E '^run_capability ' "$SCRIPT" | awk '{print $2}' | sort | tr '\n' ' ' | sed 's/ $//')"

if [ -z "$actual" ]; then
  printf 'FAIL: no run_capability invocations found — this test read nothing\n'
  exit 2
fi

if [ "$actual" = "$EXPECTED" ]; then
  ok "the capability names are exactly the five decided on"
else
  bad "the capability set changed"
  printf '      expected: %s\n' "$EXPECTED"
  printf '      actual:   %s\n' "$actual"
  printf '      A new capability is a new stored value on a client card. Decide what\n'
  printf '      it is called, in US English, and add it here.\n'
fi

# ---------------------------------------------------------------------------
# The states and the outcomes
# ---------------------------------------------------------------------------

states="$(grep -oE 'state="[a-z-]+"' "$SCRIPT" | sed 's/state="//;s/"//' | sort -u | tr '\n' ' ' | sed 's/ $//')"
[ "$states" = "not-asked reached refused" ] \
  && ok "the three states are the ones the portal parses" \
  || bad "states changed: '${states}'"

outcomes="$(grep -oE '"outcome":"[a-z-]+"' "$SCRIPT" | sed 's/.*:"//;s/"//' | sort -u | tr '\n' ' ' | sed 's/ $//')"
[ "$outcomes" = "could-not-start ran" ] \
  && ok "the two outcomes are the ones the portal parses" \
  || bad "outcomes changed: '${outcomes}'"

# ---------------------------------------------------------------------------
# Every reason is ASCII, because json_safe deletes anything else
# ---------------------------------------------------------------------------

# LC_ALL=C so the byte class means bytes rather than whatever the locale says.
nonascii="$(LC_ALL=C grep -nE 'say "(REFUSED|NOT ASKED|PARTLY):|CRED_REASON="|reason="' "$SCRIPT" \
  | LC_ALL=C grep -P '[^\x00-\x7f]' || true)"

if [ -z "$nonascii" ]; then
  ok "every line that becomes a stored reason is ASCII"
else
  bad "a stored reason carries bytes json_safe deletes"
  printf '%s\n' "$nonascii" | sed 's/^/      /'
  printf '      json_safe is tr -cd [:print:], so these arrive at the portal with the\n'
  printf '      character missing rather than replaced. Use a plain apostrophe and a\n'
  printf '      plain hyphen.\n'
fi

# ---------------------------------------------------------------------------
# A second net under the set, for the spelling itself
# ---------------------------------------------------------------------------
#
# **The set above is the mechanism; this is a net.** It is a shape check over
# the tokens only -- five short identifiers we chose, not prose -- so it is a
# roster in a place where the domain is closed and tiny. It exists to catch the
# spelling at the moment somebody widens the set, which is the moment the
# assertion above sends them here.

if printf '%s\n' "$actual" | LC_ALL=C grep -qE '(ised|isation|our-|-our|ence-|ogue|centre|licence)'; then
  bad "a capability name looks like British English: ${actual}"
else
  ok "no capability name carries a British spelling"
fi

# ---------------------------------------------------------------------------

printf '\n%s\n' "checks: ${checks}, failures: ${fails}"

if [ "$checks" -eq 0 ]; then
  printf 'FAIL: nothing was checked, so this run is evidence about nothing.\n'
  exit 2
fi

if [ "$fails" -ne 0 ]; then
  printf 'FAIL: a value this appliance stores in the portal is not what was decided.\n'
  exit 1
fi

printf 'PASS: every stored value is US English and ASCII.\n'
