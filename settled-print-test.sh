#!/usr/bin/env bash
#
# Nothing is printed before it is settled, and the script says which commit it
# is. WO-1004-RS items 5 and 6.
#
# ## What this holds
#
# - The opening banner prints no domain, controller, account or DHCP server.
#   It printed the settings file's values with no source, on a box where the
#   portal supplies all four.
# - A "settled for this run:" block comes after the DHCP servers are chosen
#   and before consent is settled, and names each of the four with where it
#   came from.
# - script_line, which that block prints first, names the commit and whether a
#   tracked file is edited on the box, and says "commit not known" with git's
#   reason rather than printing nothing when git cannot answer. Driven against
#   a throwaway repository in each of the three states.
#
set -uo pipefail

HERE_TEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE_TEST}/preflight.sh"

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

if [ ! -r "$SCRIPT" ]; then
  printf 'FAIL: cannot read %s\n' "$SCRIPT"
  exit 2
fi
if ! command -v git > /dev/null; then
  printf 'FAIL: git is not on the PATH, so script_line cannot be driven\n'
  exit 2
fi

lift() {
  local name="$1" body
  body="$(sed -n "/^${name}() {\$/,/^}\$/p" "$SCRIPT")"
  if [ -z "$body" ]; then
    echo "FATAL: preflight.sh defines no ${name}(), so there is nothing to test."
    exit 2
  fi
  printf '%s\n' "$body"
}

# --- the opening banner ------------------------------------------------------

banner="$(sed -n '/^say "Cairn appliance preflight"$/,/^# -----/p' "$SCRIPT")"
if [ -z "$banner" ]; then
  echo "FATAL: no opening banner found, so there is nothing to read."
  exit 2
fi
if printf '%s\n' "$banner" | grep -Eq '\$\{?(REALM|DC|PRINCIPAL|DHCP_SERVERS|CAIRN_[A-Z_]+)([^A-Z_]|$)'; then
  bad "the opening banner prints a value before it is settled: $(printf '%s\n' "$banner" | grep -E '\$\{?(REALM|DC|PRINCIPAL|DHCP_SERVERS|CAIRN_)')"
else
  ok "the opening banner prints no domain, controller, account or DHCP server"
fi

# --- the settled block -------------------------------------------------------

order="$(grep -nE '^(choose_dhcp_servers |say "settled for this run:"$|script_line$|settle_consent$)' "$SCRIPT" | cut -d: -f2- | cut -c1-24 | tr '\n' '|')"
case "$order" in
  'choose_dhcp_servers "$PC|say "settled for this ru|script_line|settle_consent|')
    ok "the settled block comes after the DHCP servers are chosen and before consent, with the script line first" ;;
  *) bad "the settled block is out of order or missing: ${order}" ;;
esac

settled="$(sed -n '/^say "settled for this run:"$/,/^settle_consent$/p' "$SCRIPT")"
for field in realm dc principal; do
  upper="$(printf '%s' "$field" | tr 'a-z' 'A-Z')"
  if printf '%s\n' "$settled" | grep -q "(from \${${upper}_FROM})"; then
    ok "the settled ${field} line names where it came from"
  else
    bad "the settled ${field} line does not name its source"
  fi
done
if printf '%s\n' "$settled" | grep -q '(from ${DHCP_SERVERS_FROM})' \
   && printf '%s\n' "$settled" | grep -q 'none asked: ${DHCP_REFUSAL}'; then
  ok "the settled DHCP line names its source, or why none was asked"
else
  bad "the settled DHCP line names neither its source nor why none was asked"
fi

# --- script_line, driven -----------------------------------------------------

say() { printf '%s\n' "$*"; }
eval "$(lift script_identity)"
eval "$(lift script_line)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
HERE="$work/repo"
mkdir -p "$HERE"
git -C "$HERE" init -q
git -C "$HERE" config user.email test@example.com
git -C "$HERE" config user.name test
printf 'one\n' > "$HERE/preflight.sh"
git -C "$HERE" add preflight.sh
git -C "$HERE" commit -q -m one
commit="$(git -C "$HERE" rev-parse HEAD)"

line="$(script_line)"
[ "$line" = "script    preflight.sh at ${commit}, no tracked file edited on this box" ] \
  && ok "a clean checkout names its commit and says nothing is edited" \
  || bad "a clean checkout printed: ${line}"

printf 'untracked\n' > "$HERE/scratch.txt"
line="$(script_line)"
[ "$line" = "script    preflight.sh at ${commit}, no tracked file edited on this box" ] \
  && ok "an untracked file does not make the script read as edited" \
  || bad "an untracked file was read as an edit: ${line}"

printf 'two\n' > "$HERE/preflight.sh"
line="$(script_line)"
[ "$line" = "script    preflight.sh at ${commit}, WITH A TRACKED FILE EDITED ON THIS BOX" ] \
  && ok "an edited tracked file is said in capitals beside the commit" \
  || bad "an edited tracked file printed: ${line}"

HERE="$work/not-a-repo"
mkdir -p "$HERE"
line="$(GIT_CEILING_DIRECTORIES="$work" script_line)"
case "$line" in
  "script    preflight.sh, commit not known: git could not say which commit this script is: "?*)
    ok "outside a repository the line says the commit is not known and why" ;;
  *) bad "outside a repository the line printed: ${line}" ;;
esac

echo
if [ "$checks" -lt 10 ]; then
  echo "FAIL: only ${checks} check(s) ran; the walk is narrower than this file says."
  exit 1
fi
if [ "$fails" -ne 0 ]; then
  echo "FAIL: ${fails} of ${checks} settled-print check(s) failed."
  exit 1
fi
echo "PASS: ${checks} checks; nothing is printed before it is settled, and the script names itself."
