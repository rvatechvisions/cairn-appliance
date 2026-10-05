#!/usr/bin/env bash
#
# Where the credential came from is not a capability. WO-1004-L item 2.
#
# ## What happened
#
# The first reading from RVA's own appliance, on 4 October 2026, printed
# "found: 2 (including step 0, where the credential came from)" and "PARTLY
# PROVEN: 2 capabilit(ies) answered" over a run that answered one capability,
# Kerberos. Step 0 moved the same counters the capabilities move, so the tally
# counted a fact about this box as a fact about the customer's network, and
# disagreed with the portal, which never counted it.
#
# ## What this holds
#
# - The credential step moves none of FOUND, REFUSED, UNASKED or NOTRUN, on
#   any path. Held over the function's source, because the enrolled paths need
#   a root-owned key this suite cannot make, and a behavioral test of the two
#   paths it can reach would stay green if an enrolled path counted again.
# - The two paths reachable here set CREDENTIAL_FROM and CREDENTIAL_SOURCE.
# - Every CREDENTIAL_SOURCE the step can set is one the portal's column
#   accepts, and one the run report sends.
# - The tally prints the credential on its own line and no longer says
#   "including step 0".
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

lift() {
  local name="$1" body
  body="$(sed -n "/^${name}() {\$/,/^}\$/p" "$SCRIPT")"
  if [ -z "$body" ]; then
    echo "FATAL: preflight.sh defines no ${name}(), so there is nothing to test."
    exit 2
  fi
  printf '%s\n' "$body"
}

body="$(lift capability_credential_source)"
lines="$(printf '%s\n' "$body" | wc -l)"
[ "$lines" -gt 100 ] && ok "the credential step was lifted whole (${lines} lines)" || bad "lifted only ${lines} lines"

counted="$(printf '%s\n' "$body" | grep -nE '(FOUND|REFUSED|UNASKED|NOTRUN)=\$\(\(')"
[ -z "$counted" ] && ok "the credential step moves no capability counter" || bad "it counts: ${counted}"

# The values it can set, and the seven the portal's check accepts.
accepted="portal portal-incomplete portal-failed not-fetched environment terminal none"
set_values="$(printf '%s\n' "$body" | sed -n 's/^ *CREDENTIAL_SOURCE="\([^"]*\)"$/\1/p' | sort -u)"
[ "$(printf '%s\n' "$set_values" | wc -l)" -ge 6 ] && ok "the step sets a source on every path ($(printf '%s' "$set_values" | tr '\n' ' '))" || bad "sets only: ${set_values}"
for value in $set_values; do
  case " $accepted " in
    *" $value "*) ok "${value} is a value the portal's column accepts" ;;
    *) bad "${value} is not a value the portal's column accepts" ;;
  esac
done
reported="$(grep -m 1 '    portal|portal-incomplete|' "$SCRIPT" | tr -d ' )')"
[ "$reported" = "portal|portal-incomplete|portal-failed|not-fetched|environment|terminal|none" ] && ok "the run report sends exactly the seven" || bad "the report sends: ${reported}"

# The two paths reachable without a root-owned key.
eval "$body"
say() { printf '%s\n' "$*"; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
CONFIG_DIR="$work" SETTINGS="${work}/settings.env" HERE="$work"
CAIRN_PORTAL="" PRINCIPAL="svc@LAB.EXAMPLE"

FOUND=0 REFUSED=0 UNASKED=0 NOTRUN=0 CRED_FAILED=0 CRED_REASON="" CREDENTIAL_TYPED=0
CREDENTIAL_FROM="unset" CREDENTIAL_SOURCE=""
CAIRN_PASSWORD="not-a-real-password"
capability_credential_source >/dev/null </dev/null
[ "$CREDENTIAL_SOURCE" = "environment" ] && ok "a password in the environment is said as the environment" || bad "source: ${CREDENTIAL_SOURCE}"
[ "$FOUND$REFUSED$UNASKED$NOTRUN" = "0000" ] && ok "and it counts as no capability" || bad "counted: found ${FOUND}, refused ${REFUSED}, unasked ${UNASKED}, not run ${NOTRUN}"
unset CAIRN_PASSWORD

FOUND=0 REFUSED=0 UNASKED=0 NOTRUN=0 CRED_FAILED=0 CRED_REASON=""
CREDENTIAL_FROM="unset" CREDENTIAL_SOURCE=""
capability_credential_source >/dev/null </dev/null
[ "$CREDENTIAL_SOURCE" = "none" ] && [ "$CRED_FAILED" -eq 1 ] && ok "no source and no terminal is said as none, and the run cannot start" || bad "source: ${CREDENTIAL_SOURCE}, failed: ${CRED_FAILED}"
[ "$FOUND$REFUSED$UNASKED$NOTRUN" = "0000" ] && ok "and it counts as no capability either" || bad "counted: found ${FOUND}, refused ${REFUSED}, unasked ${UNASKED}, not run ${NOTRUN}"

# The tally.
grep -q 'including step 0' "$SCRIPT" && bad "the tally still counts step 0" || ok "the tally no longer counts step 0"
grep -qE '^say "credential: +[$][{]CREDENTIAL_FROM[}]' "$SCRIPT" && ok "the tally prints the credential on its own line" || bad "no credential line in the tally"

printf '\n%s checks, %s failed\n' "$checks" "$fails"
[ "$fails" -eq 0 ]
