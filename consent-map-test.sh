#!/usr/bin/env bash
#
# The step-to-capability mapping in consent.sh.
#
# Every step preflight.sh runs maps to a capability or to the prerequisite, and
# a step that does not is refused rather than run. A new step with no mapping
# fails here, loudly, rather than defaulting to permitted.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/consent.sh"

failures=0
ok()  { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }

steps="$(grep -E '^run_capability ' "${HERE}/preflight.sh" | awk '{print $2}')"
count="$(printf '%s\n' "$steps" | grep -c . || true)"
if [ "$count" -lt 5 ]; then
  printf 'FAIL: read %s run_capability steps from preflight.sh; expected at least 5. This test read nothing it can trust.\n' "$count"
  exit 1
fi

for step in $steps; do
  needs="$(step_capability "$step")"
  if [ "$needs" = UNMAPPED ]; then
    bad "step ${step} maps to no capability"
  else
    ok "step ${step} needs ${needs}"
  fi
done

[ "$(step_capability some-new-step)" = UNMAPPED ] && ok "an unknown step is UNMAPPED" || bad "an unknown step was given a capability"
step_permitted some-new-step "ad,dhcp,snmp" && bad "an unmapped step was permitted" || ok "an unmapped step is refused even with everything granted"

step_permitted dhcp-authorized "dhcp" && bad "dhcp-authorized ran on DHCP consent alone; it reads Active Directory" || ok "dhcp-authorized needs AD consent"
step_permitted dhcp-authorized "ad" && ok "dhcp-authorized runs on AD consent" || bad "dhcp-authorized refused with AD granted"
step_permitted dhcp "ad" && bad "dhcp ran on AD consent" || ok "dhcp needs DHCP consent"
step_permitted ldap "" && bad "ldap ran with nothing granted" || ok "nothing granted permits no step"
step_permitted kerberos "" && bad "kerberos ran with nothing granted" || ok "the prerequisite does not run with nothing granted"
step_permitted kerberos "dhcp" && ok "the prerequisite runs when anything is granted" || bad "kerberos refused with DHCP granted"
step_permitted ldap "xad" && bad "a partial name matched" || ok "matching is by whole name"

if [ "$failures" -gt 0 ]; then
  printf '\n%s failure(s)\n' "$failures"
  exit 1
fi
printf '\nall passed\n'
