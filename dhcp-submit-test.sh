#!/usr/bin/env bash
#
# The scheduled DHCP step submits, or says plainly that it did not.
# WO-1001-A item 1.
#
# ## What this holds
#
# Until 1 October 2026 the step called the binary with -server, the probe,
# which prints what it read on this box and sends the portal nothing; the mode
# that submits was called from nowhere. So:
#
# **Without CAIRN_DHCP_SUBMIT=yes the step calls the probe and says so** -- on
# the screen, and in the note the run report carries -- so a probe cannot read
# as a delivery.
#
# **With it, the step calls -collect-dhcp against the portal named**, and the
# note counts the servers submitted.
#
# **With it and no portal, nothing is asked**, rather than a submission
# addressed to nowhere.
#
# The binary is a stand-in that records how it was called: the subject is the
# script's choice of mode, not the binary.
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
eval "$(lift capability_dhcp)"
say() { printf '%s\n' "$*"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "${work}/preflight"
calls="${work}/calls"
cat >"${work}/preflight/preflight" <<STUB
#!/usr/bin/env bash
if [ "\${1:-}" = "-version" ]; then echo "preflight 2026.10.01 0000000000000000000000000000000000000000"; exit 0; fi
printf '%s\n' "\$*" >>"${calls}"
echo "read 2 scopes"
STUB
chmod +x "${work}/preflight/preflight"

run_step() {
  HERE="$work" KERBEROS_OK=0 PRINCIPAL="svc@LAB.EXAMPLE" DHCP_SERVERS="dhcp01.lab.example"
  FOUND=0 REFUSED=0 UNASKED=0 CAP_NOTE=""
  : >"$calls"
  OUT="$(capability_dhcp)" ; capability_dhcp >/dev/null
}

# Held on the probe.
unset CAIRN_DHCP_SUBMIT
CAIRN_PORTAL="https://portal.example"
run_step
[ "$(head -n 1 "$calls")" = "-server dhcp01.lab.example" ] && ok "without the setting, the probe is called" || bad "called: $(cat "$calls")"
grep -q -- '-collect-dhcp' "$calls" && bad "the probe run submitted" || ok "nothing is submitted without the setting"
case "$CAP_NOTE" in *"nothing was submitted"*) ok "the note says nothing was submitted" ;; *) bad "note: $CAP_NOTE" ;; esac
case "$OUT" in *"NOT SUBMITTED"*) ok "the screen says nothing was submitted" ;; *) bad "printed: $OUT" ;; esac
[ "$FOUND" -eq 1 ] && ok "the probe still answers the capability" || bad "found: $FOUND"

# Submitting.
CAIRN_DHCP_SUBMIT=yes
run_step
[ "$(head -n 1 "$calls")" = "-portal https://portal.example -collect-dhcp -server dhcp01.lab.example" ] && ok "with the setting, collect mode is called against the portal named" || bad "called: $(cat "$calls")"
[ "$CAP_NOTE" = "submitted to the portal from 1 of 1 DHCP server(s)" ] && ok "the note counts what was submitted" || bad "note: $CAP_NOTE"

# Submitting, and no portal named.
CAIRN_PORTAL=""
run_step
[ ! -s "$calls" ] && ok "with the setting and no portal, nothing is run" || bad "called: $(cat "$calls")"
[ "$UNASKED" -eq 1 ] && ok "and it is not asked, rather than refused" || bad "unasked: $UNASKED"

printf '\n%s checks, %s failed\n' "$checks" "$fails"
[ "$fails" -eq 0 ]
