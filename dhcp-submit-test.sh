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
eval "$(lift keep_submission_digest)"
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
case "\${STUB_MODE:-}" in
  empty)
    echo "scopes: 1 attempted, 0 could not be read completely, 1 empty"
    echo "devices: 0, from leases whose hardware address could be read; 0 refused as unreadable"
    echo "preflight: no lease with a readable hardware address was found, so nothing was sent" >&2
    exit 1 ;;
  partial)
    echo "scopes: 2 attempted, 1 could not be read completely, 1 empty"
    echo "devices: 0, from leases whose hardware address could be read; 0 refused as unreadable"
    echo "preflight: no lease with a readable hardware address was found, so nothing was sent" >&2
    exit 1 ;;
  denied)
    echo "preflight: R_DhcpEnumSubnets: ERROR_ACCESS_DENIED" >&2
    exit 1 ;;
  failed)
    echo "preflight: dial tcp: i/o timeout" >&2
    exit 1 ;;
  noscopes)
    echo "the server answered and serves no scopes. That is an answer, not a refusal; nothing was sent."
    exit 0 ;;
esac
echo "read 2 scopes"
case "\$*" in *-collect-dhcp*) echo "sending 41 bytes, body SHA-256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; echo submitted ;; esac
STUB
chmod +x "${work}/preflight/preflight"

SUBMISSIONS_LOG="${work}/submissions.log"
SETTINGS="${work}/settings.env"
run_step() {
  HERE="$work" KERBEROS_OK=0 PRINCIPAL="svc@LAB.EXAMPLE" DHCP_SERVERS="${STEP_SERVERS-dhcp01.lab.example}"
  DHCP_REFUSAL="${STEP_REFUSAL:-}"
  FOUND=0 REFUSED=0 UNASKED=0 EMPTY=0 UNTOLD=0 CAP_NOTE="" CAP_SCOPES=""
  : >"$calls"
  : >"$SUBMISSIONS_LOG"
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
[ ! -s "$SUBMISSIONS_LOG" ] && ok "a probe keeps no submission digest" || bad "kept: $(cat "$SUBMISSIONS_LOG")"

# Submitting.
CAIRN_DHCP_SUBMIT=yes
run_step
[ "$(head -n 1 "$calls")" = "-portal https://portal.example -collect-dhcp -server dhcp01.lab.example" ] && ok "with the setting, collect mode is called against the portal named" || bad "called: $(cat "$calls")"
[ "$CAP_NOTE" = "submitted to the portal from 1 of 1 DHCP server" ] && ok "the note counts what was submitted" || bad "note: $CAP_NOTE"
grep -Eq "^[0-9T:Z-]+ dhcp01\.lab\.example sending 41 bytes, body SHA-256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\$" "$SUBMISSIONS_LOG" && ok "the submission digest is kept on the box, with the time and the server" || bad "kept: $(cat "$SUBMISSIONS_LOG" 2>&1)"
type keep_submission_digest >/dev/null 2>&1 && ok "the digest keeper was lifted, so its absence would fail here" || bad "keep_submission_digest is not defined"
[ "$EMPTY" -eq 0 ] && ok "a read that sent leases is not counted empty" || bad "empty: $EMPTY"

# WO-1004-L item 1. Submitting, and the one scope the server serves is empty:
# the binary exits non-zero because it had nothing to send. The lines it prints
# are copied from preflight/collect.go. That is a read, not a refusal.
export STUB_MODE=empty
run_step
[ "$REFUSED" -eq 0 ] && ok "an empty scope is not counted as a refusal" || bad "refused: $REFUSED"
# WO-1004-M item 6: empty is its own state now, not a kind of answered.
[ "$FOUND" -eq 0 ] && [ "$EMPTY" -eq 1 ] && [ "$UNTOLD" -eq 0 ] && ok "it is counted as empty, on its own" || bad "found: $FOUND, empty: $EMPTY, untold: $UNTOLD"
# WO-1004-M item 3: the counts, and only the counts, go up with the run.
[ "$CAP_SCOPES" = '{"attempted":1,"unreadable":0,"empty":1}' ] && ok "the scope counts are carried for the run report" || bad "scopes: $CAP_SCOPES"
case "$OUT" in *"EMPTY: 1 of 1 DHCP server answered with every scope read and empty, so nothing was sent."*) ok "the line the report stores says what was read" ;; *) bad "printed: $OUT" ;; esac
case "$OUT" in *"this server refused"*) bad "the screen calls an empty scope a refusal: $OUT" ;; *) ok "the screen does not say refused" ;; esac
case "$OUT" in *"That is a read, not a refusal."*) ok "the screen says it was a read" ;; *) bad "printed: $OUT" ;; esac
case "$OUT" in *"NOT KEPT"*) bad "a read that sent nothing reports a digest missing: $OUT" ;; *) ok "no missing digest is reported when nothing was sent" ;; esac
case "$OUT" in *"nothing was submitted from dhcp01.lab.example, so there is no submission digest to keep."*) ok "the absent digest is said as a non-event" ;; *) bad "printed: $OUT" ;; esac
[ ! -s "$SUBMISSIONS_LOG" ] && ok "and nothing is written to the digest log" || bad "kept: $(cat "$SUBMISSIONS_LOG")"
[ "$CAP_NOTE" = "1 of 1 DHCP server answered with every scope read and empty, so nothing was sent" ] && ok "the note says why nothing was sent" || bad "note: $CAP_NOTE"

# A server serving no scopes exits 0 and says so: an empty answer, not leases.
export STUB_MODE=noscopes
run_step
[ "$FOUND" -eq 0 ] && [ "$EMPTY" -eq 1 ] && ok "a server serving no scopes is empty, not answered" || bad "found: $FOUND, empty: $EMPTY"

# A scope that could not be read completely is not an empty one, and not a
# refusal either: this run cannot tell. WO-1004-M item 1.
export STUB_MODE=partial
run_step
[ "$EMPTY" -eq 0 ] && [ "$REFUSED" -eq 0 ] && [ "$UNTOLD" -eq 1 ] && ok "an incomplete read is could not tell, never empty and never refused" || bad "found: $FOUND, empty: $EMPTY, refused: $REFUSED, untold: $UNTOLD"
case "$OUT" in *"COULD NOT TELL: 1 of 1 DHCP server did not complete the read"*) ok "and the line the report stores says it cannot tell" ;; *) bad "printed: $OUT" ;; esac
[ "$CAP_SCOPES" = '{"attempted":2,"unreadable":1,"empty":1}' ] && ok "and the scope counts still go up" || bad "scopes: $CAP_SCOPES"

# The server said no.
export STUB_MODE=denied
run_step
[ "$REFUSED" -eq 1 ] && [ "$FOUND" -eq 0 ] && [ "$UNTOLD" -eq 0 ] && ok "ERROR_ACCESS_DENIED is counted as a refusal" || bad "found: $FOUND, refused: $REFUSED, untold: $UNTOLD"
case "$OUT" in *"this server refused (ERROR_ACCESS_DENIED)"*) ok "and the screen says refused" ;; *) bad "printed: $OUT" ;; esac
case "$OUT" in *"REFUSED: 1 of 1 DHCP server answered ERROR_ACCESS_DENIED"*) ok "and the line the report stores says who said what, naming no server" ;; *) bad "printed: $OUT" ;; esac
printf '%s\n' "$OUT" | grep '^REFUSED:' | grep -q 'dhcp01' && bad "the stored line names the server: $OUT" || ok "the stored line names no server"

# The read failed with no word from the server: could not tell, its own count.
export STUB_MODE=failed
run_step
[ "$REFUSED" -eq 0 ] && [ "$EMPTY" -eq 0 ] && [ "$UNTOLD" -eq 1 ] && ok "a failure is could not tell, never a refusal and never empty" || bad "found: $FOUND, empty: $EMPTY, refused: $REFUSED, untold: $UNTOLD"
case "$OUT" in *"this server refused"*) bad "a failure is called a refusal: $OUT" ;; *"COULD NOT TELL:"*) ok "and the screen says it cannot tell which" ;; *) bad "printed: $OUT" ;; esac
[ -z "$CAP_SCOPES" ] && ok "and with no counts printed, none are sent" || bad "scopes from nowhere: $CAP_SCOPES"
unset STUB_MODE

# WO-1004-N item 1: the chooser refused to name a server -- the portal named
# none, or the portal and the settings file disagree. Nothing is asked, the
# reason is the NOT ASKED line the run report stores, and the binary is never
# called.
STEP_SERVERS="" STEP_REFUSAL="the portal names no DHCP server, so none is asked. Name the servers on the consent card, under DHCP leases, in DHCP servers, one per line."
run_step
[ ! -s "$calls" ] && ok "a refused choice runs no binary" || bad "called: $(cat "$calls")"
[ "$UNASKED" -eq 1 ] && [ "$REFUSED" -eq 0 ] && [ "$FOUND" -eq 0 ] && ok "and it is not asked, never refused" || bad "found ${FOUND}, refused ${REFUSED}, unasked ${UNASKED}"
case "$OUT" in "NOT ASKED: the portal names no DHCP server, so none is asked."*) ok "the first line is the reason the report stores" ;; *) bad "printed: $OUT" ;; esac
unset STEP_SERVERS STEP_REFUSAL

# Submitting, and no portal named.
CAIRN_PORTAL=""
run_step
[ ! -s "$calls" ] && ok "with the setting and no portal, nothing is run" || bad "called: $(cat "$calls")"
[ "$UNASKED" -eq 1 ] && ok "and it is not asked, rather than refused" || bad "unasked: $UNASKED"

printf '\n%s checks, %s failed\n' "$checks" "$fails"
[ "$fails" -eq 0 ]
