#!/usr/bin/env bash
#
# A refusal is something the other end said; an exit code is something our
# process did. WO-1004-M items 1, 2 and 6.
#
# ## What this holds
#
# - read_reader, which Zabbix, vSphere, Configuration Manager and Proxmox VE
#   share, reads what the binary said: an empty list is EMPTY, the far end's
#   own refusal is REFUSED, and anything else is COULD NOT TELL -- never
#   REFUSED for an exit code. Exit 0 and 3 keep their meanings.
# - run_capability turns each of the six counters into its own state in the
#   run report: reached, empty, refused, could-not-tell, not-asked and
#   could-not-run. Empty carries its note, could-not-tell its reason, and a
#   step that recorded no reason does not send a reader to output they cannot
#   reach.
# - The run report says which of three things happened when it did not land:
#   the portal answered and refused it, the box could not reach the portal,
#   or it never left the box. Only the first says the portal refused.
# - kinit succeeding with no usable ticket is NOT RUN, never REFUSED.
#
# The binaries are stand-ins that print the sentences the real one prints,
# copied from preflight/*.go: the subject is the script's reading of them.
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
say() { printf '%s\n' "$*"; }
for fn in read_reader json_safe first_reason run_capability submit_run_report; do
  eval "$(lift "$fn")"
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
CAIRN_PORTAL="https://portal.example"

counters() { FOUND=0 EMPTY=0 REFUSED=0 UNTOLD=0 UNASKED=0 NOTRUN=0 CAP_NOTE="" CAP_SCOPES=""; }

# --- read_reader ----------------------------------------------------------
reader() {
  local mode="$1" stub="${work}/reader"
  cat >"$stub" <<STUB
#!/usr/bin/env bash
case "${mode}" in
  found) echo "submitted 3 hosts" ; exit 0 ;;
  notasked) echo "preflight: not asked: Zabbix is not among what this organization has allowed the collector to read" >&2 ; exit 3 ;;
  empty) echo "preflight: the Zabbix server listed no host this token may read, so nothing was sent" >&2 ; exit 1 ;;
  refused) echo "preflight: vCenter refused the account (401)" >&2 ; exit 1 ;;
  failed) echo "preflight: reaching the Zabbix server: dial tcp 10.0.0.9:443: i/o timeout" >&2 ; exit 1 ;;
  portal) echo "preflight: refused (400): The submission is not the shape the contract describes: items. It will be refused identically every time, so fix the sender rather than retrying." >&2 ; exit 1 ;;
  relayportal) echo "preflight: the portal refused the request for work (403)" >&2 ; exit 1 ;;
  connrefused) echo 'preflight: reaching vCenter: Post "https://vc.example.com/api/session": dial tcp 10.0.0.9:443: connect: connection refused' >&2 ; exit 1 ;;
esac
STUB
  chmod +x "$stub"
  counters
  OUT="$(read_reader "$stub" -collect-zabbix "the Zabbix server" "hosts")"
  read_reader "$stub" -collect-zabbix "the Zabbix server" "hosts" >/dev/null
}

reader found
[ "$FOUND" -eq 1 ] && ok "exit 0 is answered" || bad "found ${FOUND}"
reader notasked
[ "$UNASKED" -eq 1 ] && [ "$REFUSED" -eq 0 ] && ok "exit 3 is not asked" || bad "unasked ${UNASKED}, refused ${REFUSED}"
reader empty
[ "$EMPTY" -eq 1 ] && [ "$REFUSED" -eq 0 ] && [ "$UNTOLD" -eq 0 ] && ok "an empty list is empty, not a refusal" || bad "empty ${EMPTY}, refused ${REFUSED}, untold ${UNTOLD}"
case "$OUT" in *"EMPTY: the Zabbix server answered and listed no hosts, so nothing was sent."*) ok "and it says so" ;; *) bad "printed: ${OUT}" ;; esac
reader refused
[ "$REFUSED" -eq 1 ] && [ "$UNTOLD" -eq 0 ] && ok "the far end's own refusal is a refusal" || bad "refused ${REFUSED}, untold ${UNTOLD}"
case "$OUT" in *"REFUSED: vCenter refused the account (401)"*) ok "and it is stated in the binary's words, not sent to read output above" ;; *) bad "printed: ${OUT}" ;; esac
reader failed
[ "$UNTOLD" -eq 1 ] && [ "$REFUSED" -eq 0 ] && ok "a failure is could not tell, never a refusal" || bad "untold ${UNTOLD}, refused ${REFUSED}"
case "$OUT" in *"COULD NOT TELL: the Zabbix server did not answer with hosts"*"reaching the Zabbix server"*) ok "and the stored line quotes what happened" ;; *) bad "printed: ${OUT}" ;; esac
# WO-1004-T item 2: the portal's words say "refused" too, and they are Cairn's.
reader portal
[ "$UNTOLD" -eq 1 ] && [ "$REFUSED" -eq 0 ] && ok "the portal refusing a submission is not the far end refusing" || bad "a portal refusal was charged to the far end: untold ${UNTOLD}, refused ${REFUSED}: ${OUT}"
case "$OUT" in *"COULD NOT TELL: Cairn's portal refused what this box sent for the Zabbix server"*"refused (400)"*) ok "and it says whose refusal it was, in the portal's words" ;; *) bad "printed: ${OUT}" ;; esac
reader relayportal
[ "$UNTOLD" -eq 1 ] && [ "$REFUSED" -eq 0 ] && ok "the portal refusing the relay's request for work is not the far end refusing" || bad "a relay portal refusal was charged to the far end: untold ${UNTOLD}, refused ${REFUSED}"
reader connrefused
[ "$UNTOLD" -eq 1 ] && [ "$REFUSED" -eq 0 ] && ok "a connection refused at the end of the line is could not tell" || bad "connection refused was read as a refusal: untold ${UNTOLD}, refused ${REFUSED}"

# --- run_capability: six counters, six states -----------------------------
CONSENT_KNOWN=1 CONSENTED="all"
step_permitted() { return 0; }
step_reached() { FOUND=$((FOUND + 1)); }
step_empty() { say "EMPTY: it answered with nothing."; CAP_NOTE="1 of 1 answered empty"; CAP_SCOPES='{"attempted":1,"unreadable":0,"empty":1}'; EMPTY=$((EMPTY + 1)); }
step_refused() { say "REFUSED: the far end said no."; REFUSED=$((REFUSED + 1)); return 1; }
step_untold() { say "COULD NOT TELL: no answer this run could read."; UNTOLD=$((UNTOLD + 1)); return 1; }
step_unasked() { say "NOT ASKED: nothing named."; UNASKED=$((UNASKED + 1)); return 1; }
step_silent() { REFUSED=$((REFUSED + 1)); return 1; }
counters
CAP_JSON=""
for s in reached empty refused untold unasked silent; do run_capability "$s" "step_${s}" >/dev/null || true; done
case "$CAP_JSON" in *'{"name":"reached","state":"reached"}'*) ok "reached is reached" ;; *) bad "json: ${CAP_JSON}" ;; esac
case "$CAP_JSON" in *'{"name":"empty","state":"empty","note":"1 of 1 answered empty","scopes":{"attempted":1,"unreadable":0,"empty":1}}'*) ok "empty is its own state, with its note and its scope counts" ;; *) bad "json: ${CAP_JSON}" ;; esac
case "$CAP_JSON" in *'{"name":"refused","state":"refused","reason":"the far end said no."}'*) ok "refused carries the far end's reason" ;; *) bad "json: ${CAP_JSON}" ;; esac
case "$CAP_JSON" in *'{"name":"untold","state":"could-not-tell","reason":"no answer this run could read."}'*) ok "could not tell is its own state, never refused" ;; *) bad "json: ${CAP_JSON}" ;; esac
case "$CAP_JSON" in *'{"name":"unasked","state":"not-asked","reason":"nothing named."}'*) ok "not asked is not asked" ;; *) bad "json: ${CAP_JSON}" ;; esac
case "$CAP_JSON" in *"read the appliance output"*) bad "a stored reason sends the reader to output they cannot reach: ${CAP_JSON}" ;; *) ok "no stored reason sends a reader to the appliance output" ;; esac
case "$CAP_JSON" in *'"name":"silent","state":"refused","reason":"preflight.sh recorded no reason for this step, which is a fault in the script'*) ok "a step with no reason line says it is a fault in the script" ;; *) bad "json: ${CAP_JSON}" ;; esac

# --- the run report: three ways not to land --------------------------------
CONFIG_DIR="${work}/config"
mkdir -p "$CONFIG_DIR" "${work}/preflight"
: >"${CONFIG_DIR}/appliance.key"
binary_report_json() { BINARY_JSON=""; }
consent_report_json() { CONSENT_JSON=""; }
script_report_json() { SCRIPT_JSON=""; }
RUN_STARTED="2026-10-05T09:00:00Z" CRED_FAILED=0 CAP_JSON='{"name":"kerberos","state":"reached"}' CREDENTIAL_SOURCE="portal"
report() {
  local mode="$1"
  cat >"${work}/preflight/preflight" <<STUB
#!/usr/bin/env bash
cat >/dev/null
case "${mode}" in
  accepted) echo "run reported" ; exit 0 ;;
  refused) echo "preflight: refused (400): A run that ran reports at least one capability." >&2 ; exit 1 ;;
  unreachable) echo "preflight: reaching the portal: dial tcp: lookup portal.example: no such host" >&2 ; exit 1 ;;
  local) echo "preflight: generating a nonce: entropy source unavailable" >&2 ; exit 1 ;;
esac
STUB
  chmod +x "${work}/preflight/preflight"
  OUT="$(HERE="$work" submit_run_report 2>&1)"
}
report accepted
case "$OUT" in *"REPORTED: the portal accepted this run's report."*) ok "an accepted report says so" ;; *) bad "printed: ${OUT}" ;; esac
report refused
case "$OUT" in *"NOT REPORTED: the portal answered and refused the report: refused (400): A run that ran reports"*) ok "a refusal by the portal is said as the portal's, in its words" ;; *) bad "printed: ${OUT}" ;; esac
report unreachable
case "$OUT" in *"NOT REPORTED: this box could not reach the portal, so the portal said nothing."*) ok "no route to the portal is not a refusal by it" ;; *) bad "printed: ${OUT}" ;; esac
case "$OUT" in *"portal answered and refused"*) bad "an unreachable portal is called a refusal: ${OUT}" ;; *) ok "and it is not called one" ;; esac
report local
case "$OUT" in *"NOT REPORTED: the report did not leave this box (exit 1): generating a nonce"*"a fault on this box, not an answer from the portal"*) ok "a failure on this box is said as this box's" ;; *) bad "printed: ${OUT}" ;; esac

# --- kinit with no usable ticket -------------------------------------------
kerberos="$(lift capability_kerberos)"
branch="$(printf '%s\n' "$kerberos" | sed -n '/kinit reported success and the cache holds no usable ticket/,/return 1/p')"
[ -n "$branch" ] && ok "the no-usable-ticket branch was found" || bad "the no-usable-ticket branch is gone"
printf '%s\n' "$branch" | grep -q 'NOTRUN=\$((NOTRUN + 1))' && ok "it counts as not run, a fault on this box" || bad "branch: ${branch}"
printf '%s\n' "$branch" | grep -q 'REFUSED' && bad "it still says or counts a refusal: ${branch}" || ok "and it neither says nor counts a refusal"

printf '\n%s checks, %s failed\n' "$checks" "$fails"
[ "$fails" -eq 0 ]
