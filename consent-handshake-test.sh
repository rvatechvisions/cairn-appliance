#!/usr/bin/env bash
#
# A silent line is not an answer. WO-1001-D item 2.
#
# ## What happened
#
# On 1 October 2026 the lab box ran a binary from 23 September under a script
# from that morning. The portal sent a consent list; the binary had no field
# for it and dropped it; the script read the missing line as "the portal sent
# no consent list" and printed NOT ASKED against ten capabilities. Every
# component did what it was written to do, and the sentence an administrator
# would have read blamed the party that had done its job.
#
# ## What this holds
#
# - The script asks the binary what it can hear (-speaks) before asking it
#   anything, and a binary that cannot hear the consent list -- one that
#   rejects the flag, like that 23 September build -- is named as the reason,
#   with what was found.
# - "No consent list was heard" and "the portal sent no consent list" are
#   different sentences, and only a fetch by a binary that declared the list
#   may produce the second.
# - A step consent never reached is NOT RUN: it moves no network counter and
#   adds nothing to the capability list the portal receives.
#
# The binaries are stand-ins that answer -speaks the way each kind of build
# does: the subject is the script's reading of them, not the binary.
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
eval "$(lift binary_hears_consent)"
eval "$(lift settle_consent)"
eval "$(lift step_not_consented)"
eval "$(lift run_capability)"
eval "$(lift first_reason)"
eval "$(lift json_safe)"
. "${HERE}/consent.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A current build: declares the consent list.
cat >"${work}/current" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
  -speaks) echo "credential-block: username realm controller capabilities dhcp-servers" ;;
  -version) echo "preflight no-tag 1111111111111111111111111111111111111111" ;;
esac
STUB
# A build older than -speaks: Go's flag package rejects an unknown flag with
# exit 2, which is what the 23 September binary does.
cat >"${work}/old" <<'STUB'
#!/usr/bin/env bash
case "${1:-}" in
  -speaks) echo "flag provided but not defined: -speaks" >&2; exit 2 ;;
  -version) echo "preflight no-tag 09d3eec37061a042f15259f6454ee1ae99953764" ;;
esac
STUB
chmod +x "${work}/current" "${work}/old"

# --- the handshake ---------------------------------------------------------
status=0; binary_hears_consent "${work}/current" || status=$?
[ "$status" -eq 0 ] && ok "a binary that declares the consent list is heard" || bad "current returned ${status}"

status=0; binary_hears_consent "${work}/old" || status=$?
[ "$status" -eq 1 ] && ok "a binary that rejects -speaks cannot hear the consent list" || bad "old returned ${status}"
case "$BINARY_SPEAKS" in
  *"not defined: -speaks"*) ok "and what it said is kept, to be printed" ;;
  *) bad "BINARY_SPEAKS was: ${BINARY_SPEAKS}" ;;
esac

status=0; binary_hears_consent "${work}/absent" || status=$?
[ "$status" -eq 2 ] && ok "no binary at all is its own answer" || bad "absent returned ${status}"

# --- settling what was heard ----------------------------------------------
PC_CAPABILITIES="dhcp"; PC_CAPABILITIES_SET=1; CONSENT_FETCHED=1; CRED_FAILED=0; CRED_REASON=""
out="$(settle_consent)"; settle_consent >/dev/null
[ "$CONSENT_KNOWN" -eq 1 ] && [ "$CONSENTED" = "dhcp" ] && [ "$CRED_FAILED" -eq 0 ] \
  && ok "a list that arrived is the list" || bad "known=${CONSENT_KNOWN} consented=${CONSENTED} failed=${CRED_FAILED}"

PC_CAPABILITIES=""; PC_CAPABILITIES_SET=0; CONSENT_FETCHED=1; CRED_FAILED=0; CRED_REASON=""
out="$(settle_consent)"; settle_consent >/dev/null
case "$out" in
  *"the portal answered without one"*) ok "a declared binary that fetched no list says the portal sent none" ;;
  *) bad "printed: ${out}" ;;
esac
case "$CRED_REASON" in
  "the portal sent no list"*) ok "and the reported reason names the portal" ;;
  *) bad "reason: ${CRED_REASON}" ;;
esac

PC_CAPABILITIES=""; PC_CAPABILITIES_SET=0; CONSENT_FETCHED=0; CRED_FAILED=0; CRED_REASON=""
CONSENT_UNHEARD="the installed binary (preflight no-tag 09d3eec) is older than the consent list and cannot hear it"
out="$(settle_consent)"; settle_consent >/dev/null
case "$out" in
  *"NO CONSENT LIST WAS HEARD"*"cannot tell whether the portal sent one"*) ok "silence is said to be silence, and that it cannot tell" ;;
  *) bad "printed: ${out}" ;;
esac
case "$out$CRED_REASON" in
  *"portal sent no"*) bad "silence was read as the portal sending nothing: ${out} / ${CRED_REASON}" ;;
  *) ok "nothing blames the portal for what the binary could not hear" ;;
esac
case "$CRED_REASON" in
  *"09d3eec"*) ok "the reported reason names the binary that could not hear" ;;
  *) bad "reason: ${CRED_REASON}" ;;
esac

# --- a step consent never reached ------------------------------------------
FOUND=0 REFUSED=0 UNASKED=0 NOTRUN=0 CAP_JSON=""
CONSENT_KNOWN=0 CONSENTED=""
stub_step() { say "this step ran"; FOUND=$((FOUND + 1)); return 0; }
out="$(run_capability dhcp stub_step)"; run_capability dhcp stub_step >/dev/null
[ "$NOTRUN" -eq 1 ] && ok "an unheard consent marks the step NOT RUN" || bad "notrun=${NOTRUN}"
[ "$UNASKED" -eq 0 ] && [ "$FOUND" -eq 0 ] && [ "$REFUSED" -eq 0 ] \
  && ok "and moves none of the three network counts" || bad "found=${FOUND} refused=${REFUSED} unasked=${UNASKED}"
[ -z "$CAP_JSON" ] && ok "and adds nothing to the capability list the portal receives" || bad "CAP_JSON=${CAP_JSON}"
case "$out" in
  *"NOT ASKED"*) bad "printed NOT ASKED for a step nobody asked: ${out}" ;;
  *"this step ran"*) bad "the step ran without consent: ${out}" ;;
  *"NOT RUN: the installed binary"*) ok "and the screen names the reason, not a verdict" ;;
  *) bad "printed: ${out}" ;;
esac

# --- the order in the script, which no stub can show -----------------------
# The handshake has to come BEFORE the fetch: a fetch by a binary that cannot
# hear the list spends a nonce on a credential handed over without one.
hs="$(grep -n 'binary_hears_consent "\${HERE}/preflight/preflight"' "$SCRIPT" | head -n 1 | cut -d: -f1)"
fe="$(grep -n -- '-fetch -emit-credential' "$SCRIPT" | grep -v '^[0-9]*: *#' | head -n 1 | cut -d: -f1)"
if [ -n "$hs" ] && [ -n "$fe" ] && [ "$hs" -lt "$fe" ]; then
  ok "the handshake comes before the fetch (line ${hs} before ${fe})"
else
  bad "handshake line '${hs}', fetch line '${fe}'"
fi

# And the old sentence is gone from everything the script prints.
if grep -nE '^[^#]*say .*(the portal sent no consent list|Update the portal before the appliance)' "$SCRIPT"; then
  bad "a printed line still reads silence as the portal's answer (above)"
else
  ok "no printed line reads silence as the portal sending nothing"
fi

printf '\n%s checks, %s failed\n' "$checks" "$fails"
[ "$fails" -eq 0 ]
