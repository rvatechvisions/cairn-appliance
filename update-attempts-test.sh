#!/usr/bin/env bash
#
# The run report carries this box's update attempts, and a run that reached its
# end says so. WO-1018-N62 item 1, slice 6.
#
# ## What is held
#
# **A binary that keeps the ledger has its list carried whole** as the run
# report's updateAttempts, so the portal can write each attempt once.
#
# **A binary that predates the ledger leaves the field out.** It does not know
# -update-attempts and exits with its usage. Nothing is invented in its place:
# the portal reads an absent field as none reported, never as none made.
#
# **Anything that is not a list is left out too**, rather than sent as a field
# the portal would have to refuse.
#
# **The completion marker is the run's last act before its exit**, and only
# where the caller named a file. A run that died before it leaves no file, and
# only that may move a release on trial back.
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
eval "$(lift update_attempts_json)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

stub() {
  local name="$1" body="$2"
  printf '#!/usr/bin/env bash\n%s\n' "$body" >"${work}/${name}"
  chmod +x "${work}/${name}"
  printf '%s' "${work}/${name}"
}

ledger='[{"attemptId":"11111111-1111-4111-8111-111111111111","outcome":"held-not-applied","sequence":2,"boxTime":"2026-10-18T05:00:00Z"}]'
keeper="$(stub keeper "[ \"\$1\" = -update-attempts ] && printf '%s\n' '${ledger}'")"
update_attempts_json "$keeper"
[ "$UPDATE_ATTEMPTS_JSON" = ",\"updateAttempts\":${ledger}" ] \
  && ok "a binary that keeps the ledger has its list carried whole" \
  || bad "the list was carried as ${UPDATE_ATTEMPTS_JSON}"

older="$(stub older 'echo "flag provided but not defined: -update-attempts" >&2; exit 2')"
update_attempts_json "$older"
[ -z "$UPDATE_ATTEMPTS_JSON" ] \
  && ok "a binary that predates the ledger leaves the field out" \
  || bad "an older binary produced ${UPDATE_ATTEMPTS_JSON}"

garbled="$(stub garbled 'echo "the update ledger could not be read"; exit 0')"
update_attempts_json "$garbled"
[ -z "$UPDATE_ATTEMPTS_JSON" ] \
  && ok "an answer that is not a list is left out" \
  || bad "a non-list produced ${UPDATE_ATTEMPTS_JSON}"

update_attempts_json "${work}/absent"
[ -z "$UPDATE_ATTEMPTS_JSON" ] \
  && ok "no binary at the path leaves the field out" \
  || bad "an absent binary produced ${UPDATE_ATTEMPTS_JSON}"

# The marker is written after the run's last word and before its exit line.
marker_line="$(grep -n 'CAIRN_RUN_COMPLETED_FILE"$' "$SCRIPT" | tail -n 1 | cut -d: -f1)"
said_line="$(grep -n '^say "Nothing was collected and nothing on the domain was changed."$' "$SCRIPT" | cut -d: -f1)"
exit_line="$(grep -n '^\[ "\$REFUSED" -eq 0 \]$' "$SCRIPT" | cut -d: -f1)"
if [ -n "$marker_line" ] && [ -n "$said_line" ] && [ -n "$exit_line" ] && [ "$marker_line" -gt "$said_line" ] && [ "$marker_line" -lt "$exit_line" ]; then
  ok "the completion marker is written after the run's last word and before its exit"
else
  bad "the completion marker is not between the run's last word (${said_line:-none}) and its exit (${exit_line:-none}): ${marker_line:-none}"
fi
if sed -n "$((marker_line - 1))p" "$SCRIPT" | grep -q 'if \[ -n "\${CAIRN_RUN_COMPLETED_FILE:-}" \]; then'; then
  ok "and only where the caller named a file"
else
  bad "the marker is written whether or not the caller named a file"
fi

printf '%s checks, %s failed\n' "$checks" "$fails"
[ "$fails" -eq 0 ]
