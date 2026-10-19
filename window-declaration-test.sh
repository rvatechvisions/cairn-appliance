#!/usr/bin/env bash
#
# The run window this box declares. WO-1019-N75 item 4.
#
# ## What this holds
#
# - run_window_json prints the window whole, in the shape the portal keeps,
#   and nothing at all for any value it cannot read as what it claims to be.
# - The service unit's declaration agrees with the timer it describes: the
#   window opens at the timer's OnCalendar time of day and lasts its
#   RandomizedDelaySec plus the service's TimeoutStartSec. A unit whose timer
#   and declaration disagree fails here, loudly, naming both.
# - declare_window declares nothing on a hand run, the window on a scheduled
#   one, and nothing beside a sentence saying why when a value is unreadable.
# - preflight.sh sources it and sends the field on both kinds of run report.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${HERE}/run-window.sh"
SCRIPT="${HERE}/preflight.sh"
TIMER="${HERE}/systemd/cairn-preflight.timer"
SERVICE="${HERE}/systemd/cairn-preflight.service"

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

for file in "$LIB" "$SCRIPT" "$TIMER" "$SERVICE"; do
  if [ ! -r "$file" ]; then
    printf 'FAIL: cannot read %s\n' "$file"
    exit 2
  fi
done

SAID=""
say() { SAID="${SAID}$1"$'\n'; }
# shellcheck source=run-window.sh
. "$LIB"

# 1. The field, whole or not at all.
got="$(run_window_json 05:00 75 America/New_York)"
want=',"window":{"opensAt":"05:00","timeZone":"America/New_York","minutes":75}'
[ "$got" = "$want" ] && ok "a readable window is sent whole: $got" || bad "a readable window: got '$got', want '$want'"

for bad_input in "5:00 75 America/New_York" "25:00 75 America/New_York" "05:00 0 America/New_York" "05:00 1441 America/New_York" "05:00 75x America/New_York" "05:00 75 Not_A_Zone" "05:00 75 " ; do
  # shellcheck disable=SC2086
  set -- $bad_input
  out="$(run_window_json "${1:-}" "${2:-}" "${3:-}")"; status=$?
  if [ "$status" -ne 0 ] && [ -z "$out" ]; then ok "nothing for '$bad_input'"; else bad "'$bad_input' printed '$out' (status $status)"; fi
done

# 2. The unit and the timer agree.
calendar="$(sed -n 's/^OnCalendar=\*-\*-\* \([0-9][0-9]:[0-9][0-9]\):[0-9][0-9]$/\1/p' "$TIMER")"
delay="$(sed -n 's/^RandomizedDelaySec=\([0-9][0-9]*\)min$/\1/p' "$TIMER")"
timeout="$(sed -n 's/^TimeoutStartSec=\([0-9][0-9]*\)min$/\1/p' "$SERVICE")"
opens="$(sed -n 's/^Environment=CAIRN_WINDOW_OPENS_AT=\(.*\)$/\1/p' "$SERVICE")"
minutes="$(sed -n 's/^Environment=CAIRN_WINDOW_MINUTES=\(.*\)$/\1/p' "$SERVICE")"
if [ -z "$calendar" ] || [ -z "$delay" ] || [ -z "$timeout" ]; then
  printf 'FAIL: could not read the timer (OnCalendar %s, RandomizedDelaySec %s) or the service (TimeoutStartSec %s)\n' "${calendar:-unread}" "${delay:-unread}" "${timeout:-unread}"
  exit 2
fi
[ "$opens" = "$calendar" ] && ok "the window opens at the timer's OnCalendar, $calendar" || bad "the service declares the window opening at '${opens:-unset}' and the timer fires at $calendar"
[ "$minutes" = "$((delay + timeout))" ] && ok "the window lasts the delay plus the run's limit, $delay + $timeout = $minutes" || bad "the service declares '${minutes:-unset}' minutes and the timer's delay plus the run's limit is $((delay + timeout))"

# 3. What a run declares.
box_time_zone() { printf '%s' "$TEST_ZONE"; }
TEST_ZONE="America/New_York"
unset CAIRN_WINDOW_OPENS_AT CAIRN_WINDOW_MINUTES
declare_window
[ -z "$WINDOW_JSON" ] && [ -z "$SAID" ] && ok "a hand run declares nothing and says nothing" || bad "a hand run declared '$WINDOW_JSON' and said '$SAID'"
CAIRN_WINDOW_OPENS_AT=05:00 CAIRN_WINDOW_MINUTES=75 declare_window
[ "$WINDOW_JSON" = "$want" ] && ok "a scheduled run declares the window" || bad "a scheduled run declared '$WINDOW_JSON'"
TEST_ZONE=""
SAID=""
CAIRN_WINDOW_OPENS_AT=05:00 CAIRN_WINDOW_MINUTES=75 declare_window
if [ -z "$WINDOW_JSON" ] && printf '%s' "$SAID" | grep -q 'RUN WINDOW NOT DECLARED'; then ok "an unread zone declares nothing, and says so"; else bad "an unread zone declared '$WINDOW_JSON' and said '$SAID'"; fi

# 4. preflight.sh sources it and sends it on both run reports.
grep -q '^\. "\${HERE}/run-window.sh"$' "$SCRIPT" && ok "preflight.sh sources run-window.sh" || bad "preflight.sh does not source run-window.sh"
sent="$(grep -c "printf '%s%s%s%s%s%s%s}' \"\$interval_json\" \"\$WINDOW_JSON\"" "$SCRIPT")"
[ "$sent" = "2" ] && ok "both run reports carry the window" || bad "the window is sent on $sent of the two run reports"

printf '%s of %s checks failed\n' "$fails" "$checks"
[ "$fails" -eq 0 ] || exit 1
