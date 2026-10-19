# shellcheck shell=bash
#
# The run window this box declares, sourced by preflight.sh. WO-1019-N75
# item 4, the portal's APPLIANCE-BINARY-QUEUE.md item 6.
#
# ## Why a box says when it runs
#
# A portal deploy restarts the web process, and a restart in the middle of a
# run breaks the credential fetch or the run report. The deploy asks every box
# whether it is inside the window it declared, and refuses if one is. A box
# that declares nothing cannot be judged, so the deploy goes and a person keeps
# the hour clear by hand. This is what lets it stop being a person.
#
# ## Where the numbers come from
#
# The service unit declares the window beside its interval, as
# CAIRN_WINDOW_OPENS_AT (the timer's OnCalendar time of day) and
# CAIRN_WINDOW_MINUTES (the timer's RandomizedDelaySec plus the service's
# TimeoutStartSec, which is the latest a run may still be under way).
# window-declaration-test.sh fails when the unit and the timer disagree, so
# the declaration cannot drift from the schedule it describes. The zone is the
# box's own, read at run time, because OnCalendar is resolved in the host's
# local time. **Nothing is worked out from a start and an interval**: the
# window is read, never inferred.
#
# ## All three or none
#
# The portal keeps a window only whole, and reads half of one as unrecognized.
# So a value this box cannot read declares nothing, and says so beside the
# run, rather than sending a window nobody set.

# run_window_json <opensAt> <minutes> <zone>
# Prints the run report's window field, with its leading comma, or nothing and
# returns 1 when any of the three is not readable as what it claims to be.
run_window_json() {
  local opens="$1" minutes="$2" zone="$3"
  printf '%s' "$opens" | grep -Eq '^([01][0-9]|2[0-3]):[0-5][0-9]$' || return 1
  printf '%s' "$minutes" | grep -Eq '^[1-9][0-9]*$' || return 1
  [ "$minutes" -le 1440 ] || return 1
  printf '%s' "$zone" | grep -Eq '^[A-Za-z]+(/[A-Za-z0-9_+-]+)+$|^UTC$' || return 1
  printf ',"window":{"opensAt":"%s","timeZone":"%s","minutes":%s}' "$opens" "$zone" "$minutes"
}

# box_time_zone: the host's own IANA zone, from systemd, or from where
# /etc/localtime points. Prints nothing when neither says, and the caller then
# declares no window.
box_time_zone() {
  local zone="" said
  if command -v timedatectl >/dev/null; then
    said="$(timedatectl show -p Timezone --value 2>&1)" && zone="$said"
  fi
  if [ -z "$zone" ] && [ -L /etc/localtime ]; then
    zone="$(readlink /etc/localtime)"
    zone="${zone#*zoneinfo/}"
  fi
  printf '%s' "$zone"
}

# declare_window: sets WINDOW_JSON to what this run declares, from the unit's
# environment and the box's zone, and says beside the run when it declares
# none for a reason. A hand run sets neither variable and declares nothing,
# which is right: a hand run is not a schedule.
WINDOW_JSON=""
declare_window() {
  WINDOW_JSON=""
  [ -n "${CAIRN_WINDOW_OPENS_AT:-}${CAIRN_WINDOW_MINUTES:-}" ] || return 0
  local zone
  zone="$(box_time_zone)"
  if ! WINDOW_JSON="$(run_window_json "${CAIRN_WINDOW_OPENS_AT:-}" "${CAIRN_WINDOW_MINUTES:-}" "$zone")"; then
    WINDOW_JSON=""
    say ""
    say "RUN WINDOW NOT DECLARED: the unit's CAIRN_WINDOW_OPENS_AT (${CAIRN_WINDOW_OPENS_AT:-unset}),"
    say "  CAIRN_WINDOW_MINUTES (${CAIRN_WINDOW_MINUTES:-unset}) or this box's zone (${zone:-unread})"
    say "  is not readable, so the run report declares no window rather than one nobody set."
    return 0
  fi
}
