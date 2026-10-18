#!/usr/bin/env bash
#
# The entry into a signed release, at the top of preflight.sh. WO-1018-N63
# item 0b, slices 6 and 7.
#
# ## What is held
#
# **The file the timer and a person run is the one that enters the release**,
# so a hand run does what the timer does (Jackie's ruling of 23 September 2026
# in systemd/cairn-preflight.service). In order: apply, run the current
# release's own preflight.sh and wait, settle on whether it reached its end,
# stage. The exit status is the release run's own, a refusal's 1 included.
#
# **A run that died before its end is the only failure.** A release run that
# reaches the end and exits 1 for a refusal is settled as applied; one that
# never reaches the end is settled with -run-failed.
#
# **A binary that cannot name the current release changes nothing**: the file
# runs as before, and says why in one line.
#
# **A run inside a release does not enter again**, and **no release current
# means this file runs and stages at its end.**
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/preflight.sh"

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

lift() {
  local name="$1" body
  body="$(sed -n "/^${name}() {\$/,/^}\$/p" "$SCRIPT")"
  if [ -z "$body" ]; then
    echo "FATAL: preflight.sh defines no ${name}(), so there is nothing to test."
    exit 2
  fi
  printf '%s\n' "$body"
}

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A box: a config directory holding a key, and a binary that logs every call.
# BOX_CURRENT names the current release directory, or nothing; BOX_SPEAKS=no
# makes it a binary from before -current-release.
setup() {
  rm -rf "${work}/box"
  mkdir -p "${work}/box/config" "${work}/box/preflight" "${work}/box/release"
  : >"${work}/box/config/appliance.key"
  cat >"${work}/box/preflight/preflight" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${BOX_LOG}"
case " $* " in
  *" -current-release "*)
    [ "${BOX_SPEAKS:-yes}" = no ] && { echo "flag provided but not defined: -current-release" >&2; exit 2; }
    [ -n "${BOX_CURRENT:-}" ] && printf '%s\n%s\n' "$BOX_CURRENT" "1111111111111111111111111111111111111111"
    exit 0 ;;
esac
exit 0
STUB
  chmod +x "${work}/box/preflight/preflight"
  : >"${work}/box/log"
}

# The current release's preflight.sh: RELEASE_RUN=complete writes the marker
# and exits RELEASE_EXIT; RELEASE_RUN=dies exits before it.
release_script() {
  cat >"${work}/box/release/preflight.sh" <<'REL'
#!/usr/bin/env bash
printf 'release run in=%s commit=%s\n' "${CAIRN_IN_RELEASE:-}" "${CAIRN_RELEASE_COMMIT:-}" >>"${BOX_LOG}"
[ "${RELEASE_RUN:-complete}" = dies ] && exit 7
: >"$CAIRN_RUN_COMPLETED_FILE"
exit "${RELEASE_EXIT:-0}"
REL
}

# Runs release_entry as preflight.sh would, in a subshell because it exits.
enter() {
  (
    say() { printf '%s\n' "$*"; }
    HERE="${work}/box"
    CONFIG_DIR="${work}/box/config"
    CAIRN_PORTAL="https://portal.example"
    RELEASE_STAGE_AT_END=0
    eval "$(lift release_entry)"
    release_entry
    printf 'returned stage_at_end=%s\n' "$RELEASE_STAGE_AT_END"
  )
}

export BOX_LOG="${work}/box/log"

# An older binary.
setup
said="$(BOX_SPEAKS=no enter)"
case "$said" in *"cannot say which release is current"*"returned stage_at_end=0"*) ok "an older binary changes nothing, and says why" ;; *) bad "an older binary gave: ${said}" ;; esac
grep -q -- '-apply-release' "${work}/box/log" && bad "an older binary was asked to apply" || ok "and is asked to apply nothing"

# No release current.
setup
said="$(enter)"
case "$said" in *"returned stage_at_end=1"*) ok "with no release current this file runs, and stages at its end" ;; *) bad "no current release gave: ${said}" ;; esac
grep -q -- '-portal https://portal.example -apply-release' "${work}/box/log" && ok "after an apply was asked for" || bad "no apply was asked for: $(cat "${work}/box/log")"

# A release current, its run reaching the end with a refusal's exit 1.
setup
release_script
said="$(BOX_CURRENT="${work}/box/release" RELEASE_EXIT=1 enter)"
status=$?
[ "$status" -eq 1 ] && ok "the release run's own exit status is the run's, a refusal's 1 included" || bad "the entry exited ${status}, want 1"
case "$said" in *"returned"*) bad "the entry returned after running a release, so this file would run too" ;; *) ok "and this file does not run after it" ;; esac
grep -q '^release run in=1 commit=1111111111111111111111111111111111111111$' "${work}/box/log" \
  && ok "the release ran inside the release, told its commit" || bad "the release run was told: $(grep '^release run' "${work}/box/log")"
grep -qx -- '-settle-release' "${work}/box/log" && ok "a run that reached its end is settled as applied, refusal or not" || bad "the settle was: $(grep settle "${work}/box/log")"
grep -q -- '-portal https://portal.example -stage-release' "${work}/box/log" && ok "and the next release is staged" || bad "nothing was staged"
order="$(grep -n -e '-apply-release' -e '^release run' -e '-settle-release' -e '-stage-release' "${work}/box/log" | cut -d: -f2- | sed 's/ .*//' | tr '\n' ' ')"
case "$order" in "-portal release -settle-release -portal "*) ok "in the order apply, run, settle, stage" ;; *) bad "the order was: ${order}" ;; esac

# A release current, its run dying before the end.
setup
release_script
said="$(BOX_CURRENT="${work}/box/release" RELEASE_RUN=dies enter)"
status=$?
[ "$status" -eq 7 ] && ok "a run that died exits with its own status" || bad "the entry exited ${status}, want 7"
grep -q -- '-settle-release -run-failed preflight.sh of the current release did not reach its end (exit 7)' "${work}/box/log" \
  && ok "and is settled as failed, naming its exit" || bad "the settle was: $(grep settle "${work}/box/log")"

# Inside a release.
setup
said="$(CAIRN_IN_RELEASE=1 BOX_CURRENT="${work}/box/release" enter)"
case "$said" in *"returned stage_at_end=0"*) ok "a run inside a release does not enter again" ;; *) bad "a run inside a release gave: ${said}" ;; esac
[ ! -s "${work}/box/log" ] && ok "and asks its binary nothing" || bad "inside a release the binary was asked: $(cat "${work}/box/log")"

printf '%s checks, %s failed\n' "$checks" "$fails"
[ "$fails" -eq 0 ]
