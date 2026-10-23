#!/usr/bin/env bash
#
# A release brings the box's systemd units. WO-1022-N122 item 5, on Jackie's
# answer of 22 October 2026 to card 1219722441221156 (option A).
#
# ## What is held
#
# - **A unit the release carries and the box holds differently is installed**,
#   and systemd is told to reload once.
# - **A unit the box already holds byte for byte is left alone**, and nothing
#   is reloaded.
# - **A unit the release does not carry is left as it is.**
# - **An install that fails is said, and nothing is reloaded.**
# - **preflight.sh calls it once a release is current**, before that release's
#   own preflight.sh runs.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/preflight.sh"

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

body="$(sed -n '/^release_units() {$/,/^}$/p' "$SCRIPT")"
if [ -z "$body" ]; then
  echo "FATAL: preflight.sh defines no release_units(), so there is nothing to test."
  exit 2
fi
say() { printf '%s\n' "$*"; }
eval "$body"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

setup() {
  rm -rf "${work}/release" "${work}/units" "${work}/reloads"
  mkdir -p "${work}/release/systemd" "${work}/units"
  : >"${work}/reloads"
  cat >"${work}/systemctl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${RELOADS}"
STUB
  chmod +x "${work}/systemctl"
}
run() {
  RELOADS="${work}/reloads" CAIRN_SYSTEMD_DIR="${work}/units" CAIRN_SYSTEMCTL="${work}/systemctl" \
    release_units "${work}/release"
}

# 1. A unit that differs is installed, and systemd reloads once.
setup
printf 'release service\n' >"${work}/release/systemd/cairn-preflight.service"
printf 'release timer\n' >"${work}/release/systemd/cairn-preflight.timer"
printf 'old service\n' >"${work}/units/cairn-preflight.service"
out="$(RELOADS="${work}/reloads" run)"
if cmp -s "${work}/release/systemd/cairn-preflight.service" "${work}/units/cairn-preflight.service" \
  && cmp -s "${work}/release/systemd/cairn-preflight.timer" "${work}/units/cairn-preflight.timer"; then
  ok "a differing or missing unit is installed from the release"
else
  bad "a differing or missing unit is installed from the release"
fi
if [ "$(wc -l <"${work}/reloads")" -eq 1 ] && grep -qx 'daemon-reload' "${work}/reloads"; then
  ok "systemd is reloaded once after installing"
else
  bad "systemd is reloaded once after installing (got: $(tr '\n' ' ' <"${work}/reloads"))"
fi
case "$out" in
  *"installed cairn-preflight.service from the current release"*) ok "the run says which unit it installed" ;;
  *) bad "the run says which unit it installed (got: $out)" ;;
esac

# 2. A unit the box already holds byte for byte is left alone.
setup
printf 'same\n' >"${work}/release/systemd/cairn-preflight.service"
printf 'same\n' >"${work}/units/cairn-preflight.service"
before="$(stat -c %Y "${work}/units/cairn-preflight.service")"
out="$(RELOADS="${work}/reloads" run)"
if [ -z "$out" ] && [ ! -s "${work}/reloads" ] && [ "$(stat -c %Y "${work}/units/cairn-preflight.service")" = "$before" ]; then
  ok "an identical unit is left alone and nothing reloads"
else
  bad "an identical unit is left alone and nothing reloads (said: $out)"
fi

# 3. A unit the release does not carry is left as it is.
setup
printf 'box timer\n' >"${work}/units/cairn-preflight.timer"
out="$(RELOADS="${work}/reloads" run)"
if [ "$(cat "${work}/units/cairn-preflight.timer")" = "box timer" ] && [ ! -s "${work}/reloads" ]; then
  ok "a unit the release does not carry is left as it is"
else
  bad "a unit the release does not carry is left as it is"
fi

# 4. An install that fails is said, and nothing reloads.
setup
printf 'release service\n' >"${work}/release/systemd/cairn-preflight.service"
out="$(RELOADS="${work}/reloads" CAIRN_SYSTEMD_DIR="${work}/no-such-directory" CAIRN_SYSTEMCTL="${work}/systemctl" \
  release_units "${work}/release" 2>&1)"
case "$out" in
  *"could not install cairn-preflight.service"*) ok "a failed install is said" ;;
  *) bad "a failed install is said (got: $out)" ;;
esac
if [ ! -s "${work}/reloads" ]; then ok "nothing reloads after a failed install"; else bad "nothing reloads after a failed install"; fi

# 5. preflight.sh calls it once a release is current, before the release's own run.
entry="$(sed -n '/^release_entry() {$/,/^}$/p' "$SCRIPT")"
call="$(printf '%s\n' "$entry" | grep -n 'release_units "\$dir"' | cut -d: -f1)"
runs="$(printf '%s\n' "$entry" | grep -n 'bash "\${dir}/preflight.sh"' | cut -d: -f1)"
current="$(printf '%s\n' "$entry" | grep -n 'RELEASE_STAGE_AT_END=1' | cut -d: -f1)"
if [ -n "$call" ] && [ -n "$runs" ] && [ -n "$current" ] && [ "$call" -gt "$current" ] && [ "$call" -lt "$runs" ]; then
  ok "release_entry installs the units once a release is current, before running it"
else
  bad "release_entry installs the units once a release is current, before running it"
fi

# 6. A run inside a release installs the units its own release carries.
# WO-1023-N125 item 5: the entry file on a box already on releases is never
# replaced, so on RVA's box it is release 2's and has no release_units. The
# release's own preflight.sh, run with CAIRN_IN_RELEASE set, has to do it.
inside="$(printf '%s\n' "$entry" | grep -n 'release_units "\$HERE"' | cut -d: -f1)"
leaves="$(printf '%s\n' "$entry" | grep -n 'return 0' | head -n 1 | cut -d: -f1)"
guard="$(printf '%s\n' "$entry" | grep -n 'if \[ -n "\${CAIRN_IN_RELEASE:-}" \]; then' | cut -d: -f1)"
if [ -n "$inside" ] && [ -n "$leaves" ] && [ -n "$guard" ] && [ "$guard" -lt "$inside" ] && [ "$inside" -lt "$leaves" ]; then
  ok "a run inside a release installs its own release's units before it leaves release_entry"
else
  bad "a run inside a release installs its own release's units before it leaves release_entry"
fi

printf '%d of %d checks passed\n' "$((checks - fails))" "$checks"
[ "$fails" -eq 0 ]
