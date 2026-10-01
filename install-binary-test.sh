#!/usr/bin/env bash
#
# The install path refuses what does not match, and leaves the old binary in
# place. WO-1001-D item 1.
#
# The binaries are stand-ins that answer -version and -speaks: the subject is
# install-binary.sh's checks and the order it does them in, not the binary.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/install-binary.sh"

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

if [ ! -r "$SCRIPT" ]; then
  printf 'FAIL: cannot read %s\n' "$SCRIPT"
  exit 2
fi
# Sourced, not run: the guard at its foot keeps the main block out.
. "$SCRIPT"
if ! declare -F verify_and_install >/dev/null; then
  printf 'FATAL: install-binary.sh defines no verify_and_install, so there is nothing to test.\n'
  exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "${work}/box/preflight"
target="${work}/box/preflight/preflight"

stub() {
  local path="$1" name="$2" speaks="$3"
  cat >"$path" <<STUB
#!/usr/bin/env bash
case "\${1:-}" in
  -version) echo "preflight no-tag ${name}" ;;
  -speaks) ${speaks} ;;
esac
STUB
  chmod +x "$path"
}
digest() { sha256sum "$1" | cut -c1-64; }

stub "$target" "OLD0000000000000000000000000000000000000" 'echo "flag provided but not defined: -speaks" >&2; exit 2'
old_digest="$(digest "$target")"

stub "${work}/carried" "NEW1111111111111111111111111111111111111" 'echo "credential-block: username realm controller capabilities dhcp-servers"'
published="$(digest "${work}/carried")"

# --- a file that does not match is refused, and nothing moves --------------
out="$(verify_and_install "${work}/carried" "$(printf '0%.0s' $(seq 64))" "$target" 2>&1)"; status=$?
[ "$status" -eq 1 ] && ok "a file that does not hash to the published digest is refused" || bad "status ${status}"
case "$out" in
  *"THE FILE DOES NOT MATCH THE DIGEST THE PORTAL PUBLISHED"*) ok "and it says so, loudly" ;;
  *) bad "printed: ${out}" ;;
esac
case "$out" in
  *"the digest on the card:"*"the file you carried:"*) ok "both digests are printed, so the person sees the comparison" ;;
  *) bad "printed: ${out}" ;;
esac
[ "$(digest "$target")" = "$old_digest" ] && ok "the installed binary is byte for byte what it was" || bad "the installed binary changed"
case "$out" in
  *"is unchanged: preflight no-tag OLD"*) ok "and the refusal says which binary is still installed" ;;
  *) bad "printed: ${out}" ;;
esac
[ ! -e "${target}.incoming" ] && [ ! -e "${target}.previous" ] && ok "nothing is left staged or set aside" || bad "a stray file was left"

# --- a digest that is not a digest ----------------------------------------
out="$(verify_and_install "${work}/carried" "not-a-digest" "$target" 2>&1)"; status=$?
[ "$status" -eq 1 ] && [ "$(digest "$target")" = "$old_digest" ] && ok "a typed value that is not a SHA-256 is refused before anything is read" || bad "status ${status}"

# --- a matching file that cannot hear the consent list ---------------------
stub "${work}/mute" "MUTE222222222222222222222222222222222222" 'echo "flag provided but not defined: -speaks" >&2; exit 2'
out="$(verify_and_install "${work}/mute" "$(digest "${work}/mute")" "$target" 2>&1)"; status=$?
[ "$status" -eq 1 ] && [ "$(digest "$target")" = "$old_digest" ] && ok "a matching binary that cannot hear the consent list is refused, and nothing moves" || bad "status ${status}"
[ ! -e "${target}.incoming" ] && ok "and its staged copy is removed" || bad "the staged copy was left"

# --- the published file, typed in upper case as people read it off a screen
upper="$(printf '%s' "$published" | tr '[:lower:]' '[:upper:]')"
out="$(verify_and_install "${work}/carried" "$upper" "$target" 2>&1)"; status=$?
[ "$status" -eq 0 ] && ok "the published file installs" || bad "status ${status}: ${out}"
[ "$(digest "$target")" = "$published" ] && ok "and what is installed is the published bytes" || bad "installed digest $(digest "$target")"
[ "$(digest "${target}.previous")" = "$old_digest" ] && ok "and the previous binary is kept beside it" || bad "no previous kept"
case "$out" in
  *"INSTALLED:"*"preflight no-tag NEW"*) ok "and it says what is now installed, in the binary's own words" ;;
  *) bad "printed: ${out}" ;;
esac

printf '\n%s checks, %s failed\n' "$checks" "$fails"
[ "$fails" -eq 0 ]
