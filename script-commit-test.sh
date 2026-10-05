#!/usr/bin/env bash
#
# The run report says which preflight.sh ran. WO-1004-K item 1a.
#
# The binary reaches a box verified against a digest the portal published;
# this script reaches it by a person's git pull and is verified against
# nothing, so the least the run can do is say which commit it is and whether
# the tracked files on the box differ from it. Three outcomes, each held here:
#
# - clean: the commit, and nothing tracked differs;
# - dirty: the commit, and a tracked file has been edited on the box;
# - unknown: git could not answer, said in git's own words -- never nothing.
#
# An untracked file -- the preflight.previous a binary install leaves -- does
# not make a box dirty.
#
set -uo pipefail

HERE_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE_REPO}/preflight.sh"

fails=0
checks=0
ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

if [ ! -r "$SCRIPT" ]; then
  printf 'FAIL: cannot read %s\n' "$SCRIPT"
  exit 2
fi
if ! command -v git >/dev/null 2>&1; then
  printf 'FAIL: git is not on this PATH, so nothing here can be tested\n'
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
eval "$(lift json_safe)"
eval "$(lift script_identity)"
eval "$(lift script_report_json)"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

repo="${work}/box"
mkdir -p "$repo"
git -C "$repo" init -q
printf 'echo run\n' >"${repo}/preflight.sh"
git -C "$repo" add preflight.sh
git -C "$repo" -c user.name=t -c user.email=t@rvatechvisions.com commit -q -m one
commit="$(git -C "$repo" rev-parse HEAD)"

HERE="$repo"
script_report_json
[ "$SCRIPT_JSON" = ",\"script\":{\"commit\":\"${commit}\",\"state\":\"clean\"}" ] \
  && ok "a box on a commit with nothing changed reports the commit, clean" || bad "clean reported: ${SCRIPT_JSON}"

printf 'leftover\n' >"${repo}/preflight.previous"
script_report_json
[ "$SCRIPT_JSON" = ",\"script\":{\"commit\":\"${commit}\",\"state\":\"clean\"}" ] \
  && ok "an untracked file left by an install does not make the box dirty" || bad "untracked reported: ${SCRIPT_JSON}"

printf 'echo edited on the box\n' >"${repo}/preflight.sh"
script_report_json
[ "$SCRIPT_JSON" = ",\"script\":{\"commit\":\"${commit}\",\"state\":\"dirty\"}" ] \
  && ok "an edited tracked file reports the commit, dirty" || bad "dirty reported: ${SCRIPT_JSON}"

HERE="${work}/not-a-repository"
mkdir -p "$HERE"
script_report_json
case "$SCRIPT_JSON" in
  ',"script":{"state":"unknown","reason":"git could not say which commit this script is: '*) ok "a directory git does not know reports unknown, with git's words" ;;
  *) bad "not a repository reported: ${SCRIPT_JSON}" ;;
esac

# A git that fails as a missing one does, first on the PATH, so every other
# tool the function uses is still there and only git is absent.
HERE="$repo"
mkdir -p "${work}/no-git"
printf '#!/usr/bin/env bash\necho "git: command not found" >&2\nexit 127\n' >"${work}/no-git/git"
chmod +x "${work}/no-git/git"
saved_path="$PATH"
PATH="${work}/no-git:${PATH}"
script_report_json
PATH="$saved_path"
case "$SCRIPT_JSON" in
  ',"script":{"state":"unknown","reason":"git could not say which commit this script is: git: command not found"}') ok "a box with no git reports unknown, saying why, rather than nothing" ;;
  *) bad "no git reported: ${SCRIPT_JSON}" ;;
esac

if [ "$(grep -c '"\$CONSENT_JSON" "\$SCRIPT_JSON"' "$SCRIPT")" -eq 2 ]; then
  ok "both report shapes, ran and could-not-start, carry the script"
else
  bad "a report shape does not carry SCRIPT_JSON"
fi

printf '%s checks, %s failed\n' "$checks" "$fails"
[ "$fails" -eq 0 ]
