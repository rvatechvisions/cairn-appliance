#!/usr/bin/env bash
#
# Every file a release can carry checks out with LF line endings, whatever the
# machine's core.autocrlf. WO-1023-N125 item 5.
#
# ## What happened, 23 October 2026
#
# Release 4's manifest was written on the Windows build machine from a clean
# worktree. Its three shell scripts matched their committed blobs byte for
# byte, because .gitattributes forces *.sh to LF. Its two systemd units did
# not: core.autocrlf is true there, nothing named them, and they checked out
# with CRLF, 3,678 and 2,509 bytes against the committed 3,601 and 2,455. The
# manifest would have sent a box unit files with a carriage return on every
# line. It was withdrawn before anything was uploaded.
#
# ## What is held
#
# For every tracked file of the kinds a release lists (shell scripts and the
# units under systemd/), git check-attr must answer eol: lf. A file whose
# attribute is unset fails by name. It reads the attribute rather than the
# bytes on disk, because the bytes on this machine depend on how it is set.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE" || { printf 'FATAL: cannot enter %s\n' "$HERE"; exit 2; }

files="$(git ls-files -- '*.sh' 'systemd/*.service' 'systemd/*.timer' 2>&1)" || {
  printf 'FATAL: git could not list the files: %s\n' "$files"
  exit 2
}
units="$(printf '%s\n' "$files" | grep -c '^systemd/')"
if [ "$units" -lt 2 ]; then
  printf 'FATAL: found %s systemd units, fewer than the two a release carries, so this would pass on nothing\n' "$units"
  exit 2
fi

fails=0
checks=0
while IFS= read -r file; do
  [ -n "$file" ] || continue
  checks=$((checks + 1))
  eol="$(git check-attr eol -- "$file" | sed 's/.*: eol: //')"
  if [ "$eol" != "lf" ]; then
    fails=$((fails + 1))
    printf 'FAIL: %s checks out with eol %s, not lf\n' "$file" "$eol"
  fi
done <<<"$files"

printf 'files a release can carry: %s, of them systemd units: %s, not forced to LF: %s\n' "$checks" "$units" "$fails"
if [ "$fails" -eq 0 ]; then
  echo "PASS: every file a release can carry checks out with LF."
  exit 0
fi
exit 1
