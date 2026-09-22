#!/usr/bin/env bash
#
# Point this appliance at a portal, idempotently, leaving exactly one
# CAIRN_PORTAL line.
#
# ## Why this is a script and not a line in a runbook
#
# The runbook used to say:
#
#     grep CAIRN_PORTAL settings.env || echo 'CAIRN_PORTAL=…' >> settings.env
#
# `grep CAIRN_PORTAL` matches `CAIRN_PORTAL=` -- a line that is PRESENT and
# EMPTY -- so the guard succeeded, nothing was appended, and the next run fell
# to the lab path and asked a human for a password. **A missing line and an
# empty one are both NOT SET, and only one of them looked like it.** That is
# the fails-open shape: the check answered "already done" for a thing that was
# not done.
#
# It cost a real run on 21 September 2026.
#
# ## Why exactly one line, measured rather than assumed
#
# `preflight.sh` reads this file with `.`, which is shell sourcing: the
# assignments execute in order and **the LAST one wins**. Observed, not
# reasoned about -- see `set-portal-test.sh`, which asserts it.
#
# So two lines do not take the wrong value the way a take-the-first reader
# would fear. They do something quieter and worse: **the file lies to whoever
# reads it.** Somebody scanning from the top sees `CAIRN_PORTAL=`, concludes it
# is unset, and is wrong about what the run will do. One line is the only state
# a person and the shell agree about.
#
# ## What it does
#
#   present with this value   leave it, and say so
#   present with another      replace it in place
#   present and empty         replace it in place
#   absent                    append it
#   present more than once    replace the first, remove the rest
#
# Then it prints the resulting line and counts them, and refuses if the count
# is not one -- because a script that reports on its own work must read the
# outcome rather than report the attempt.
#
set -uo pipefail

PORTAL="${1:-}"
SETTINGS="${2:-/etc/cairn-appliance/settings.env}"

if [ -z "$PORTAL" ]; then
  echo "usage: $0 <portal-url> [settings-file]"
  echo
  echo "  $0 https://portal.rvatechvisions.com"
  exit 2
fi

case "$PORTAL" in
  https://*) : ;;
  http://*)
    echo "REFUSING: ${PORTAL} is http, and the appliance signs requests to it."
    echo "  Use https. A credential fetched over http is a credential on the wire."
    exit 2
    ;;
  *)
    echo "REFUSING: ${PORTAL} does not look like a URL."
    exit 2
    ;;
esac

if [ ! -f "$SETTINGS" ]; then
  echo "REFUSING: no ${SETTINGS}."
  echo "  Run bootstrap.sh first. This script edits that file; it does not"
  echo "  create it, because creating it is where its permissions are decided."
  exit 1
fi

if [ ! -w "$SETTINGS" ]; then
  echo "REFUSING: ${SETTINGS} is not writable. Run this as root."
  exit 1
fi

before="$(grep -c '^CAIRN_PORTAL=' "$SETTINGS" 2>/dev/null || echo 0)"

# **Already set, to this value, exactly once.** Nothing is written, and saying
# so is the point: a script that rewrites a file it did not need to change
# moves its mtime, and an mtime is evidence somebody will read later.
if [ "$before" = "1" ] && grep -Eq "^CAIRN_PORTAL=${PORTAL}\$" "$SETTINGS"; then
  echo "already set, left alone:"
  grep -n '^CAIRN_PORTAL=' "$SETTINGS" | sed 's/^/  /'
  exit 0
fi

# A temporary file beside the target, so the replace is a rename on the same
# filesystem rather than a truncate-and-write somebody can interrupt halfway.
tmp="$(mktemp "${SETTINGS}.XXXXXX")" || { echo "REFUSING: could not create a temporary file"; exit 1; }
trap 'rm -f "$tmp"' EXIT

# Replace the FIRST CAIRN_PORTAL line and drop any others, or append if there
# were none. Written with awk rather than sed -i because the "drop the rest"
# half needs state, and a second sed pass is a second thing that can half-run.
if ! awk -v line="CAIRN_PORTAL=${PORTAL}" '
  /^CAIRN_PORTAL=/ {
    if (!done) { print line; done = 1 }
    next
  }
  { print }
  END { if (!done) print line }
' "$SETTINGS" > "$tmp"; then
  echo "REFUSING: rewriting ${SETTINGS} failed; the original is untouched."
  exit 1
fi

# The original's mode and owner, not the temporary file's. settings.env is
# 600 root:root and a rename that relaxed it would be a quiet downgrade.
chmod --reference="$SETTINGS" "$tmp" 2>/dev/null || chmod 600 "$tmp"
chown --reference="$SETTINGS" "$tmp" 2>/dev/null || true

mv -f "$tmp" "$SETTINGS" || { echo "REFUSING: could not replace ${SETTINGS}"; exit 1; }
trap - EXIT

# Read the outcome rather than report the attempt.
after="$(grep -c '^CAIRN_PORTAL=' "$SETTINGS" 2>/dev/null || echo 0)"

if [ "$after" != "1" ]; then
  echo "FAILED: ${SETTINGS} now has ${after} CAIRN_PORTAL lines, and should have 1."
  grep -n '^CAIRN_PORTAL=' "$SETTINGS" | sed 's/^/  /'
  exit 1
fi

echo "set (${before} line(s) before, 1 now):"
grep -n '^CAIRN_PORTAL=' "$SETTINGS" | sed 's/^/  /'
