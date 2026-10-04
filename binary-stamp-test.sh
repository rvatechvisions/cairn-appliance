#!/usr/bin/env bash
#
# The run report carries the installed binary's own account of its build.
# WO-0930-J item 2.
#
# ## What is held
#
# **A binary that answers is reported with its stamp and the SHA-256 of the
# file at the path the timer runs.** That digest is the one the portal
# publishes binaries under, so the two can be compared.
#
# **A binary that cannot be read is said out loud and not claimed.** No binary
# at the path, or one that says nothing when asked: the report carries no
# build, and the portal reads that as "build not reported" -- never as the
# current build.
#
# **Nothing say() prints reaches the JSON.** The fragment is set into a
# variable because say() writes to the stream a command substitution would
# capture; the second half of that is asserted rather than trusted.
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

# A function body runs from its opening line to the first line that is a lone
# closing brace. Refused, loudly, if either is missing.
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
eval "$(lift binary_report_json)"
say() { printf '%s\n' "$*"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A stand-in for the installed binary: it answers -version as the real one does.
stamped="${work}/stamped"
printf '#!/usr/bin/env bash\necho "preflight 2026.09.30 95d899ce82b58a6b8f1b2acca9d9b0be9ad67310"\n' >"$stamped"
chmod +x "$stamped"
want_digest="$(sha256sum "$stamped" | cut -c1-64)"

printed="$(binary_report_json "$stamped")"
binary_report_json "$stamped"
expected=",\"binary\":{\"stamp\":\"preflight 2026.09.30 95d899ce82b58a6b8f1b2acca9d9b0be9ad67310\",\"sha256\":\"${want_digest}\"}"
[ "$BINARY_JSON" = "$expected" ] && ok "a binary that answers is reported with its stamp and the digest of the file" \
  || bad "the fragment was: $BINARY_JSON"
[ -z "$printed" ] && ok "nothing is printed when the build is read" || bad "printed: $printed"

# No binary at the path.
printed="$(binary_report_json "${work}/absent"; printf 'JSON=%s' "$BINARY_JSON")"
case "$printed" in
  *"BUILD NOT REPORTED: there is no binary"*"JSON=") ok "no binary: said out loud, and no build claimed" ;;
  *) bad "no binary gave: $printed" ;;
esac

# A binary that says nothing when asked.
silent="${work}/silent"
printf '#!/usr/bin/env bash\nexit 1\n' >"$silent"
chmod +x "$silent"
printed="$(binary_report_json "$silent"; printf 'JSON=%s' "$BINARY_JSON")"
case "$printed" in
  *"BUILD NOT REPORTED"*"did not say its build"*"JSON=") ok "a silent binary: said out loud, and no build claimed" ;;
  *) bad "a silent binary gave: $printed" ;;
esac

# The fragment reaches both shapes of the report.
# Matched on the arguments rather than the format string, which grew a third
# field for the consent list in WO-1004-I item 1.
uses="$(grep -c '^ *printf .%s%s[%s]*}. "\$interval_json" "\$BINARY_JSON"' "$SCRIPT")"
[ "$uses" = "2" ] && ok "both report shapes carry the build" || bad "report shapes carrying the build: $uses, not 2"

printf '\n%s checks, %s failed\n' "$checks" "$fails"
[ "$fails" -eq 0 ]
