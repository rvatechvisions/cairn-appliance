#!/usr/bin/env bash
#
# A failed sign-in stops the steps that depend on it.
#
# preflight.sh records whether kerberos succeeded in KERBEROS_OK, and the dhcp
# step refuses to run when it is non-zero. The lines that set it are taken from
# preflight.sh as written and run against a stand-in for run_capability, so a
# rewrite that loses the status fails here rather than on a box at 05:44.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/preflight.sh"

failures=0
ok()  { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; failures=$((failures + 1)); }

gate="$(grep -E '^(KERBEROS_OK=|run_capability kerberos )' "$SCRIPT")"
if [ "$(printf '%s\n' "$gate" | grep -c .)" -lt 2 ]; then
  printf 'FAIL: found no kerberos gate lines in preflight.sh; this test read nothing\n'
  exit 2
fi

# The sign-in fails.
run_capability() { return 1; }
eval "$gate"
[ "$KERBEROS_OK" -ne 0 ] && ok "a failed sign-in is recorded as failed" \
  || bad "a failed sign-in was recorded as a success (KERBEROS_OK=${KERBEROS_OK})"

# The dependent step then does not run.
dhcp_body="$(sed -n '/^capability_dhcp() {/,/^}/p' "$SCRIPT")"
if [ -z "$dhcp_body" ]; then
  printf 'FAIL: capability_dhcp not found in preflight.sh\n'
  exit 2
fi
eval "$dhcp_body"
# A stand-in binary that leaves a marker if it is ever run, so "did not run"
# is observed rather than inferred. Without it the step would stop for a
# different reason -- no binary -- and this assertion could not fail.
say() { :; }
UNASKED=0
FOUND=0
REFUSED=0
DHCP_SERVERS="dhcp01.example.test"
PRINCIPAL="svc-cairn@EXAMPLE.TEST"
fake="$(mktemp -d)"
mkdir -p "${fake}/preflight"
printf '#!/usr/bin/env bash\ncase "$1" in -version) echo stamped;; *) touch "%s/ran";; esac\n' "$fake" > "${fake}/preflight/preflight"
chmod +x "${fake}/preflight/preflight"
HERE_SAVED="$HERE"
HERE="$fake"
capability_dhcp
status=$?
HERE="$HERE_SAVED"
if [ -e "${fake}/ran" ]; then
  bad "the DHCP step read from a server after a failed sign-in"
elif [ "$status" -ne 0 ] && [ "$UNASKED" -eq 1 ]; then
  ok "the DHCP step does not run after a failed sign-in"
else
  bad "the DHCP step stopped for some other reason (status ${status}, unasked ${UNASKED})"
fi
rm -rf "$fake"

# The sign-in succeeds.
run_capability() { return 0; }
eval "$gate"
[ "$KERBEROS_OK" -eq 0 ] && ok "a successful sign-in is recorded as a success" \
  || bad "a successful sign-in was recorded as failed"

if [ "$failures" -gt 0 ]; then
  printf '\n%s failure(s)\n' "$failures"
  exit 1
fi
printf '\nall passed\n'
