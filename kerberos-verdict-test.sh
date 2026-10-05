#!/usr/bin/env bash
#
# Only an answer the domain gave is a refusal. WO-1004-RS item 1.
#
# ## What this holds
#
# - kinit_failure prints REFUSED only for an answer the KDC gave -- a wrong
#   password, clock skew, no such principal, an expired password, a disabled
#   or locked account -- and quotes Kerberos in its own words beside it.
# - "Cannot contact any KDC" is COULD NOT TELL: nothing answered, so the
#   domain said nothing about this account, and the path to a controller is
#   the network's rather than a fault in this box's software.
# - A kinit message this script does not recognize is COULD NOT TELL, never
#   REFUSED.
#
# ## Where the sentences come from, stated
#
# "Password incorrect while getting initial credentials" was printed by kinit
# on RVA's own appliance and is quoted in preflight-output-test.sh. The others
# are MIT Kerberos's messages as the builder knows them, not copied from a run
# on the box: that is the weaker kind of fixture, and it is named here so
# nobody reads these as captured.
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

lift() {
  local name="$1" body
  body="$(sed -n "/^${name}() {\$/,/^}\$/p" "$SCRIPT")"
  if [ -z "$body" ]; then
    echo "FATAL: preflight.sh defines no ${name}(), so there is nothing to test."
    exit 2
  fi
  printf '%s\n' "$body"
}

say() { printf '%s\n' "$*"; }
eval "$(lift tool_said)"
eval "$(lift kinit_failure)"

PRINCIPAL="svc-cairn@EXAMPLE.COM"
REALM="EXAMPLE.COM"
DC="dc.example.com"

verdict_of() { # expected verdict, then what kinit printed, then the label
  local expected="$1" said="$2" label="$3" out
  KINIT_VERDICT=""
  out="$(kinit_failure "$said"; printf 'VERDICT=%s\n' "$KINIT_VERDICT")"
  local got="${out##*VERDICT=}"
  local line
  line="$(printf '%s\n' "$out" | grep -m1 -E '^(REFUSED|COULD NOT TELL):' || true)"
  if [ "$got" != "$expected" ]; then
    bad "${label}: expected ${expected}, got ${got:-nothing}: ${out}"
    return
  fi
  case "$expected" in
    refused)
      case "$line" in
        "REFUSED: the domain answered"*"Kerberos said: ${said}") ok "$label" ;;
        *) bad "${label}: the refusal does not quote Kerberos in its own words: ${line}" ;;
      esac
      ;;
    untold)
      if printf '%s\n' "$out" | grep -q '^REFUSED'; then
        bad "${label}: printed REFUSED for something the domain did not say: ${out}"
      else
        case "$line" in
          "COULD NOT TELL: "*"Kerberos said: ${said}") ok "$label" ;;
          *) bad "${label}: no COULD NOT TELL line quoting Kerberos: ${out}" ;;
        esac
      fi
      ;;
  esac
}

verdict_of refused 'kinit: Password incorrect while getting initial credentials' \
  "a wrong password is REFUSED, quoting Kerberos"
verdict_of refused 'kinit: Clock skew too great while getting initial credentials' \
  "clock skew is REFUSED, quoting Kerberos"
verdict_of refused "kinit: Client 'svc-cairn@EXAMPLE.COM' not found in Kerberos database while getting initial credentials" \
  "no such principal is REFUSED, quoting Kerberos"
verdict_of refused 'kinit: Password has expired while getting initial credentials' \
  "an expired password is REFUSED, quoting Kerberos"
verdict_of refused "kinit: Client's credentials have been revoked while getting initial credentials" \
  "a disabled or locked account is REFUSED, quoting Kerberos"
verdict_of untold "kinit: Cannot contact any KDC for realm 'EXAMPLE.COM' while getting initial credentials" \
  "Cannot contact any KDC is COULD NOT TELL, never REFUSED"
verdict_of untold "kinit: Cannot find KDC for realm \"EXAMPLE.COM\" while getting initial credentials" \
  "no KDC found for the realm is COULD NOT TELL"
verdict_of untold 'kinit: KDC reply did not match expectations while getting initial credentials' \
  "a message this script does not recognize is COULD NOT TELL, never REFUSED"

# The step's own counter follows the verdict. Read as written in
# capability_kerberos: the lines after kinit_failure choose the counter.
body="$(lift capability_kerberos)"
if printf '%s\n' "$body" | grep -q 'kinit_failure "\$kinit_out"' \
   && printf '%s\n' "$body" | grep -q 'if \[ "\$KINIT_VERDICT" = untold \]; then' \
   && printf '%s\n' "$body" | grep -A1 'if \[ "\$KINIT_VERDICT" = untold \]; then' | grep -q 'UNTOLD=\$((UNTOLD + 1))'; then
  ok "capability_kerberos counts could-not-tell as UNTOLD and only a refusal as REFUSED"
else
  bad "capability_kerberos does not choose its counter from kinit_failure's verdict"
fi

echo
if [ "$checks" -lt 9 ]; then
  echo "FAIL: only ${checks} check(s) ran; the walk is narrower than this file says."
  exit 1
fi
if [ "$fails" -ne 0 ]; then
  echo "FAIL: ${fails} of ${checks} Kerberos verdict check(s) failed."
  exit 1
fi
echo "PASS: ${checks} checks; kinit's failures are refusals only where the domain answered."
