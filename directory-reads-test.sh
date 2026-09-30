#!/usr/bin/env bash
#
# The two directory reads preflight makes after Kerberos -- the bind check and
# the DNS zone check -- told a read that did not happen from an answer by the
# exit code alone. WO-0930-F item 5.
#
# ## What each was doing
#
# The bind check asked the domain head for dnsHostName. The domain object does
# not carry that attribute, so a good bind came back as a bare "dn:" line and
# "the directory answered" rested on ldapsearch exiting 0.
#
# The DNS check read DomainDnsZones alone and took ANY non-zero exit as "no
# directory-integrated DNS": a refused read, a timeout and a zone kept in the
# forest partition all came back as the same plausible answer.
#
# ## How this tests them
#
# The functions are lifted out of preflight.sh rather than copied here, so the
# test is about the script and not about a second description of it. ldapsearch
# is a shell function answering from a table keyed by the base DN it is asked
# for, so every case is one the script really meets: present, "no such object"
# (32), and a failure that is neither.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/preflight.sh"

failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
pass() { echo "ok:   $*"; }

if [ ! -f "$SCRIPT" ]; then
  echo "FATAL: no preflight.sh beside this test at ${SCRIPT}."
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
eval "$(lift capability_ldap)"
eval "$(lift capability_dns)"

say() { printf '%s\n' "$*" >> "$OUT"; }

# ldapsearch answers from LDAP_TABLE: one line per base DN, "base|exit|body",
# with \n in the body for a newline. The rootDSE is the empty base.
ldapsearch() {
  local base="" previous=""
  for argument in "$@"; do
    [ "$previous" = "-b" ] && base="$argument"
    previous="$argument"
  done
  local line
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if [ "${line%%|*}" = "$base" ]; then
      local rest="${line#*|}"
      printf '%b\n' "${rest#*|}"
      return "${rest%%|*}"
    fi
  done <<< "$LDAP_TABLE"
  printf 'ldap_search_ext: No such object (32)\n'
  return 32
}

BASE_DN="DC=child,DC=example,DC=com"
FOREST="DC=example,DC=com"
DOMAIN_ZONES="CN=MicrosoftDNS,DC=DomainDnsZones,${BASE_DN}"
LEGACY_ZONES="CN=MicrosoftDNS,CN=System,${BASE_DN}"
FOREST_ZONES="CN=MicrosoftDNS,DC=ForestDnsZones,${FOREST}"
ROOTDSE="|0|dn:\nrootDomainNamingContext: ${FOREST}"

run() { # function, then prints the state line
  OUT="$(mktemp)"
  FOUND=0 REFUSED=0 UNASKED=0 KERBEROS_OK=0 LDAP_OK=0 DC="dc.example.com"
  # Everything the function prints is kept: the zone list goes to stdout and the
  # verdicts through say, and a test that dropped either would read half a run.
  "$1" >> "$OUT" 2>&1
  STATUS=$?
}

# --- the bind check -----------------------------------------------------------

LDAP_TABLE="${BASE_DN}|0|dn: ${BASE_DN}\nobjectClass: top\nobjectClass: domain\nobjectClass: domainDNS"
run capability_ldap
[ $STATUS -eq 0 ] && [ $FOUND -eq 1 ] \
  && pass "a bound read that returns the domain object's class is FOUND" \
  || fail "a bound read returning domainDNS was not FOUND: $(cat "$OUT")"

LDAP_TABLE="${BASE_DN}|0|dn: ${BASE_DN}"
run capability_ldap
[ $STATUS -ne 0 ] && [ $REFUSED -eq 1 ] && [ $FOUND -eq 0 ] \
  && pass "a read that exits 0 and returns no domain object is not called an answer" \
  || fail "a bare dn: line was reported as the directory answering: $(cat "$OUT")"

# --- the DNS zones check ------------------------------------------------------

LDAP_TABLE="${ROOTDSE}
${DOMAIN_ZONES}|0|dn: DC=child.example.com,${DOMAIN_ZONES}\ndc: child.example.com
${FOREST_ZONES}|0|dn: DC=_msdcs.example.com,${FOREST_ZONES}\ndc: _msdcs.example.com"
run capability_dns
if [ $STATUS -eq 0 ] && [ $FOUND -eq 1 ] && grep -q '_msdcs.example.com' "$OUT" && grep -q 'child.example.com' "$OUT" \
   && grep -q 'from 2 of 3 place' "$OUT"; then
  pass "zones in the forest partition are found beside the domain's, and the legacy container's absence is not a refusal"
else
  fail "a zone kept in ForestDnsZones was not found: $(cat "$OUT")"
fi

LDAP_TABLE="${ROOTDSE}
${DOMAIN_ZONES}|255|ldap_sasl_interactive_bind: Can't contact LDAP server (-1)"
run capability_dns
if [ $STATUS -ne 0 ] && [ $REFUSED -eq 1 ] && ! grep -q 'NOT PRESENT' "$OUT"; then
  pass "a read that failed for a reason other than no-such-object is REFUSED, never NOT PRESENT"
else
  fail "a failed read was reported as a site without directory DNS: $(cat "$OUT")"
fi

LDAP_TABLE="${ROOTDSE}"
run capability_dns
if [ $STATUS -ne 0 ] && [ $UNASKED -eq 1 ] && [ $REFUSED -eq 0 ] && grep -q 'NOT PRESENT' "$OUT"; then
  pass "all three places absent is NOT PRESENT, a fact about the site"
else
  fail "a site with no directory DNS was not reported as NOT PRESENT: $(cat "$OUT")"
fi

LDAP_TABLE="|1|ldap_search_ext: Operations error (1)
${DOMAIN_ZONES}|0|dn: DC=child.example.com,${DOMAIN_ZONES}\ndc: child.example.com"
run capability_dns
if [ $STATUS -ne 0 ] && [ $REFUSED -eq 1 ] && grep -q 'ForestDnsZones partition was not looked in' "$OUT"; then
  pass "an unreadable forest root leaves the forest partition unasked and says so"
else
  fail "the forest partition was skipped silently when the root could not be read: $(cat "$OUT")"
fi

echo
if [ $failures -ne 0 ]; then
  echo "FAIL: ${failures} directory-read assertion(s) failed."
  exit 1
fi
echo "PASS: both directory reads tell an answer from a read that did not happen."
