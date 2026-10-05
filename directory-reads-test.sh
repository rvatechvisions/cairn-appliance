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
#
# ## ldap_outcome's wordings have none of them been seen (WO-1004-T item 1)
#
# "Invalid credentials (49)", "Insufficient access (50)", "Strong(er)
# authentication required (8)", "Confidentiality required (13)", "Unwilling to
# perform (53)" and "Server not found in Kerberos database" are LDAP result codes
# and a GSSAPI message as the builder knows them; none was copied from a run.
# The last means the KDC has no service principal for the name this box asked
# for -- CAIRN_DC as an address or an alias -- so the directory was never asked.
# It was REFUSED, and since WO-1004-V item 1 it is COULD NOT TELL, saying what it
# suggests: unseen is a caveat on how far a match is trusted; wrong is a defect
# in whether it should exist.

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
eval "$(lift tool_said)"
eval "$(lift ldap_outcome)"
eval "$(lift no_spn_sentence)"
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
  FOUND=0 REFUSED=0 UNASKED=0 UNTOLD=0 NOTRUN=0 EMPTY=0 KERBEROS_OK=0 LDAP_OK=0 DC="dc.example.com"
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
[ $STATUS -ne 0 ] && [ $UNTOLD -eq 1 ] && [ $REFUSED -eq 0 ] && [ $FOUND -eq 0 ] \
  && pass "a read that exits 0 and returns no domain object is COULD NOT TELL, neither an answer nor a refusal" \
  || fail "a bare dn: line was reported as the directory answering: $(cat "$OUT")"

LDAP_TABLE="${BASE_DN}|49|ldap_sasl_interactive_bind: Invalid credentials (49)\n\tadditional info: 80090308: LdapErr"
run capability_ldap
[ $STATUS -ne 0 ] && [ $REFUSED -eq 1 ] && [ $UNTOLD -eq 0 ] && grep -q 'Invalid credentials (49)' "$OUT" \
  && pass "a bind the directory refused is REFUSED, in ldapsearch's own words" \
  || fail "a refused bind was not REFUSED in the tool's words: $(cat "$OUT")"

LDAP_TABLE="${BASE_DN}|255|ldap_sasl_interactive_bind: Can't contact LDAP server (-1)"
run capability_ldap
[ $STATUS -ne 0 ] && [ $UNTOLD -eq 1 ] && [ $REFUSED -eq 0 ] && ! grep -q 'REFUSED' "$OUT" \
  && pass "no answer from the directory is COULD NOT TELL, never REFUSED" \
  || fail "a directory that did not answer was printed as a refusal: $(cat "$OUT")"

LDAP_TABLE="${BASE_DN}|255|ldap_sasl_interactive_bind: Unknown authentication method (-6)\n\tadditional info: SASL(-4): no mechanism available: No worthy mechs found"
run capability_ldap
[ $STATUS -ne 0 ] && [ $NOTRUN -eq 1 ] && [ $REFUSED -eq 0 ] && [ $UNTOLD -eq 0 ] \
  && pass "a host with no GSSAPI mechanism is NOT RUN, a fact about this box" \
  || fail "a missing SASL mechanism was charged to the directory: $(cat "$OUT")"

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
if [ $STATUS -ne 0 ] && [ $UNTOLD -eq 1 ] && [ $REFUSED -eq 0 ] && ! grep -q 'NOT PRESENT' "$OUT"; then
  pass "a place that did not answer is COULD NOT TELL, never REFUSED and never NOT PRESENT"
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
if [ $STATUS -ne 0 ] && [ $UNTOLD -eq 1 ] && [ $REFUSED -eq 0 ] && grep -q 'ForestDnsZones partition was not looked in' "$OUT"; then
  pass "an unreadable forest root leaves the forest partition unasked and says so"
else
  fail "the forest partition was skipped silently when the root could not be read: $(cat "$OUT")"
fi

LDAP_TABLE="${ROOTDSE}
${DOMAIN_ZONES}|50|ldap_search_ext: Insufficient access (50)"
run capability_dns
if [ $STATUS -ne 0 ] && [ $REFUSED -eq 1 ] && [ $UNTOLD -eq 0 ] && grep -q 'Insufficient access (50)' "$OUT"; then
  pass "a place the directory refused to show is REFUSED, in ldapsearch's own words"
else
  fail "a refused zone read was not REFUSED in the tool's words: $(cat "$OUT")"
fi

# WO-1004-V item 1: no service principal for the name asked is not the directory answering.
LDAP_TABLE="${BASE_DN}|254|ldap_sasl_interactive_bind: Local error (-2)\n\tadditional info: SASL(-1): generic failure: GSSAPI Error: Unspecified GSS failure.  Minor code may provide more information (Server not found in Kerberos database)"
run capability_ldap
if [ $STATUS -ne 0 ] && [ $UNTOLD -eq 1 ] && [ $REFUSED -eq 0 ] && ! grep -q '^REFUSED' "$OUT" \
   && grep -q 'COULD NOT TELL: the KDC has no service principal for ldap/dc.example.com' "$OUT"; then
  pass "no service principal for the name asked is COULD NOT TELL, and says it is usually a configured value"
else
  fail "a missing service principal was printed as the directory refusing: $(cat "$OUT")"
fi

LDAP_TABLE="${ROOTDSE}
${DOMAIN_ZONES}|255|ldap_sasl_interactive_bind: Can't contact LDAP server (-1)
${LEGACY_ZONES}|50|ldap_search_ext: Insufficient access (50)"
run capability_dns
verdict_line="$(grep -m1 '^REFUSED:' "$OUT" || true)"
if [ $STATUS -ne 0 ] && [ $REFUSED -eq 1 ] && printf '%s' "$verdict_line" | grep -q 'Insufficient access (50)' \
   && ! printf '%s' "$verdict_line" | grep -q "Can't contact"; then
  pass "a refusal after a place that did not answer quotes the refusal, not the silence before it"
else
  fail "the REFUSED line quoted a place that did not refuse: $(cat "$OUT")"
fi

echo
if [ $failures -ne 0 ]; then
  echo "FAIL: ${failures} directory-read assertion(s) failed."
  exit 1
fi
echo "PASS: both directory reads tell an answer from a read that did not happen."
