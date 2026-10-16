#!/usr/bin/env bash
#
# Which hosts the directory step asks for replication partners. WO-1016-N40
# item 2.
#
# ad_dc_hosts reads two files the step has already written -- every nTDSDSA
# under the sites, and every server object above them -- and prints the
# dNSHostName of each controller that holds this domain. It is the only list
# the step asks across the network from, so what it must never do is widen:
# a controller of another domain in the forest is not this domain's to read,
# and a host the directory did not name is never invented.
#
# The function is lifted out of preflight.sh rather than copied, so the test is
# about the script and not about a second description of it. Every value below
# is invented for the test.

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

body="$(sed -n '/^ad_dc_hosts() {$/,/^}$/p' "$SCRIPT")"
if [ -z "$body" ]; then
  echo "FATAL: preflight.sh defines no ad_dc_hosts(), so there is nothing to test."
  exit 2
fi
eval "$body"

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT
BASE_DN="DC=example,DC=test"
SITES="CN=Sites,CN=Configuration,DC=example,DC=test"

# DC1 holds this domain, with its DN folded across two lines as LDIF folds a
# long one. DC2 holds it through hasMasterNCs and in another case. CHILDDC holds
# only a child domain. NOHOST holds this domain and its server object carries no
# dNSHostName.
printf '%s\n' \
  "dn: CN=NTDS Settings,CN=DC1,CN=Servers,CN=Main-Site,CN=Sites,CN=Configuratio" \
  " n,DC=example,DC=test" \
  "msDS-hasDomainNCs: DC=example,DC=test" \
  "" \
  "dn: CN=NTDS Settings,CN=DC2,CN=Servers,CN=Branch,${SITES}" \
  "hasMasterNCs: dc=EXAMPLE,dc=test" \
  "" \
  "dn: CN=NTDS Settings,CN=CHILDDC,CN=Servers,CN=Branch,${SITES}" \
  "msDS-hasDomainNCs: DC=child,DC=example,DC=test" \
  "" \
  "dn: CN=NTDS Settings,CN=NOHOST,CN=Servers,CN=Branch,${SITES}" \
  "msDS-hasDomainNCs: DC=example,DC=test" \
  "" >"${DIR}/dcs.ldif"
printf '%s\n' \
  "dn: CN=DC1,CN=Servers,CN=Main-Site,${SITES}" \
  "dNSHostName: dc1.example.test" \
  "" \
  "dn: CN=DC2,CN=Servers,CN=Branch,${SITES}" \
  "dNSHostName: dc2.example.test" \
  "" \
  "dn: CN=CHILDDC,CN=Servers,CN=Branch,${SITES}" \
  "dNSHostName: childdc.child.example.test" \
  "" \
  "dn: CN=NOHOST,CN=Servers,CN=Branch,${SITES}" \
  "" \
  "dn: CN=MEMBER,CN=Servers,CN=Branch,${SITES}" \
  "dNSHostName: member.example.test" \
  "" >"${DIR}/servers.ldif"

got="$(ad_dc_hosts "$DIR" | sort | tr '\n' ' ')"
[ "$got" = "dc1.example.test dc2.example.test " ] \
  && pass "this domain's controllers are named, a folded DN and a differently cased one included" \
  || fail "hosts: '${got}'"

case "$got" in
  *childdc*) fail "a controller holding only a child domain was asked" ;;
  *) pass "a controller of another domain in the forest is not asked" ;;
esac
case "$got" in
  *member*) fail "a server object with no domain controller beneath it was asked" ;;
  *) pass "a server that is not a controller of this domain is not asked" ;;
esac

: >"${DIR}/dcs.ldif"
got="$(ad_dc_hosts "$DIR")"
[ -z "$got" ] && pass "no controller listed is no host asked, never a guess" || fail "hosts from nothing: '${got}'"

echo
if [ $failures -ne 0 ]; then
  echo "FAIL: ${failures} host-list assertion(s) failed."
  exit 1
fi
echo "PASS: the directory step asks only this domain's controllers, at the hosts the directory names."
