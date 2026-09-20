#!/usr/bin/env bash
#
# What can this appliance actually reach, and with what?
#
# ## Four capabilities, reported separately
#
# Kerberos, Active Directory over LDAP, the DNS zones held in the directory,
# and DHCP over MS-DHCPM. They are four different things and they fail for four
# different reasons: a keytab that has gone stale, an account that cannot read
# the directory, a domain whose DNS is not directory-integrated, and an account
# that is not in DHCP Users. Reporting them as one verdict sends somebody to
# fix whichever one they thought of first.
#
# So each is asked on its own and answered on its own, and a failure in one
# does not stop the others being tried. `set -e` is deliberately not used.
#
# ## It reports what it found. It never asserts an expected count.
#
# There is no line in here that says a district should have six DHCP servers or
# four hundred leases. Preflight has no way to know what is correct for a site
# it has never seen, and a check that invents an expectation produces a
# confident wrong verdict about somebody else's network. It prints what
# answered, what refused, and what each one said. The person reading it is the
# one who knows what the site is meant to look like.
#
# ## It submits nothing
#
# No portal, no token, no upload, no outbound call of any kind beyond the
# customer's own domain controllers. What it writes goes to the screen, and to
# a file only if the operator asks for one.
#
set -uo pipefail

CONFIG_DIR=/etc/cairn-appliance
SETTINGS="${CONFIG_DIR}/settings.env"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FOUND=0
REFUSED=0
UNASKED=0

say() { printf '%s\n' "$*"; }
rule() { printf '\n--- %s ---\n' "$*"; }

if [ ! -r "$SETTINGS" ]; then
  say "No settings at ${SETTINGS}."
  say "Run bootstrap.sh first, then fill it in. Nothing was asked of the domain."
  exit 1
fi

# shellcheck disable=SC1090
. "$SETTINGS"

REALM="${CAIRN_REALM:-}"
DC="${CAIRN_DC:-}"
PRINCIPAL="${CAIRN_PRINCIPAL:-}"
DHCP_SERVERS="${CAIRN_DHCP_SERVERS:-}"

say "Cairn appliance preflight"
say "realm     ${REALM:-<unset>}"
say "dc        ${DC:-<unset>}"
say "principal ${PRINCIPAL:-<unset>}"
say "dhcp      ${DHCP_SERVERS:-<unset>}"
say ""
say "Read-only throughout. Nothing is submitted anywhere."
say "No credential is written down by this script, and none is printed."

# ---------------------------------------------------------------------------
# Nothing durable, checked rather than claimed.
#
# The design's whole claim is that no copy of a customer's credential survives
# a run on this box: it is fetched from the portal, used from a memory-backed
# ticket cache, and dropped. A claim like that is worth exactly what checking
# it is worth, so this refuses to continue if it finds the thing the design
# says is not here.
#
# A keytab is the specific artifact the earlier design placed by hand, so it is
# named; a password written into the settings file is the other way the same
# property gets lost, so it is named too.
# ---------------------------------------------------------------------------
rule "nothing durable on this box"
DURABLE=0

for found in "$CONFIG_DIR"/*.keytab "$CONFIG_DIR"/*.kt /etc/krb5.keytab; do
  [ -e "$found" ] || continue
  say "FOUND A KEYTAB: ${found}"
  DURABLE=1
done

if grep -qiE '^[[:space:]]*(CAIRN_PASSWORD|CAIRN_PASS|CAIRN_SECRET)=..*' "$SETTINGS" 2>/dev/null; then
  say "FOUND A PASSWORD in ${SETTINGS}"
  DURABLE=1
fi

if [ "$DURABLE" -ne 0 ]; then
  say ""
  say "REFUSING TO CONTINUE. A durable credential is on this appliance, and the"
  say "  design this runs under says there is not one. The customer's credential"
  say "  is held in the portal and fetched for the length of a run; a copy here"
  say "  is a second place it lives, which nobody revokes and nobody rotates."
  say ""
  say "  If this host was built under the earlier keytab design, remove the file"
  say "  and re-enrol. If a password was pasted into the settings file, remove"
  say "  the line and treat that credential as disclosed."
  exit 1
fi

say "no keytab, no stored password. Nothing here outlives a run."

# ---------------------------------------------------------------------------
# 0. Where does the credential come from, and does it survive the run?
#
# ## This is the step the product question turns on
#
# The earlier design placed a keytab on this box by hand, and the objection to
# it was never the file mode: a long-lived credential on a machine the client's
# domain does not manage is one nobody rotates and nobody can revoke without
# knowing it exists.
#
# **A domain join was the candidate answer and is withdrawn. Jackie's decision,
# 20 September 2026.** A collector must not be a member of the trust boundary
# it reads. Joining would make this appliance a computer object inside the
# directory it is measuring -- subject to that domain's policy, inside its
# blast radius, and a foothold within it if this host is compromised, rather
# than a read-only credential held outside it. It also keeps a durable machine
# credential on the box, which is the property being removed.
#
# ## What replaces it
#
# The customer enters a read-only credential **into the portal**. This
# appliance connects out, authenticates with a key generated here at enrolment,
# fetches the credential for the length of one run, kinits into a
# memory-backed ticket cache, and drops it. Revocation is one action in the
# portal rather than a site visit.
#
# The property that falls out of it, and the one worth stating: **we never
# handle the client's credential.** Not in a ticket, not in a message, not in a
# file anybody places. That rule has stood all week on discipline; this is the
# first design that enforces it.
#
# ## It reports, and blocks nothing
#
# A run whose credential came from an operator's shell and one whose credential
# came from the portal are the same ticket to step 1 and a different product.
# This makes the difference visible rather than deciding anything: the lab path
# in LAB-BUILD.md is deliberately the first kind.
# ---------------------------------------------------------------------------
rule "0. Where the credential comes from"
capability_credential_source() {
  local enrolled=0

  if [ -f "${CONFIG_DIR}/appliance.key" ]; then
    local perms
    perms="$(stat -c '%a %U:%G' "${CONFIG_DIR}/appliance.key" 2>/dev/null || echo unknown)"
    say "enrolled: an appliance key exists (${perms}), generated here and never transmitted."
    if [ "$perms" != "600 root:root" ]; then
      say "  REFUSING TO CONTINUE: the appliance key must be 600 and owned by root."
      say "  A key any local user can read is this appliance's identity readable"
      say "  by anybody with a shell on it."
      exit 1
    fi
    enrolled=1
  else
    say "not enrolled: no appliance key. Run enroll.sh to generate one."
  fi

  if [ -n "${CAIRN_PORTAL:-}" ]; then
    say "portal:   ${CAIRN_PORTAL}"
  else
    say "portal:   <unset>"
  fi

  # The credential for this run, and where it came from. Read from the
  # environment only -- never from a file, which is the whole point.
  if [ -n "${CAIRN_PASSWORD:-}" ]; then
    say ""
    say "CREDENTIAL SOURCE: this operator's shell, for this run only."
    say "  This is the lab path. It is honest about what it is: the credential"
    say "  is in one environment variable and one memory-backed ticket cache,"
    say "  and nothing writes it down -- but it passed through a human's"
    say "  terminal, which is exactly what the portal fetch exists to avoid."
    say "  **Never use this at a customer.** See LAB-BUILD.md."
    FOUND=$((FOUND + 1))
    return 0
  fi

  if [ "$enrolled" -eq 1 ] && [ -n "${CAIRN_PORTAL:-}" ]; then
    say ""
    say "CREDENTIAL SOURCE: the portal, fetched per run."
    say "  **The portal side of this is not built.** There is no endpoint to"
    say "  fetch from yet, so nothing below can obtain a credential this way and"
    say "  step 1 will report that it had none. Saying so here rather than"
    say "  failing later is the difference between a missing feature and a"
    say "  mystery."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  say ""
  say "NO CREDENTIAL SOURCE. Nothing below can authenticate."
  say "  Either set CAIRN_PASSWORD for a lab run, or enrol this appliance and"
  say "  set CAIRN_PORTAL once the portal side exists."
  UNASKED=$((UNASKED + 1))
  return 1
}
capability_credential_source

# ---------------------------------------------------------------------------
# 1. Kerberos
# ---------------------------------------------------------------------------
rule "1. Kerberos"
capability_kerberos() {
  if [ -z "$PRINCIPAL" ] || [ -z "$REALM" ]; then
    say "NOT ASKED: CAIRN_PRINCIPAL or CAIRN_REALM is unset in ${SETTINGS}."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  if [ -z "${CAIRN_PASSWORD:-}" ]; then
    say "NOT ASKED: no credential was available for this run — see step 0."
    say "  This is not a refusal by the domain. Nothing was sent to it."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  # A MEMORY-backed ticket cache, which is the whole design in one line.
  #
  # It lives in this process and its children and is gone when the script
  # exits: there is no file to forget, none to back up, and nothing for the
  # next person with a shell on this box to read. A FILE: cache under /tmp
  # would work identically and would leave a usable ticket on disk, which is
  # the property this design exists to remove.
  export KRB5CCNAME="MEMORY:cairn-preflight"

  # Piped into kinit rather than passed as an argument: a password on a command
  # line is visible in `ps` to every user on the host for as long as the call
  # takes, which is a disclosure to anybody watching.
  if printf '%s' "$CAIRN_PASSWORD" | kinit "$PRINCIPAL" 2>&1 | sed 's/^/  /'; then
    say "FOUND: a ticket was issued for ${PRINCIPAL}"
    say "  cache: ${KRB5CCNAME} — in memory, and gone when this script exits."
    klist 2>/dev/null | sed 's/^/  /'
    FOUND=$((FOUND + 1))
    return 0
  fi

  say "REFUSED: no ticket. The account, the password or the clock is the cause."
  say "  Kerberos refuses a request more than five minutes out from the KDC, and"
  say "  the error does not say so in those words."
  REFUSED=$((REFUSED + 1))
  return 1
}
capability_kerberos
KERBEROS_OK=$?

# ---------------------------------------------------------------------------
# 2. Active Directory over LDAP
#
# The base DN is derived from the realm rather than configured, because a realm
# and its default naming context are the same fact written twice and the second
# copy is the one that goes stale.
# ---------------------------------------------------------------------------
rule "2. Active Directory over LDAP"
BASE_DN=""
if [ -n "$REALM" ]; then
  BASE_DN="DC=$(printf '%s' "$REALM" | tr 'A-Z' 'a-z' | sed 's/\./,DC=/g')"
fi

capability_ldap() {
  if [ "$KERBEROS_OK" -ne 0 ]; then
    say "NOT ASKED: there is no ticket, so this would only report the same failure."
    UNASKED=$((UNASKED + 1))
    return 1
  fi
  if [ -z "$DC" ] || [ -z "$BASE_DN" ]; then
    say "NOT ASKED: CAIRN_DC or CAIRN_REALM is unset."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  say "base DN: ${BASE_DN}"

  # One attribute, one object. This asks whether the directory answers at all,
  # not how large it is -- reading the whole tree to prove a bind worked is a
  # large read against somebody's domain controller for no extra information.
  local out
  out="$(ldapsearch -LLL -Y GSSAPI -H "ldap://${DC}" -b "$BASE_DN" -s base dnsHostName 2>&1)"
  local status=$?

  printf '%s\n' "$out" | sed 's/^/  /'

  if [ $status -eq 0 ]; then
    say "FOUND: the directory answered a bound read."
    FOUND=$((FOUND + 1))
    return 0
  fi

  say "REFUSED: the bind or the read failed. The text above is the reason."
  REFUSED=$((REFUSED + 1))
  return 1
}
capability_ldap
LDAP_OK=$?

# ---------------------------------------------------------------------------
# 3. DNS held in the directory
#
# Directory-integrated DNS lives under CN=MicrosoftDNS in the DomainDnsZones
# partition. A domain whose DNS is not directory-integrated has no such
# container, and that is a fact about the site rather than a failure -- so it
# is reported as "not present" rather than as a refusal.
# ---------------------------------------------------------------------------
rule "3. DNS zones in the directory"
capability_dns() {
  if [ "$LDAP_OK" -ne 0 ]; then
    say "NOT ASKED: the directory did not answer, so this cannot be asked separately."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  local dns_dn="CN=MicrosoftDNS,DC=DomainDnsZones,${BASE_DN}"
  say "looking under: ${dns_dn}"

  local out
  out="$(ldapsearch -LLL -Y GSSAPI -H "ldap://${DC}" -b "$dns_dn" \
          -s one '(objectClass=dnsZone)' dc 2>&1)"
  local status=$?

  if [ $status -ne 0 ]; then
    printf '%s\n' "$out" | sed 's/^/  /'
    say "NOT PRESENT: no directory-integrated DNS under that container."
    say "  This is a normal state at a site whose DNS is not AD-integrated."
    say "  It is reported rather than treated as a failure."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  # Counted and listed, never compared against an expectation.
  local zones
  zones="$(printf '%s\n' "$out" | sed -n 's/^dc: //p' | sort)"
  local count
  count="$(printf '%s\n' "$zones" | grep -c . || true)"

  say "FOUND: ${count} zone(s) readable in the directory."
  printf '%s\n' "$zones" | sed 's/^/  /'
  say "  What is correct for this site is not something preflight can know."
  FOUND=$((FOUND + 1))
  return 0
}
capability_dns

# ---------------------------------------------------------------------------
# 4. The authorised DHCP servers, from the directory
#
# ## This is the capability that earns partial credit, and it is why the
# ## summary below counts rather than stopping
#
# Reading `CN=NetServices` needs **only an authenticated user**. The MS-DHCPM
# interface below needs the account to be in **DHCP Users**. They are different
# rights, so this can succeed on a host where the next one refuses outright --
# and a run that proves Kerberos, the directory, DNS and this, and then fails
# DHCP, is a useful result rather than a failed run. It says the credential
# works, the directory is readable, and one right is missing, which is a
# different conversation from *this host cannot do the job*.
#
# The spike this came from stopped at the first failure. That was right for a
# question of *does any of this work at all* and is wrong here.
# ---------------------------------------------------------------------------
rule "4. Authorised DHCP servers, from the directory"
capability_authorized_servers() {
  if [ "$LDAP_OK" -ne 0 ]; then
    say "NOT ASKED: the directory did not answer."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  local dn="CN=NetServices,CN=Services,CN=Configuration,${BASE_DN}"
  say "looking under: ${dn}"

  local out
  out="$(ldapsearch -LLL -Y GSSAPI -H "ldap://${DC}" -b "$dn" \
          -s sub '(objectClass=dHCPClass)' dhcpServers name 2>&1)"
  local status=$?

  if [ $status -ne 0 ]; then
    printf '%s\n' "$out" | sed 's/^/  /'
    say "REFUSED: the authorised-server list could not be read."
    say "  This needs only an authenticated user, so a refusal here is a"
    say "  different fact from the DHCP interface refusing below."
    REFUSED=$((REFUSED + 1))
    return 1
  fi

  # Counted and printed, never compared against an expectation. What is correct
  # for a site is not something preflight can know.
  local entries
  entries="$(printf '%s\n' "$out" | grep -c '^dn:' || true)"
  say "FOUND: the container answered, ${entries} entr(ies) under it."
  printf '%s\n' "$out" | sed 's/^/  /' | head -40
  say "  The authorised list is what the directory says; whether each of those"
  say "  servers still exists is a separate question this does not ask."
  FOUND=$((FOUND + 1))
  return 0
}
capability_authorized_servers

# ---------------------------------------------------------------------------
# 5. DHCP over MS-DHCPM
#
# The only capability here that is not a shell tool. It is a small Go program
# using go-msrpc, calling R_DhcpEnumSubnets and R_DhcpEnumSubnetClientsV5 --
# both reads, and the pair the collector itself would use.
# ---------------------------------------------------------------------------
rule "5. DHCP over MS-DHCPM"
capability_dhcp() {
  if [ "$KERBEROS_OK" -ne 0 ]; then
    say "NOT ASKED: there is no ticket."
    UNASKED=$((UNASKED + 1))
    return 1
  fi
  if [ -z "$DHCP_SERVERS" ]; then
    say "NOT ASKED: CAIRN_DHCP_SERVERS is unset in ${SETTINGS}."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  local binary="${HERE}/preflight/preflight"
  if [ ! -x "$binary" ]; then
    say "building the DHCP probe..."
    if ! (cd "${HERE}/preflight" && go build -o preflight . 2>&1 | sed 's/^/  /'); then
      say "REFUSED: the probe did not build. Go is installed by bootstrap.sh;"
      say "  the module's dependencies need network access the first time."
      REFUSED=$((REFUSED + 1))
      return 1
    fi
  fi

  # Each server asked and answered on its own. A site with six DHCP servers
  # where one refuses is a different fact from a site with five servers, and
  # one summary line cannot carry both.
  local any_found=0
  local IFS=,
  for server in $DHCP_SERVERS; do
    server="$(printf '%s' "$server" | tr -d ' ')"
    [ -z "$server" ] && continue

    say ""
    say "asking ${server}:"
    if "$binary" -server "$server" 2>&1 | sed 's/^/  /'; then
      any_found=1
    else
      say "  this server did not answer. The others are still being asked."
    fi
  done

  if [ "$any_found" -eq 1 ]; then
    FOUND=$((FOUND + 1))
    return 0
  fi

  REFUSED=$((REFUSED + 1))
  return 1
}
capability_dhcp

# ---------------------------------------------------------------------------
rule "what this appliance can reach"
say "found:      ${FOUND}"
say "refused:    ${REFUSED}"
say "not asked:  ${UNASKED}"
say ""
say "Three states, not two. A capability that was never asked -- because"
say "something it depends on failed, or because nothing configured it -- is not"
say "a capability that was tried and refused, and only one of those is evidence"
say "about the customer's network."
say ""

#
# **Partial credit, stated rather than left to be inferred from the counts.**
#
# The capabilities above need different rights: reading the authorised-server
# list needs an authenticated user, the DHCP interface needs DHCP Users. So a
# run can prove most of what matters and fail the last one, and that is a
# result worth carrying back rather than a wasted trip. Saying so here is the
# difference between an operator reading the output as *one right is missing*
# and reading it as *this does not work*.
#
if [ "$FOUND" -gt 0 ] && [ "$REFUSED" -gt 0 ]; then
  say "PARTLY PROVEN: ${FOUND} capabilit(ies) answered and ${REFUSED} refused."
  say "  That is a result, not a failed run. The ones that answered are proven"
  say "  on this host with this credential, and what they proved stays true"
  say "  whatever refused after them -- these capabilities need different"
  say "  rights, so one refusal never stands in for the others."
  say ""
fi

say "Nothing was submitted anywhere, and nothing on the domain was changed."

# Exit non-zero only when something was genuinely refused. Nothing-asked is not
# a failure of this host; it is a gap in what it was told.
[ "$REFUSED" -eq 0 ]
