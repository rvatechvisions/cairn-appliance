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
KEYTAB="${CAIRN_KEYTAB:-${CONFIG_DIR}/cairn.keytab}"
DHCP_SERVERS="${CAIRN_DHCP_SERVERS:-}"

say "Cairn appliance preflight"
say "realm     ${REALM:-<unset>}"
say "dc        ${DC:-<unset>}"
say "principal ${PRINCIPAL:-<unset>}"
say "keytab    ${KEYTAB}"
say "dhcp      ${DHCP_SERVERS:-<unset>}"
say ""
say "Read-only throughout. Nothing is submitted anywhere."

# ---------------------------------------------------------------------------
# 0. The keytab, before anything tries to use it.
#
# Checked for permissions as well as presence. A keytab any local user can read
# is the appliance's domain identity readable by anybody with a shell on it,
# and that is worth failing on rather than noting.
# ---------------------------------------------------------------------------
rule "the keytab"
if [ ! -f "$KEYTAB" ]; then
  say "NOT FOUND: ${KEYTAB}"
  say "  Nothing below can be asked. Put the keytab in place and run this again."
  exit 1
fi

PERMS="$(stat -c '%a %U:%G' "$KEYTAB" 2>/dev/null || echo 'unknown')"
say "present: ${KEYTAB} (${PERMS})"
case "$PERMS" in
  "600 root:root") say "  permissions are what they should be." ;;
  *)
    say "  REFUSING TO CONTINUE: this must be 600 and owned by root."
    say "  A keytab readable by anybody else is the domain account readable by"
    say "  anybody else. Fix it with:"
    say "    chown root:root ${KEYTAB} && chmod 600 ${KEYTAB}"
    exit 1
    ;;
esac

# ---------------------------------------------------------------------------
# 0. Is this host a domain member, and by what mechanism?
#
# ## This is the step the product question turns on
#
# `SPIKE-LINUX-DHCP-2026-09-19.md` chose Windows over Linux on one argument:
# a domain-joined Windows collector runs under a group Managed Service Account,
# where Active Directory generates and rotates the password and nothing sits in
# a file anybody has to protect. A Linux collector needs a keytab on disk --
# a long-lived credential, on a machine the client's domain does not manage.
#
# **Mode 600 and a .gitignore entry do not answer that.** They constrain who on
# this host can read the file. They are a lab-acceptable deferral, not a
# solution, and this script says so rather than implying the problem is handled.
#
# The candidate answer is a real domain join: realmd and adcli give the host a
# **machine account**, the join tooling creates and rotates the keytab, and
# revocation becomes disabling the computer object in Active Directory. It is
# still a keytab on disk -- it is not a gMSA, and nothing here should pretend
# otherwise -- but it moves Linux from *a secret nobody manages* to *a domain
# member like any other*.
#
# ## It reports, and decides nothing
#
# A ticket from a hand-placed keytab and a ticket from a machine account are
# the same ticket to step 1 and a different product. So this step exists to
# make the difference visible in the output, and it never blocks the steps
# below: a host with a hand-placed keytab is a perfectly good lab instrument.
# ---------------------------------------------------------------------------
rule "0. Domain membership"
capability_domain_join() {
  local joined=0

  if command -v realm >/dev/null 2>&1; then
    local realms
    realms="$(realm list --name-only 2>/dev/null)"
    if [ -n "$realms" ]; then
      say "FOUND: joined through realmd:"
      printf '%s\n' "$realms" | sed 's/^/    /'
      joined=1
    else
      say "realm is installed and this host is joined to nothing."
    fi
  else
    say "realm(8) is not installed, so a realmd join cannot be detected."
  fi

  if command -v adcli >/dev/null 2>&1; then
    say "adcli is available for a join."
  else
    say "adcli is not installed."
  fi

  # The machine account's own keytab, which is what a join writes. Distinct
  # from CAIRN_KEYTAB, which is the one a person placed.
  if [ -f /etc/krb5.keytab ]; then
    say "a machine keytab exists at /etc/krb5.keytab, which a join writes."
    joined=1
  fi

  say ""
  if [ "$joined" -eq 1 ]; then
    say "This host is a domain member. The credential below is managed by the"
    say "  domain rather than placed by hand, and revoking it is disabling the"
    say "  computer object in Active Directory."
    say "  It is still a keytab on disk. It is not a gMSA."
    FOUND=$((FOUND + 1))
    return 0
  fi

  say "NOT JOINED: this host authenticates with a keytab somebody placed."
  say "  That is acceptable for a lab instrument and is NOT a solution to the"
  say "  credential problem: the file is long-lived, the domain does not manage"
  say "  it, it does not rotate, and revoking it means knowing it exists."
  say "  Nothing below is blocked by this. What it changes is what a passing"
  say "  run is worth as a product rather than as an experiment."
  UNASKED=$((UNASKED + 1))
  return 1
}
capability_domain_join

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

  # A private cache, so this never disturbs a ticket somebody else on the host
  # is holding and nothing is left behind in the default one.
  export KRB5CCNAME="FILE:$(mktemp -t cairn-preflight-XXXXXX.ccache)"

  if kinit -k -t "$KEYTAB" "$PRINCIPAL" 2>&1 | sed 's/^/  /'; then
    say "FOUND: a ticket was issued for ${PRINCIPAL}"
    klist 2>/dev/null | sed 's/^/  /'
    FOUND=$((FOUND + 1))
    return 0
  fi

  say "REFUSED: no ticket. The account, the keytab or the clock is the cause;"
  say "  a keytab stops working when the account's password is changed."
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
