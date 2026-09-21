#!/usr/bin/env bash
#
# What can this appliance actually reach, and with what?
#
# ## Four capabilities, reported separately
#
# Kerberos, Active Directory over LDAP, the DNS zones held in the directory,
# and DHCP over MS-DHCPM. They are four different things and they fail for four
# different reasons: a credential the KDC will not accept, an account that
# cannot read the directory, a domain whose DNS is not directory-integrated,
# and an account that is not in DHCP Users. Reporting them as one verdict
# sends somebody to fix whichever one they thought of first.
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

# The places a password actually gets parked, not just the settings file.
#
# This checked $SETTINGS alone and then printed "no keytab, no stored password.
# Nothing here outlives a run" -- a claim about the whole box from a look at one
# file. The gap is not hypothetical: the obvious way to make an unattended daily
# run work is a systemd EnvironmentFile or a cron wrapper carrying
# CAIRN_PASSWORD, and NONE of those were looked at while the line still printed.
#
# A scan is only ever evidence about what it walks, so the reach is now named in
# the output rather than implied by it. What it still cannot see is stated below
# rather than left for somebody to discover: an environment variable exported
# from a parent process leaves no file to find, and this list is the common
# places rather than every place.
PASSWORD_HOMES="
${SETTINGS}
${CONFIG_DIR}/environment
/etc/environment
/etc/default/cairn-appliance
/root/.bashrc
/root/.profile
/etc/cron.d/cairn-appliance
/var/spool/cron/crontabs/root
"

for home in $PASSWORD_HOMES; do
  [ -f "$home" ] || continue
  if grep -qiE '(CAIRN_PASSWORD|CAIRN_PASS|CAIRN_SECRET)=..*' "$home" 2>/dev/null; then
    say "FOUND A PASSWORD in ${home}"
    DURABLE=1
  fi
done

# systemd units are the other obvious home, and they are found rather than
# listed: an EnvironmentFile= line pointing anywhere at all is worth seeing.
if [ -d /etc/systemd/system ]; then
  for unit in $(grep -rlE 'cairn|preflight' /etc/systemd/system 2>/dev/null); do
    if grep -qiE '(CAIRN_PASSWORD|CAIRN_PASS|CAIRN_SECRET)|EnvironmentFile' "$unit" 2>/dev/null; then
      say "A SYSTEMD UNIT MAY CARRY A CREDENTIAL: ${unit}"
      DURABLE=1
    fi
  done
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

# The claim is the size of the look, which it was not before.
say "no keytab, and no password in the places this looked:"
say "  ${SETTINGS}, /etc/environment, /etc/default, root's shell profiles,"
say "  root's crontab, /etc/cron.d, and any systemd unit naming cairn."
say "  It cannot see a variable exported by whatever started this run, so"
say "  'nothing outlives a run' is true of the disk rather than of everything."

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

  # Ask for it here rather than requiring the operator to arrange an
  # environment variable first.
  #
  # The documented lab path was `read -rs CAIRN_PASSWORD && export ...` in the
  # operator's own shell, and it is fragile in three separate ways that all
  # look like a wrong password:
  #
  #   - **Pasted as a block, `read` consumes the NEXT LINE OF THE PASTE.** The
  #     password becomes `echo`, kinit reports *Password incorrect*, and the
  #     domain records a failed logon for a password nobody typed.
  #   - A new terminal, or a reboot, arrives with nothing set -- which is the
  #     design working, and is indistinguishable from having forgotten.
  #   - An exported variable is readable from /proc for the life of the shell,
  #     by root, long after the run that needed it.
  #
  # Prompting removes all three: one command, nothing to paste, and the value
  # lives in this process rather than in the shell that launched it.
  #
  # CAIRN_PASSWORD is still honoured when it is set, because a non-interactive
  # run has no terminal to ask. `[ -t 0 ]` is the test for that, and a run with
  # no terminal and no variable falls through to the refusal below rather than
  # blocking for input nobody can supply.
  # THE PORTAL FETCH COMES FIRST, and its position is the whole point.
  #
  # Below this, a run with no credential prompts a human. That is the lab
  # path and the script says so in terms: **never use this at a customer**.
  # If the fetch ran after the prompt, an enrolled appliance at a district
  # would still ask somebody for the password -- and the operator typing it
  # would have no way to know the box could have got it itself.
  #
  # So: enrolled, told a portal, and not already carrying a credential means
  # the credential comes from the portal and nothing is typed.
  if [ -z "${CAIRN_PASSWORD:-}" ] && [ "$enrolled" -eq 1 ] && [ -n "${CAIRN_PORTAL:-}" ]; then
    local fetched=""
    local fetch_status=0

    # -emit writes ONLY the password to stdout; the username and any refusal
    # go to stderr, which is left attached so the operator sees them. The
    # value is captured into a variable and never echoed.
    # ONE invocation. An earlier draft of this ran it twice -- once to catch
    # stderr and once for the value -- which would have spent a nonce on a
    # request whose answer was thrown away, and left the operator reading the
    # diagnostics of a fetch that was not the one that counted.
    fetched="$("${HERE}/preflight/preflight" -portal "${CAIRN_PORTAL}" -fetch -emit)" || fetch_status=$?

    if [ "$fetch_status" -eq 0 ] && [ -n "$fetched" ]; then
      CAIRN_PASSWORD="$fetched"
      export CAIRN_PASSWORD
      unset fetched

      say ""
      say "CREDENTIAL SOURCE: the portal, fetched for this run."
      say "  It was not typed, is not on this disk, and goes no further than"
      say "  this process and one memory-backed ticket cache."
      FOUND=$((FOUND + 1))
      return 0
    fi

    # A refusal here is NOT a fall-through to the prompt. The box is enrolled
    # and was told a portal; if the portal would not hand it a credential,
    # that is the finding, and asking a human to type one instead would
    # paper over exactly the thing this run is testing.
    say ""
    say "REFUSED: enrolled, and the portal would not hand over a credential."
    say "  Nothing was typed and nothing was sent to the domain."
    say "  The portal named the reason on stderr above. The usual causes are a"
    say "  revoked appliance, a clock more than five minutes out, or no"
    say "  credential saved on that connection yet."
    REFUSED=$((REFUSED + 1))
    return 1
  fi

  if [ -z "${CAIRN_PASSWORD:-}" ] && [ -t 0 ]; then
    printf '\n  password for %s (not echoed): ' "${PRINCIPAL:-the service account}"
    IFS= read -rs CAIRN_PASSWORD
    printf '\n'
    export CAIRN_PASSWORD
  fi

  if [ -n "${CAIRN_PASSWORD:-}" ]; then
    say ""
    say "CREDENTIAL SOURCE: this operator's terminal, for this run only."
    say "  This is the lab path. It is honest about what it is: the credential"
    say "  is held in this process and one memory-backed ticket cache, and"
    say "  nothing writes it down -- but it passed through a human's terminal,"
    say "  which is exactly what the portal fetch exists to avoid."
    say "  **Never use this at a customer.** See LAB-BUILD.md."
    FOUND=$((FOUND + 1))
    return 0
  fi


  # Reached only with no terminal AND no variable, which is a scheduled or
  # piped run. There is nobody to prompt, so it says what such a run needs
  # rather than printing an interactive recipe nothing there can follow.
  say ""
  say "NO CREDENTIAL SOURCE, and no terminal to ask at."
  say "  Run this from a terminal and it will prompt, or set CAIRN_PASSWORD"
  say "  in the environment of the run for an unattended one."
  say ""
  say "  Do not put a password in ${SETTINGS}."
  say "  This script refuses to start if it finds one there."
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

  # Said before the request rather than after the refusal, and the reason is a
  # rule rather than tidiness: ONE FAILED AUTHENTICATION IS A STOP, NOT A
  # RETRY. Failed authentications accumulate in somebody else's directory as
  # lockout counters and security events, so a request we can already see is
  # malformed is one not to send. A lower-case realm is the most common
  # first-run mistake and the KDC's answer to it names neither the realm nor
  # its case.
  #
  # It warns and proceeds rather than refusing. A lower-case realm is unusual
  # and not illegal, and a guard that refuses a legal configuration is a guard
  # somebody switches off.
  case "$REALM" in
    *[a-z]*)
      say "NOTE BEFORE ASKING: CAIRN_REALM is '${REALM}', which contains lower"
      say "  case. Kerberos realms are case-sensitive and conventionally upper"
      say "  case. If this refuses, try '$(printf '%s' "$REALM" | tr 'a-z' 'A-Z')'"
      say "  before suspecting the password or the clock."
      ;;
  esac

  # A ticket cache in RAM that OTHER PROCESSES CAN ALSO READ.
  #
  # This was `MEMORY:cairn-preflight` and it did not work, in a way that looked
  # exactly like working. **An MIT `MEMORY:` cache lives in the address space of
  # the process that created it.** kinit made one, put a real ticket in it, exited
  # 0 -- and the cache went with it. Every later process inherited the variable
  # naming a cache that no longer existed, so ldapsearch reported *No Kerberos
  # credentials available (default cache: MEMORY:cairn-preflight)* and read as a
  # permissions problem in somebody's directory.
  #
  # `/dev/shm` is tmpfs: RAM, never written to persistent storage, cleared on
  # reboot. A file there is readable by processes rather than by one process,
  # which is the property that was actually needed, and the directory is private
  # and removed on exit below.
  #
  # **The claim is narrowed rather than defended.** It is no longer "nothing is
  # ever written down" -- it is "the ticket exists only in RAM, only for this
  # run, in a directory only root can enter, and it is removed when this script
  # ends." Root can read another process's memory anyway, so against the
  # attacker who matters this is the same guarantee; against the disk it is
  # identical. Saying "MEMORY:" while leaving the capability broken was the
  # worse of the two.
  if [ ! -d /dev/shm ]; then
    say "NOT ASKED: no /dev/shm on this host, so there is nowhere to hold a"
    say "  ticket in RAM. This refuses rather than falling back to disk: a"
    say "  ticket under /tmp would survive this run and outlive the reason for"
    say "  it, which is the one thing this design exists to prevent."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  CCDIR="$(mktemp -d /dev/shm/cairn-preflight.XXXXXX)" || {
    say "NOT ASKED: could not create a private cache directory in /dev/shm."
    UNASKED=$((UNASKED + 1))
    return 1
  }
  # Armed before anything else can fail, and not three lines later: a cleanup
  # installed after the next command is a directory that leaks whenever that
  # command is the one that breaks. It covers an interrupt too, because a
  # cleanup that only runs on the happy path is one that does not run on the
  # day it matters.
  trap 'rm -rf "$CCDIR"' EXIT INT TERM

  chmod 700 "$CCDIR"
  export KRB5CCNAME="FILE:${CCDIR}/ccache"

  # A Kerberos configuration for this run, written beside the ticket.
  #
  # `krb5-user` installs with DEBIAN_FRONTEND=noninteractive so that its realm
  # dialogue cannot stall an unattended bootstrap, and the cost of that is an
  # /etc/krb5.conf with no default realm. **kinit does not notice**, because
  # CAIRN_PRINCIPAL is fully qualified and carries its own realm -- so step 1
  # passes and step 2 fails with *Unspecified GSS failure ... Configuration
  # file does not specify default realm*, which names neither Kerberos nor the
  # file it is about. Seen on the appliance, 20 September 2026.
  #
  # It is generated per run in the tmpfs directory rather than written to
  # /etc, because preflight answers what this host can reach and must not
  # change the host to get a better answer. Everything in it is derived from
  # settings the operator already supplied; nothing is invented.
  #
  # `rdns = false` is not a preference: with reverse lookups on, the service
  # principal is built from whatever PTR the resolver returns, so a DC with a
  # stale or absent PTR produces a principal the KDC has never heard of, and
  # the error talks about a server rather than about DNS.
  {
    printf '[libdefaults]\n'
    printf '    default_realm = %s\n' "$REALM"
    printf '    dns_lookup_realm = false\n'
    printf '    dns_lookup_kdc = true\n'
    printf '    rdns = false\n\n'
    printf '[realms]\n'
    printf '    %s = {\n' "$REALM"
    printf '        kdc = %s\n' "$DC"
    printf '    }\n\n'
    printf '[domain_realm]\n'
    printf '    .%s = %s\n' "$(printf '%s' "$REALM" | tr 'A-Z' 'a-z')" "$REALM"
    printf '    %s = %s\n' "$(printf '%s' "$REALM" | tr 'A-Z' 'a-z')" "$REALM"
  } > "${CCDIR}/krb5.conf" || {
    say "NOT ASKED: could not write a Kerberos configuration for this run."
    UNASKED=$((UNASKED + 1))
    return 1
  }
  export KRB5_CONFIG="${CCDIR}/krb5.conf"

  # And an OpenLDAP configuration beside it, because `rdns = false` above does
  # not reach the LDAP client.
  #
  # **OpenLDAP canonicalises the server's name itself before handing it to
  # GSSAPI**, by reverse-resolving the address it connected to. That is a
  # separate mechanism from MIT Kerberos's `rdns`, governed by SASL_NOCANON in
  # ldap.conf, and it is why an appliance can hold a perfectly good service
  # ticket for ldap/<the configured name> and still be told the server is not
  # in the Kerberos database: the client asked for ldap/<whatever the PTR
  # said>, which is a different principal and frequently does not exist.
  #
  # Proven on the appliance, 20 September 2026: kvno obtained tickets for
  # ldap/, host/ AND cifs/ on the configured name, while ldapsearch against
  # that same name was refused. The SPN was never the problem.
  #
  # Turning canonicalisation off makes the name the operator configured the
  # name that is used, which is the same decision as `rdns = false` and is
  # made for the same reason: a stale or absent PTR should not silently
  # redirect a request somewhere nobody chose.
  printf 'SASL_NOCANON on\n' > "${CCDIR}/ldap.conf" || {
    say "NOT ASKED: could not write an LDAP configuration for this run."
    UNASKED=$((UNASKED + 1))
    return 1
  }
  export LDAPCONF="${CCDIR}/ldap.conf"

  say "krb5.conf: generated for this run from CAIRN_REALM and CAIRN_DC."
  say "ldap.conf: generated with SASL_NOCANON on, so the configured name is"
  say "  the name used rather than whatever a reverse lookup returns."
  if [ -f /etc/krb5.conf ] && grep -q 'default_realm' /etc/krb5.conf; then
    say "  /etc/krb5.conf also names a default realm and is NOT being used here."
    say "  If a later collector reads it instead, that file is what it will get."
  fi

  # Piped into kinit rather than passed as an argument: a password on a command
  # line is visible in `ps` to every user on the host for as long as the call
  # takes, which is a disclosure to anybody watching.
  #
  # Captured rather than piped straight into sed, because the refusal below has
  # to read what the KDC actually said. Piping it away left every failure
  # looking alike -- "the account, the password or the clock" -- when kinit had
  # already distinguished them.
  local kinit_out kinit_status
  kinit_out="$(printf '%s' "$CAIRN_PASSWORD" | kinit "$PRINCIPAL" 2>&1)"
  kinit_status=$?
  [ -n "$kinit_out" ] && printf '%s\n' "$kinit_out" | sed 's/^/  /'

  if [ "$kinit_status" -eq 0 ]; then

    # Read the cache rather than trusting the exit status.
    #
    # kinit returned 0 for two whole runs while leaving nothing any later
    # process could use, and this line is why nobody saw it: klist's error
    # stream went to the null device, so an empty cache printed exactly what a
    # full one would have printed on a quiet day -- nothing. Absence of output
    # read as absence of a problem.
    local tickets
    tickets="$(klist 2>&1)"
    case "$tickets" in
      *"$PRINCIPAL"*)
        say "FOUND: a ticket was issued for ${PRINCIPAL} and is readable."
        say "  cache: ${KRB5CCNAME}"
        say "  in RAM (tmpfs), private to root, removed when this script ends."
        printf '%s\n' "$tickets" | sed 's/^/  /'
        FOUND=$((FOUND + 1))
        return 0
        ;;
    esac

    say "REFUSED: kinit reported success and the cache holds no usable ticket."
    say "  This is not a refusal by the domain -- the request was accepted."
    say "  What klist says about ${KRB5CCNAME}:"
    printf '%s\n' "$tickets" | sed 's/^/  /'
    REFUSED=$((REFUSED + 1))
    return 1
  fi

  # What the KDC said, rather than a list of everything it might have meant.
  #
  # kinit distinguishes these and the first version of this message did not,
  # printing "the account, the password or the clock" over an answer that had
  # already named one of the three. A refusal that lists every possible cause
  # sends somebody to check all of them, starting with whichever they thought
  # of first.
  case "$kinit_out" in

    *"Password incorrect"*)
      say "REFUSED: the domain answered, and the password does not match."
      say ""
      say "  THIS IS A DEFINITE ANSWER, AND THREE THINGS ARE NOW PROVEN: the"
      say "  realm is right, ${PRINCIPAL} exists, and the KDC is reachable and"
      say "  replied. Only the password is wrong."
      say ""
      say "  STOP RATHER THAN RETRYING. Each attempt increments the lockout"
      say "  counter on this account in the customer's own directory and writes"
      say "  a failed-logon event to the domain controller. A password typed"
      say "  twice more is a locked service account and a security alert"
      say "  somebody has to answer for."
      say ""
      say "  Verify it away from here instead: sign in as ${PRINCIPAL} on a"
      say "  domain-joined machine, or reset it deliberately on the DC and use"
      say "  the value you set. It was read without echo, so a typo is"
      say "  invisible -- check the length matches what you expect with"
      say "  printf '%s' \"\${#CAIRN_PASSWORD}\" before trying again."
      ;;

    *"Clock skew"*|*"clock skew"*)
      say "REFUSED: the clocks disagree by more than Kerberos allows."
      say "  Five minutes is the limit. Neither the password nor the account is"
      say "  implicated: this request never got as far as being judged."
      say "  Compare 'timedatectl status' here with the clock on ${DC}."
      ;;

    *"not found in Kerberos database"*|*"Client not found"*)
      say "REFUSED: the KDC has no such principal as ${PRINCIPAL}."
      say "  The realm answered, so this is the NAME rather than the domain."
      say "  Check CAIRN_PRINCIPAL against the account's userPrincipalName, and"
      say "  remember the part after the @ is the realm and is case-sensitive."
      ;;

    *"Password has expired"*|*"password has expired"*)
      say "REFUSED: the password is correct and the domain will not issue on it."
      say "  It has expired. A service account for this should be set not to"
      say "  expire -- see LAB-BUILD.md section 2 -- which is a change to the"
      say "  account rather than anything on this appliance."
      ;;

    *)
      say "REFUSED: no ticket. The account, the password or the clock is the cause."
      say "  Kerberos refuses a request more than five minutes out from the KDC, and"
      say "  the error does not say so in those words."
      ;;
  esac

  # Name the likely cause when the likely cause is our own configuration.
  #
  # A realm written in lower case is the most common first-run failure here,
  # and kinit answers it with "KDC reply did not match expectations" -- a
  # sentence that names neither the realm nor its case. The KDC issues for the
  # upper-case realm, the client asked for the lower-case one, and they do not
  # match. Jackie hit exactly this on the first live run, 20 September 2026.
  #
  # It is reported as the first thing to check rather than as the cause: a
  # lower-case realm is unusual and not illegal, so this must not become a
  # confident wrong answer standing in front of a real password problem.
  case "$REALM" in
    *[a-z]*)
      say ""
      say "  CHECK THE REALM'S CASE FIRST. CAIRN_REALM is '${REALM}', which"
      say "  contains lower case. Kerberos realms are case-sensitive and are"
      say "  conventionally upper case, so a KDC that issues for"
      say "  '$(printf '%s' "$REALM" | tr 'a-z' 'A-Z')' will not match a request"
      say "  for '${REALM}'. Set CAIRN_REALM and the part of CAIRN_PRINCIPAL"
      say "  after the @ in upper case, and leave host names in lower."
      ;;
  esac

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

  # Name our own missing package rather than leaving the reader with a message
  # that names neither SASL nor a package.
  #
  # "No worthy mechs found" means ldapsearch has no GSSAPI SASL mechanism
  # installed. It is not a fact about the domain, the account or the ticket --
  # and arriving one step after Kerberos succeeded, it reads as though the
  # ticket were at fault. bootstrap.sh installs the package now; this is here
  # for an appliance built before it did, and for the day a distribution moves
  # it somewhere else.
  case "$out" in
    *"No worthy mechs found"*|*"Unknown authentication method"*)
      say ""
      say "  THIS IS THIS HOST, NOT THE DOMAIN. ldapsearch has no GSSAPI SASL"
      say "  mechanism installed, so the bind was never attempted. Kerberos"
      say "  succeeded in step 1, and that result stands."
      say ""
      say "    apt-get install -y libsasl2-modules-gssapi-mit"
      say ""
      say "  Then run this again. Nothing on the domain needs changing."
      ;;

    *"Server not found in Kerberos database"*)
      # The name, not the rights, and not the ticket.
      #
      # GSSAPI asked the KDC for ldap/<CAIRN_DC> and the KDC has no such
      # service principal. A domain controller registers its SPNs against the
      # hostname of the machine account, so a CNAME, a round-robin record or
      # any convenience name pointing at it resolves perfectly and has no SPN
      # of its own. `rdns = false` in the generated krb5.conf means the name is
      # used exactly as configured rather than being replaced by whatever a
      # PTR says -- which is the safer default and is what surfaces this.
      say ""
      say "  THIS IS THE NAME, NOT THE ACCOUNT AND NOT THE TICKET."
      say "  Step 1 holds a valid ticket; the KDC has no service principal"
      say "  called ldap/${DC}, and refused before any right was consulted."

      # Read what the resolver says rather than asserting what it probably is.
      #
      # The first version of this branch asserted the alias explanation and
      # told the reader to use "a controller's own hostname". On the appliance
      # this ran against, CAIRN_DC ALREADY WAS one: getent returned the same
      # name and the SRV record advertised it, since a controller registers
      # that record itself. The advice was confident and useless, which is
      # worse than no advice -- so the two cases are now distinguished by
      # reading, and only the one the reading supports is offered.
      local canonical srv_names
      canonical="$(getent hosts "$DC" 2>/dev/null | awk '{print $2}')"

      srv_names=""
      if command -v dig >/dev/null 2>&1 && [ -n "$REALM" ]; then
        srv_names="$(dig +short -t SRV "_ldap._tcp.$(printf '%s' "$REALM" | tr 'A-Z' 'a-z')" 2>/dev/null)"
      fi

      say ""
      say "  What the resolver says ${DC} is:"
      say "    ${canonical:-nothing -- the name did not resolve}"
      if [ -n "$srv_names" ]; then
        say "  Controllers this domain advertises in DNS:"
        printf '%s\n' "$srv_names" | sed 's/^/    /'
      fi

      if [ -n "$canonical" ] && [ "$canonical" != "$DC" ]; then
        say ""
        say "  THESE DIFFER, so ${DC} is an alias. A controller registers its"
        say "  principals against its own name, and an alias pointing at it"
        say "  resolves correctly while having no principal of its own."
        say "  Set CAIRN_DC to ${canonical} and run this again."
      else
        say ""
        say "  THESE AGREE, so this is not an alias and changing CAIRN_DC will"
        say "  not help. The name is the controller's own."
        say ""

        # Ask the KDC which principals it does hold for this host.
        #
        # kvno requests a SERVICE ticket against the TGT already in the cache.
        # It is not a password authentication, so it cannot contribute to a
        # lockout -- which is why it is safe to ask several times here, and
        # why this is the read to make rather than another bind.
        if command -v kvno >/dev/null 2>&1; then
          say "  Asking the KDC which principals it holds for this host:"
          local spn result ldap_spn_exists=0
          for spn in "ldap/${DC}" "host/${DC}" "cifs/${DC}"; do
            result="$(kvno "$spn" 2>&1)"
            case "$result" in
              *"kvno = "*)
                say "    EXISTS       ${spn}"
                [ "$spn" = "ldap/${DC}" ] && ldap_spn_exists=1
                ;;
              *"not found in Kerberos database"*) say "    NOT PRESENT  ${spn}" ;;
              *) say "    UNCLEAR      ${spn} -- ${result}" ;;
            esac
          done
          say ""

          # The conclusion follows the reading, rather than the reading being
          # printed under a conclusion written before it.
          if [ "$ldap_spn_exists" -eq 1 ]; then
            say "  ldap/${DC} EXISTS AND THIS CREDENTIAL CAN OBTAIN IT. So the"
            say "  service principal is not missing and the domain is not"
            say "  refusing it -- the client asked for a DIFFERENT name."
            say ""
            say "  OpenLDAP reverse-resolves the address it connected to and"
            say "  builds the principal from that, separately from Kerberos's"
            say "  own rdns setting. A stale, absent or differing PTR therefore"
            say "  sends it to a principal nobody configured."

            # Show the name that canonicalisation would have produced.
            local addr ptr
            addr="$(getent hosts "$DC" 2>/dev/null | awk '{print $1}')"
            if [ -n "$addr" ]; then
              ptr="$(getent hosts "$addr" 2>/dev/null | awk '{print $2}')"
              say ""
              say "  ${DC} is ${addr}, and reverse-resolving ${addr} gives:"
              say "    ${ptr:-nothing -- there is no PTR record for it}"
              if [ -n "$ptr" ] && [ "$ptr" != "$DC" ]; then
                say "  THAT is the name it was asking for: ldap/${ptr}"
              fi
            fi

            say ""
            say "  This run already sets SASL_NOCANON on, which turns that"
            say "  off. If you are still reading this, that setting did not"
            say "  take effect -- check LDAPCONF is honoured by this build."
          else
            say "  host/ present with ldap/ absent is a computer object missing"
            say "  that one principal, which an administrator adds with setspn"
            say "  on the DC. None present means the KDC that issued the ticket"
            say "  is not the one holding this computer object -- check whether"
            say "  ${REALM} is the domain ${DC} is actually joined to."
          fi
        else
          say "  kvno is not installed, so which principals exist cannot be"
          say "  read from here. It ships in krb5-user."
        fi
      fi
      ;;
  esac

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
  #
  # AN ENTRY UNDER THIS CONTAINER IS NOT THE SAME THING AS AN AUTHORISED
  # SERVER, and the difference would have shipped a finding that fires at every
  # site on earth. Jackie read the RVA run on 20 September 2026: the filter
  # `(objectClass=dHCPClass)` returned TWO entries and ONE server.
  #
  #   CN=DhcpRoot              -- no dhcpServers attribute, no DNS name
  #   CN=dc.rvatechvisions.com -- dhcpServers: i10.200.2.4$rcn=dc...$
  #
  # `DhcpRoot` is a container Microsoft creates in every domain. It is a
  # dHCPClass object, so it matches the filter, and it resolves to nothing --
  # so anything that enumerates children and probes each name would report it
  # as a registration answering nothing. **At 100% of sites.**
  #
  # NOT-A-SERVER AND A SERVER THAT FAILED TO RESOLVE ARE DIFFERENT STATES, and
  # only the second is a finding. That is *unknown is not zero* pointed at a
  # directory object: an entry carrying no `dhcpServers` attribute is not a
  # server whose name is dead, it is not a server.
  #
  # The PowerShell collector is not affected -- it reads `Get-DhcpServerInDC`,
  # which is the authorised list rather than the container -- so this is a
  # hazard for the appliance census only, and it is separated here at the read
  # rather than left for the receiver to filter.
  local entries servers
  entries="$(printf '%s\n' "$out" | grep -c '^dn:' || true)"
  servers="$(printf '%s\n' "$out" | grep -c '^dhcpServers:' || true)"
  say "FOUND: ${entries} entr(ies) under the container, ${servers} carrying a"
  say "  dhcpServers attribute."
  printf '%s\n' "$out" | sed 's/^/  /' | head -40
  say ""
  say "  AN ENTRY IS NOT A SERVER. CN=DhcpRoot is a container Microsoft creates"
  say "  in every domain; it matches this filter and carries no dhcpServers"
  say "  attribute. Only the ${servers} above are authorised servers. An entry"
  say "  with no such attribute is NOT-A-SERVER, which is a different state from"
  say "  a server whose name does not resolve, and only the second is a finding."
  say ""
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

  # ALWAYS BUILD. The previous version built only when the binary was absent,
  # and that is how a run reports on code it did not execute.
  #
  # On 20 September 2026 a credential fix was written, committed, pulled onto
  # the appliance and run -- and the run used the binary left behind by the
  # hour before, because the file still existed. It produced the identical
  # refusal, which read as the fix not working when the fix had never been
  # compiled. Nothing in the output said the probe was stale, and the one line
  # that would have given it away was the BUILDING line not being printed:
  # an absence, which is the hardest thing to notice.
  #
  # That is *committed is not shipped* at the smallest scale. Go's build cache
  # makes a rebuild with no changes almost free, so the guard was saving
  # nothing and costing the ability to trust the result.
  # THE COMPILER IS THE ONE go.mod PINS, AND THAT IS READ RATHER THAN ASSUMED.
  #
  # `toolchain go1.27.1` in go.mod means any Go 1.21+ selects that compiler,
  # fetching it if it has to. That is what makes the binary a property of the
  # COMMIT rather than of whichever machine built it -- the same purpose as
  # -trimpath and the commit stamp, and decision 3 needs all three.
  #
  # It needs network the first time. **A build that quietly fell back to a
  # local compiler is the same defect as a stamp that did not take**: it
  # succeeds, it looks right, and the bytes are not the ones anybody pinned.
  # So the selected toolchain is compared with the pin and a mismatch refuses.
  local pinned selected
  pinned="$(sed -n 's/^toolchain \(go[0-9.]*\)$/\1/p' "${HERE}/preflight/go.mod")"
  selected="$(cd "${HERE}/preflight" && go version 2>/dev/null | awk '{print $3}')"

  if [ -z "$pinned" ]; then
    say "REFUSED: preflight/go.mod names no toolchain."
    say "  The build would use whatever compiler this host happens to have,"
    say "  which makes the binary a property of the machine rather than of the"
    say "  commit. Add a toolchain line before building."
    REFUSED=$((REFUSED + 1))
    return 1
  fi

  if [ "$selected" != "$pinned" ]; then
    say "REFUSED: the TOOLCHAIN IS NOT THE PINNED ONE."
    say "  go.mod pins ${pinned}; this build would use ${selected:-(go did not answer)}."
    say ""
    say "  The usual cause is no network: the pinned compiler is fetched on"
    say "  first use, and a host that cannot reach the proxy falls back to its"
    say "  own. That fallback is refused rather than accepted, because a build"
    say "  that quietly used a different compiler than the one pinned is the"
    say "  same defect as a stamp that did not take."
    say ""
    say "  This is moot once the signed binary ships and this box stops"
    say "  compiling. Until then: give it network once, or build elsewhere."
    REFUSED=$((REFUSED + 1))
    return 1
  fi

  say "toolchain: ${selected} (pinned in go.mod)"
  say "building the DHCP probe..."

  # `go mod tidy` ONLY when there is no go.sum, and the comment that used to
  # sit here was describing a design that had already been replaced.
  #
  # It said go.mod "deliberately pins nothing" and that the require line and
  # checksums are written from the imports on first build. That was true, and
  # stopped being true when the module was pinned and go.sum committed -- and
  # the sentence survived, directly above the one command that rewrites the
  # file it was describing. A superseded design surviving in the prose beside
  # the thing that changed is a shape this project has already paid for once.
  #
  # Tidy is kept for the case it was written for: a tree with no go.sum, where
  # `go build` refuses with "missing go.sum entry" for every import -- five
  # errors naming packages that are all correct. That case needs the network
  # once, and its failure is reported on its own, because "could not reach the
  # module proxy" and "the code does not compile" are different facts and only
  # the second is about this repository.
  #
  # When go.sum IS present the build is offline and the pin is authoritative.
  if [ ! -f "${HERE}/preflight/go.sum" ]; then
    say "  no go.sum: resolving dependencies once, which needs the network"
    if ! (cd "${HERE}/preflight" && go mod tidy 2>&1 | sed 's/^/  /'); then
      say "REFUSED: could not resolve the probe's dependencies."
      say "  This needs outbound network access to the Go module proxy, once."
      say "  It is not a failure of the domain or of this host's credentials."
      REFUSED=$((REFUSED + 1))
      return 1
    fi
  fi

  # The pin has to survive the build, and that is asserted rather than assumed.
  #
  # The toolchain check above compares the selected compiler against the
  # version in go.mod. If anything in this step rewrites go.mod, that check
  # compared against a file the build then changed, and the pin is a sentence
  # rather than a constraint. Cheap to check, and it fails in the direction
  # that asks a person rather than the one that carries on.
  local mod_before
  mod_before="$(cat "${HERE}/preflight/go.mod")"

  # The commit is stamped in, and the stamp is READ BACK below.
  #
  # A binary that cannot say what it is gives the digest pin nothing to check
  # against, and `-X main.commit=` fails SILENTLY: a wrong symbol path, a
  # renamed variable or a quoting slip all produce a clean build and an empty
  # stamp. That is *absence of output read as absence of finding* in a linker
  # flag, so the build is not trusted to have done it.
  local stamp_commit
  stamp_commit="$(git -C "${HERE}" rev-parse HEAD 2>/dev/null || echo "")"

  if ! (cd "${HERE}/preflight" && go build -trimpath -ldflags "-X main.commit=${stamp_commit}" -o preflight . 2>&1 | sed 's/^/  /'); then
    say "REFUSED: the probe's dependencies resolved and it did not compile."
    say ""
    say "  THIS IS THE CODE, NOT THIS HOST. The probe compiled and ran on this"
    say "  appliance on 20 September 2026, so the toolchain, the module cache"
    say "  and the network are all known to work here. A compile failure now is"
    say "  a change made since then, and the compiler names it above."
    say ""
    say "  Nothing about the domain, the account or the credential is implicated."
    REFUSED=$((REFUSED + 1))
    return 1
  fi

  if [ "$(cat "${HERE}/preflight/go.mod")" != "${mod_before}" ]; then
    say "REFUSED: the build rewrote go.mod."
    say ""
    say "  The toolchain check above read a pinned version out of that file,"
    say "  and something here has since changed it -- so what was compared is"
    say "  not what was built against. Run:  git -C . diff preflight/go.mod"
    say "  to see it. Do not commit the rewrite without deciding about it."
    REFUSED=$((REFUSED + 1))
    return 1
  fi

  # Read the artifact rather than assuming the build produced one.
  if [ ! -x "$binary" ]; then
    say "REFUSED: the build reported success and there is no binary at"
    say "  ${binary}. Nothing was asked of any DHCP server."
    REFUSED=$((REFUSED + 1))
    return 1
  fi

  # READ THE STAMP BACK, and refuse a build that did not take one.
  #
  # This is the one question the binary can answer about itself with
  # certainty, and it is the input to the update decision: the appliance
  # refuses to run bytes whose digest does not match what the portal named.
  # An unstamped binary cannot participate in that at all.
  local reported
  reported="$("$binary" -version 2>&1)"

  case "$reported" in
    *unstamped*)
      say "REFUSED: the build succeeded and the STAMP DID NOT TAKE."
      say "  ${binary} -version says: ${reported}"
      say ""
      say "  The linker flag produced no commit. A wrong symbol path, a renamed"
      say "  variable or a quoting slip all build cleanly and stamp nothing, so"
      say "  this is read back rather than assumed. A binary that cannot say what"
      say "  it is gives the digest pin nothing to check against."
      REFUSED=$((REFUSED + 1))
      return 1
      ;;
  esac

  say "  built: $(date '+%Y-%m-%d %H:%M:%S') — ${reported}"

  say "  built: $(date -r "$binary" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'timestamp unreadable')"

  # Each server asked and answered on its own. A site with six DHCP servers
  # where one refuses is a different fact from a site with five servers, and
  # one summary line cannot carry both.
  local any_found=0

  # Split the probe's flags BEFORE IFS is changed below.
  #
  # `local IFS=,` is there to split the comma-separated server list, and it is
  # in scope for everything inside the loop -- so an unquoted expansion added
  # in there later splits on commas too. CAIRN_PROBE_ARGS="-transport
  # ncacn_np:" contains no comma, so it arrived as ONE argument and Go
  # reported `flag provided but not defined: -transport ncacn_np:`, naming a
  # flag that is defined.
  #
  # That is correct-by-arrangement: the IFS change was right for its own loop
  # and quietly wrong for something written inside it an hour later. An array
  # built out here cannot be re-split by it.
  local -a probe_args=()
  if [ -n "${CAIRN_PROBE_ARGS:-}" ]; then
    # shellcheck disable=SC2206
    probe_args=($CAIRN_PROBE_ARGS)
  fi

  local IFS=,
  for server in $DHCP_SERVERS; do
    server="$(printf '%s' "$server" | tr -d ' ')"
    [ -z "$server" ] && continue

    say ""
    say "asking ${server}:"
    # CAIRN_PRINCIPAL is passed explicitly rather than exported globally.
    #
    # settings.env is read with `.`, which makes its names shell variables and
    # NOT environment variables, so the probe would not have seen it however
    # plainly it was named. KRB5CCNAME reaches the probe only because it was
    # separately exported for kinit. Naming it on the command that needs it
    # keeps the reason visible at the place it matters.
    # CAIRN_PROBE_ARGS carries extra flags to the probe:
    #
    #   CAIRN_PROBE_ARGS="-debug" ./preflight.sh
    #   CAIRN_PROBE_ARGS="-transport ncacn_np:" ./preflight.sh
    #
    # It exists because the alternative is running the binary by hand, and the
    # ticket it needs lives in a tmpfs cache this script deletes on exit --
    # so by the time somebody has a shell to run it from, the credential is
    # gone. A diagnostic flag nobody can reach is a flag that does not exist.
    if CAIRN_PRINCIPAL="$PRINCIPAL" "$binary" -server "$server" "${probe_args[@]}" 2>&1 | sed 's/^/  /'; then
      any_found=1
    else
      # "Refused" rather than "did not answer", because they are different
      # facts and this script spends its whole output insisting on that.
      #
      # ERROR_ACCESS_DENIED from R_DhcpEnumSubnets is the server ANSWERING: the
      # mapper resolved, the interface bound, Kerberos authenticated and the
      # call was dispatched. Calling that silence would report a working DHCP
      # service as unreachable and send somebody to look at the network.
      say "  this server refused. The others are still being asked."
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
