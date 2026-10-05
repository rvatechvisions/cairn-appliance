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
# ## It collects nothing, and it reports only what it reached
#
# **The original claim was "no outbound call of any kind" and it is
# withdrawn rather than reworded.** An enrolled box fetches its credential
# from the portal and, at the end, posts what the run reached. Both calls
# are to us and to nowhere else.
#
# What the report carries is the name of each capability and one of three
# states, with a reason where it did not answer. **No device, no lease, no
# address, no account name and no part of the directory.** Inventory has
# its own door with its own rules; nothing here writes through it.
#
# The narrower sentence is the one a domain administrator relies on, and a
# weaker sentence guarded by a stronger claim is the worst arrangement of
# the two: the claim reads true, the sentence is wrong, and nobody finds
# out until a client reads it.
#
set -uo pipefail

CONFIG_DIR=/etc/cairn-appliance
SETTINGS="${CONFIG_DIR}/settings.env"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FOUND=0
REFUSED=0
UNASKED=0
# Capabilities whose read finished and held nothing. A read, not a refusal.
# WO-1004-L item 2 counted these inside FOUND and labeled them; WO-1004-M item 6
# gives them their own state in the run report, so they are their own count.
EMPTY=0

# Capabilities where this run cannot tell a refusal from no answer. WO-1004-M
# item 1: these were counted with the refusals, and a count that adds a refusal
# to an unknown has two populations in one number. A refusal is something the
# other end said; this is something about us.
UNTOLD=0

# Where this run's credential came from, said on its own line and never counted
# as a capability. WO-1004-L item 2: step 0 was counted in FOUND, so a run that
# answered one capability printed two. CREDENTIAL_SOURCE is the same fact as one
# of the seven values the run report sends; the portal keeps it in its own
# column, credential_source, and counts it nowhere.
CREDENTIAL_FROM="not settled: the credential step did not run"
CREDENTIAL_SOURCE=""

say() { printf '%s\n' "$*"; }
rule() { printf '\n--- %s ---\n' "$*"; }

if [ ! -r "$SETTINGS" ]; then
  say "No settings at ${SETTINGS}."
  say "Run bootstrap.sh first, then fill it in. Nothing was asked of the domain."
  exit 1
fi

# shellcheck disable=SC1090
. "$SETTINGS"

# What settings.env still carries, kept UNDER ITS OWN NAMES rather than
# loaded straight into the three variables the run uses.
#
# **The portal is the only source of the domain, the controller, the
# account and the password**, and an enrolled box takes all four from it.
# What is left in settings.env is a leftover from before that was true, and
# a leftover that DISAGREES is refused by name -- because the failure it
# produces otherwise is a Kerberos error naming neither file.
#
# Two sources of truth for one fact is not a configuration question. It is
# the shape where a client renames a domain controller, the portal is
# updated, and a box goes on presenting a credential to a host that has
# gone -- with both records looking correct to whoever reads one of them.
LOCAL_REALM="${CAIRN_REALM:-}"
LOCAL_DC="${CAIRN_DC:-}"
LOCAL_PRINCIPAL="${CAIRN_PRINCIPAL:-}"

# The values the run will actually use. Filled from the portal when there
# is one, and from the file when this is the lab path.
REALM="$LOCAL_REALM"
DC="$LOCAL_DC"
PRINCIPAL="$LOCAL_PRINCIPAL"

# Where each of the three came from, so the run can say so rather than
# leaving somebody to infer it from a value they cannot check.
FIELD_SOURCE="settings.env"

# Where each of the three came from, per field, for the block that prints them
# once they are settled. WO-1004-RS item 5. The portal supplies the account
# always and the domain and controller where it holds them; anything it does not
# supply stays the file's.
REALM_FROM="${SETTINGS}"
DC_FROM="${SETTINGS}"
PRINCIPAL_FROM="${SETTINGS}"

# Set when the credential step could not produce one, and it carries the
# reason. **A run that could not start is not a run that found nothing**,
# and this is the variable that keeps the two apart all the way to the
# portal's card.
CRED_FAILED=0

# **A fourth count, and it is about this box rather than the customer's
# network.** WO-1001-D item 2. FOUND, REFUSED and UNASKED are the three things
# a run can say about what it asked of a client's systems. NOTRUN is a step
# this box never got as far as considering, because its own software could not
# hear what it may read -- and folding that into UNASKED is how ten
# capabilities were reported as not asked when nobody had asked anything.
NOTRUN=0

# Whether the consent list could have been heard, and if not, why. Set by the
# credential step; read by settle_consent. A component may report what it was
# told; it may not report what it failed to hear as what it was told.
CONSENT_FETCHED=0
CONSENT_UNHEARD="no credential came from the portal, so no consent list arrived with one"

# The same three answers as a field of the run report, so the portal reads
# what this box heard rather than inferring it from the reason's prose.
# WO-1004-I item 1. Set by settle_consent to heard, not-sent (a binary that
# relays the list fetched, and the portal's answer carried none) or not-heard
# (this box cannot tell whether the portal sent one). Empty until settled, and
# an empty value is not reported, so the portal reads it as not reported.
CONSENT_LIST=""
CRED_REASON=""

# When this run began, in UTC, stamped once and reported with the run.
# A report with no time is a present-tense claim from evidence of unknown
# age.
RUN_STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Agreement between the portal and a leftover, for one field.
#
# **Case-insensitively**, and that is the fact rather than a leniency: a
# Kerberos realm is conventionally upper case and a client types their own
# domain in lower case, a DNS host name is case-insensitive by
# specification, and an Active Directory account name is too. Comparing
# display bytes would refuse a box whose settings file says exactly the
# same thing in a different case -- which is a comparison that is right
# about bytes and wrong about the fact.
agrees() {
  local left right
  left="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  right="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
  [ "$left" = "$right" ]
}

# Read the portal's credential block, and set four globals from it.
#
# **A function of its own so that something can drive it.** It was written
# inline, where the only way to exercise it was to run the whole script
# against a live portal -- which is the arrangement that leaves a parser
# proven by the one input its author happened to have.
#
# The format: name=value lines, a blank line, then the password as the
# REMAINDER to end of input. Nothing is quoted and nothing is escaped, so a
# password containing an equals sign, a quotation mark, a backslash or a
# newline arrives exactly as the portal sent it. Quoting would be a second
# place for a credential to be mangled, and this project has lost a .env
# secret to exactly that.
PC_USERNAME=""
PC_REALM=""
PC_CAPABILITIES=""
PC_CAPABILITIES_SET=0
PC_CONTROLLER=""
PC_PASSWORD=""
PC_DHCP_SERVERS=""
parse_credential_block() {
  PC_USERNAME=""
  PC_REALM=""
  PC_CAPABILITIES=""
  PC_CAPABILITIES_SET=0
  PC_CONTROLLER=""
  PC_PASSWORD=""
  PC_DHCP_SERVERS=""

  local in_header=1 pw_started=0 line

  while IFS= read -r line; do
    if [ "$in_header" -eq 1 ]; then
      if [ -z "$line" ]; then
        in_header=0
        continue
      fi
      case "$line" in
        username=*)   PC_USERNAME="${line#username=}" ;;
        realm=*)      PC_REALM="${line#realm=}" ;;
        controller=*) PC_CONTROLLER="${line#controller=}" ;;
        dhcp-servers=*) PC_DHCP_SERVERS="${line#dhcp-servers=}" ;;
        capabilities=*)
          PC_CAPABILITIES="${line#capabilities=}"
          PC_CAPABILITIES_SET=1
          ;;
      esac
    elif [ "$pw_started" -eq 0 ]; then
      # **A flag rather than a test for emptiness.** A password whose first
      # line is blank would otherwise have its second line written over the
      # top of it: an empty accumulator and an accumulator holding an empty
      # first line are different states, and only a flag tells them apart.
      PC_PASSWORD="$line"
      pw_started=1
    else
      PC_PASSWORD="${PC_PASSWORD}
${line}"
    fi
  done
}

# **Ask the binary what it can hear before asking it anything.** WO-1001-D
# item 2.
#
# The consent list arrives as one line of the block -emit-credential prints,
# and a binary built before that line existed drops it without a word. The
# 1 October 2026 run on RVA's own appliance was exactly that: a binary from
# 23 September, a script from that morning, and a run that told its operator
# the portal had sent no list -- while the portal was sending one.
#
# So the binary declares, through -speaks, the lines it relays. A binary older
# than the flag rejects it, and the rejection is the answer: this box cannot
# hear its consent list, which is a fact about this box and never about the
# portal or the customer.
#
# Sets BINARY_SPEAKS to what the binary said. Returns 0 when it declares the
# consent list, 1 when it answers without declaring it, 2 when there is no
# binary to ask.
BINARY_SPEAKS=""
binary_hears_consent() {
  local binary="$1"
  BINARY_SPEAKS=""
  if [ ! -x "$binary" ]; then
    return 2
  fi
  BINARY_SPEAKS="$("$binary" -speaks 2>&1)" || BINARY_SPEAKS="${BINARY_SPEAKS:-it answered nothing}"
  case " ${BINARY_SPEAKS#credential-block:} " in
    *" capabilities "*) return 0 ;;
  esac
  return 1
}

# What this run knows about its consent list, settled once and said once.
#
# Three answers, and only one of them is about the portal:
#   - the list arrived, and says what this box may read;
#   - a binary that relays the list fetched from the portal and there was no
#     list in the answer, so the portal sent none;
#   - no list was HEARD, for the reason in CONSENT_UNHEARD, and this box
#     cannot tell whether the portal sent one.
# Sets CONSENT_KNOWN, CONSENTED and CONSENT_LIST, and prints the line.
settle_consent() {
  CONSENTED="$PC_CAPABILITIES"
  CONSENT_KNOWN="$PC_CAPABILITIES_SET"
  if [ "$CONSENT_KNOWN" -eq 1 ]; then
    CONSENT_LIST="heard"
    say "consent   ${CONSENTED:-nothing granted}"
    return 0
  fi
  if [ "$CONSENT_FETCHED" -eq 1 ]; then
    CONSENT_LIST="not-sent"
    CONSENT_UNHEARD="the portal sent no list of what this collector may read"
    say "NO CONSENT LIST: the portal answered without one, so nothing will be read."
  else
    CONSENT_LIST="not-heard"
    say "NO CONSENT LIST WAS HEARD: ${CONSENT_UNHEARD}."
    say "  This box cannot tell whether the portal sent one, so nothing will be"
    say "  read -- and no step below is reported as a finding about the network."
  fi
  if [ "$CRED_FAILED" -eq 0 ]; then
    CRED_FAILED=1
    CRED_REASON="${CONSENT_UNHEARD}, so nothing was read"
  fi
}

# Refuse a leftover that disagrees, naming BOTH values.
#
# Named rather than described: "settings.env disagrees with the portal" is
# a sentence somebody has to go and investigate, and the two strings side
# by side is the investigation.
refuse_disagreement() {
  local field="$1" portal_value="$2" local_value="$3"
  say ""
  say "REFUSING TO CONTINUE: ${field} is set in two places and they disagree."
  say "  the portal says:  ${portal_value}"
  say "  ${SETTINGS} says: ${local_value}"
  say ""
  say "  The portal is the only source of this. Remove CAIRN_REALM, CAIRN_DC"
  say "  and CAIRN_PRINCIPAL from ${SETTINGS} and run this again, or correct"
  say "  the connection in the portal if the file is the one that is right."
  say ""
  say "  Nothing was asked of the domain. Presenting a credential built from"
  say "  two records that disagree is how a box authenticates against a host"
  say "  that has been renamed, and the error it produces names neither."
  exit 1
}

# kinit prints a prompt LABEL even when the password arrives on a pipe, and
# this removes it. It is NOT a prompt: stdin is a pipe on both paths, and the
# script's own prompt is the lower-case one.
#
# **The label is removed and the line is not.** kinit writes the prompt with no
# trailing newline, so a refusal is frequently glued to it --
# `Password for x@REALM: kinit: Password incorrect ...` -- and dropping the line
# would discard the error, which is the rule this project holds hardest.
#
# Why it matters enough to be here at all: this output is the evidence we hand
# a district's administrator that the box does not hold their credential, and
# the label printed four lines under *it was not typed* reads as a prompt
# somebody answered. Held by `preflight-output-test.sh`, which reads this
# expression out of this file rather than keeping a second copy of it.
KINIT_PROMPT_STRIP='s/^Password for [^:]*: *//'
DHCP_SERVERS="${CAIRN_DHCP_SERVERS:-}"
DHCP_SERVERS_FROM=""

# Why no DHCP server is asked, when the box decided not to ask one. Empty when
# it did not decide that. WO-1004-N item 1.
DHCP_REFUSAL=""

# A server list in one comparable form: lower case, no spaces, sorted, so
# "dc.example.test, dhcp2" and "DHCP2,dc.example.test" are the same list.
dhcp_list_key() {
  printf '%s' "$1" | tr 'A-Z' 'a-z' | tr -d ' ' | tr ',' '\n' | sed '/^$/d' | sort -u | paste -sd, -
}

# Which DHCP servers to ask. WO-0928-G item 3: the portal is where a client
# names them, on the card where they allowed DHCP.
#
# **The portal is the only source when the run's credential came from it.**
# WO-1004-N item 1. The consent card says the collector asks the servers the
# client names and nothing else, and until then nothing is read. On 4 October
# 2026 the portal named none and this box read a scope anyway, because the
# settings file named one: the page's promise was false of the one appliance
# there is. So, on a run whose credential came from the portal:
#
#   - the portal and the settings file name different lists: nothing is asked,
#     and both are named, the way refuse_disagreement names a disagreeing
#     domain. The box does not pick one;
#   - the portal names none: nothing is asked, and the reason points at the
#     field on the consent card where the servers are named.
#
# A lab run, whose credential was typed or set in the environment, has no
# portal to name anything, so the settings file is used and the run says so.
#
# $1 is the portal's list (possibly empty), $2 the settings file's, $3 where
# the run's credential came from (CREDENTIAL_SOURCE).
choose_dhcp_servers() {
  local portal="$1" local_list="$2" source="${3:-}"
  local file="${SETTINGS:-settings}"
  DHCP_REFUSAL=""
  if [ "$source" = "portal" ]; then
    if [ -z "$portal" ]; then
      DHCP_SERVERS=""
      DHCP_SERVERS_FROM=""
      if [ -n "$local_list" ]; then
        DHCP_REFUSAL="the portal names no DHCP server, so none is asked. ${file} names ${local_list}, which is not used. Name the servers on the consent card, under DHCP leases, in DHCP servers, one per line."
      else
        DHCP_REFUSAL="the portal names no DHCP server, so none is asked. Name the servers on the consent card, under DHCP leases, in DHCP servers, one per line."
      fi
      return 0
    fi
    if [ -n "$local_list" ] && [ "$(dhcp_list_key "$local_list")" != "$(dhcp_list_key "$portal")" ]; then
      DHCP_SERVERS=""
      DHCP_SERVERS_FROM=""
      DHCP_REFUSAL="the portal names ${portal} and ${file} names ${local_list}, and they disagree, so no DHCP server is asked. Remove CAIRN_DHCP_SERVERS from ${file}, or change the DHCP servers on the consent card if the file is the one that is right."
      return 0
    fi
    DHCP_SERVERS="$portal"
    DHCP_SERVERS_FROM="the portal"
    return 0
  fi
  if [ -n "$portal" ]; then
    # A portal list on a run whose credential did not come from the portal
    # cannot happen today: the list arrives with the credential. Used if it
    # does, and said to be.
    DHCP_SERVERS="$portal"
    DHCP_SERVERS_FROM="the portal"
  elif [ -n "$local_list" ]; then
    DHCP_SERVERS="$local_list"
    DHCP_SERVERS_FROM="${file}, on a run whose credential did not come from the portal"
  else
    DHCP_SERVERS=""
    DHCP_SERVERS_FROM=""
  fi
}

# Which commit this script is and whether a tracked file here differs from it,
# as SCRIPT_ID_STATE (clean, dirty or unknown), SCRIPT_ID_COMMIT and
# SCRIPT_ID_REASON. One function, read by the run report and by the line the
# person at the terminal sees, so the two cannot disagree. WO-1004-RS item 6.
script_identity() {
  SCRIPT_ID_STATE="" SCRIPT_ID_COMMIT="" SCRIPT_ID_REASON=""
  local commit changes
  if ! commit="$(git -C "$HERE" rev-parse HEAD 2>&1)" || ! printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$'; then
    SCRIPT_ID_STATE="unknown"
    SCRIPT_ID_REASON="git could not say which commit this script is: $(printf '%s' "$commit" | head -n 1)"
    return 0
  fi
  if ! changes="$(git -C "$HERE" status --porcelain --untracked-files=no 2>&1)"; then
    SCRIPT_ID_STATE="unknown"
    SCRIPT_ID_REASON="git could not say whether ${commit} has local changes: $(printf '%s' "$changes" | head -n 1)"
    return 0
  fi
  SCRIPT_ID_COMMIT="$commit"
  if [ -z "$changes" ]; then SCRIPT_ID_STATE="clean"; else SCRIPT_ID_STATE="dirty"; fi
}

# The script's identity as the person at the terminal reads it. WO-1004-RS
# item 6: the run sent the portal its commit and printed nothing, so the one
# person who had just pulled could not see from the output whether the pull
# took.
script_line() {
  script_identity
  case "$SCRIPT_ID_STATE" in
    clean) say "script    preflight.sh at ${SCRIPT_ID_COMMIT}, no tracked file edited on this box" ;;
    dirty) say "script    preflight.sh at ${SCRIPT_ID_COMMIT}, WITH A TRACKED FILE EDITED ON THIS BOX" ;;
    *) say "script    preflight.sh, commit not known: ${SCRIPT_ID_REASON}" ;;
  esac
}

# **Nothing here is printed before it is settled.** WO-1004-RS item 5: this
# block printed the domain, controller, account and DHCP servers from the
# settings file, with no source, at the top of the screen -- and the portal is
# the source of all four on an enrolled box, so on the day the two disagree the
# first thing a person reads would name a server that is not being asked. They
# are printed after the credential step, once settled, each with where it came
# from.
say "Cairn appliance preflight"
say "The domain, the controller, the account and the DHCP servers are printed"
say "once they are settled, after the credential step, with where each came from."
say ""
say "Read-only throughout. Nothing is collected, and the only thing sent"
say "anywhere is which capabilities answered, to the portal, at the end."
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

# The scan is a FUNCTION so that something can drive it.
#
# **This was a block, and it was the only enforcement of a promise about a
# client's domain controller with no test behind it.** It could not have had
# one: CONFIG_DIR is a literal, so nothing could point the scan anywhere but
# this machine's own /etc.
#
# The three places it looks are parameters now and the caller passes the real
# ones. It prints what it found and returns non-zero when it found anything,
# so the refusal below still belongs to the caller — a scan that exits on
# somebody's behalf is a scan nothing can test either.
#
# Echoes one line per find. Returns 0 when the box is clean, 1 when it is not.
durable_credentials() {
  local config_dir="$1"
  local system_keytab="$2"
  local password_homes="$3"
  local unit_dir="$4"
  local dirty=0

  local found
  for found in "$config_dir"/*.keytab "$config_dir"/*.kt "$system_keytab"; do
    [ -e "$found" ] || continue
    printf 'FOUND A KEYTAB: %s\n' "$found"
    dirty=1
  done

  local home
  for home in $password_homes; do
    [ -f "$home" ] || continue
    if grep -qiE '(CAIRN_PASSWORD|CAIRN_PASS|CAIRN_SECRET)=..*' "$home" 2>/dev/null; then
      printf 'FOUND A PASSWORD in %s\n' "$home"
      dirty=1
    fi
  done

  if [ -d "$unit_dir" ]; then
    local unit
    for unit in $(grep -rlE 'cairn|preflight' "$unit_dir" 2>/dev/null); do
      if grep -qiE '(CAIRN_PASSWORD|CAIRN_PASS|CAIRN_SECRET)|EnvironmentFile' "$unit" 2>/dev/null; then
        printf 'A SYSTEMD UNIT MAY CARRY A CREDENTIAL: %s\n' "$unit"
        dirty=1
      fi
    done
  fi

  return "$dirty"
}

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

# The caller passes the real paths, and owns the refusal.
DURABLE_REPORT="$(durable_credentials "$CONFIG_DIR" /etc/krb5.keytab "$PASSWORD_HOMES" /etc/systemd/system)"
DURABLE=$?

if [ -n "$DURABLE_REPORT" ]; then
  say "$DURABLE_REPORT"
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

    # The handshake comes before the fetch, so a binary that could not hear
    # the consent list never spends a nonce on a credential it would then
    # hand over without one.
    local hears=0
    binary_hears_consent "${HERE}/preflight/preflight" || hears=$?
    if [ "$hears" -ne 0 ]; then
      local found_stamp
      found_stamp="$("${HERE}/preflight/preflight" -version 2>&1)" || found_stamp="${found_stamp:-no answer}"
      say ""
      if [ "$hears" -eq 2 ]; then
        say "NOT RUN: there is no binary at ${HERE}/preflight/preflight to fetch with."
        CONSENT_UNHEARD="there is no binary on this box to fetch the consent list with"
      else
        say "NOT RUN: the installed binary is too old to hear the consent list."
        say "  needs:  a binary whose -speaks declares the capabilities line"
        say "  found:  ${found_stamp}"
        say "  -speaks answered: ${BINARY_SPEAKS}"
        CONSENT_UNHEARD="the installed binary (${found_stamp}) is older than the consent list and cannot hear it"
      fi
      say ""
      say "  Nothing was fetched, nothing was asked of the domain, and nothing"
      say "  here is about the portal or the customer. Install the published"
      say "  binary by the path in INSTALL-STEPS.md and run this again."
      CREDENTIAL_FROM="none: ${CONSENT_UNHEARD}"
      CREDENTIAL_SOURCE="not-fetched"
      CRED_FAILED=1
      CRED_REASON="${CONSENT_UNHEARD}; nothing was fetched or read"
      return 1
    fi

    # -emit writes ONLY the password to stdout; the username and any refusal
    # go to stderr, which is left attached so the operator sees them. The
    # value is captured into a variable and never echoed.
    # ONE invocation. An earlier draft of this ran it twice -- once to catch
    # stderr and once for the value -- which would have spent a nonce on a
    # request whose answer was thrown away, and left the operator reading the
    # diagnostics of a fetch that was not the one that counted.
    # -emit-credential, never -emit: the portal supplies four fields and
    # this box uses all four. The header lines carry no secret and the
    # password is the remainder after the blank line, so nothing has to be
    # quoted and a password containing any byte at all survives.
    fetched="$("${HERE}/preflight/preflight" -portal "${CAIRN_PORTAL}" -fetch -emit-credential)" || fetch_status=$?

    if [ "$fetch_status" -eq 0 ] && [ -n "$fetched" ]; then
      parse_credential_block <<< "$fetched"
      unset fetched

      local portal_username="$PC_USERNAME"
      local portal_realm="$PC_REALM"
      local portal_controller="$PC_CONTROLLER"
      CAIRN_PASSWORD="$PC_PASSWORD"

      # **A header that never arrived is a refusal, not a blank password.**
      # This is the shape a half-pulled box takes: an older binary answering
      # -emit-credential with a bare password, or a newer portal answering
      # something this script does not recognise. Handing whatever came back
      # to kinit would put a failed logon in a customer’s domain.
      # **What is missing is what the BINARY printed**, and nothing here can
      # see past it to what the portal sent -- so the sentence names the
      # binary. It was counted REFUSED and blamed the portal until WO-1001-D
      # item 2, and told the operator to rebuild on a box that has had no
      # compiler since 24 September 2026.
      if [ -z "$portal_username" ] || [ -z "${CAIRN_PASSWORD:-}" ]; then
        say ""
        say "NOT RUN: the binary's credential block did not carry the fields this"
        say "  run needs -- a username line, and a password after a blank line."
        say "  This box cannot tell whether the portal sent them. The usual cause"
        say "  is a binary and a script from different installs: install the"
        say "  published binary by the path in INSTALL-STEPS.md and try again."
        say "  Nothing was typed and nothing was sent to the domain."
        CREDENTIAL_FROM="none: the portal answered and the binary's credential block was incomplete"
        CREDENTIAL_SOURCE="portal-incomplete"
        CRED_FAILED=1
        CRED_REASON="the binary's credential block did not carry the expected fields"
        CONSENT_UNHEARD="the binary's credential block was incomplete, so no consent list was read from it"
        return 1
      fi

      # Fetched by a binary that declared the consent list, so an absent list
      # below is the portal's answer rather than this box's silence.
      CONSENT_FETCHED=1

      export CAIRN_PASSWORD

      # **The leftover is checked against the portal before anything uses
      # either.** A disagreement is refused here, with both values named,
      # rather than at the KDC where the message names neither.
      if [ -n "$LOCAL_PRINCIPAL" ] && ! agrees "$LOCAL_PRINCIPAL" "$portal_username"; then
        refuse_disagreement "the service account" "$portal_username" "$LOCAL_PRINCIPAL"
      fi
      if [ -n "$portal_realm" ] && [ -n "$LOCAL_REALM" ] \
         && ! agrees "$LOCAL_REALM" "$portal_realm"; then
        refuse_disagreement "the domain" "$portal_realm" "$LOCAL_REALM"
      fi
      if [ -n "$portal_controller" ] && [ -n "$LOCAL_DC" ] \
         && ! agrees "$LOCAL_DC" "$portal_controller"; then
        refuse_disagreement "the domain controller" "$portal_controller" "$LOCAL_DC"
      fi

      # The portal's values win where it has one. Where it has none -- a
      # connection saved before those columns existed -- the file is used and
      # the run says so, because a value silently coming from somewhere else
      # is the thing this whole change is against.
      PRINCIPAL="$portal_username"
      PRINCIPAL_FROM="the portal"
      if [ -n "$portal_realm" ]; then REALM="$portal_realm"; REALM_FROM="the portal"; fi
      if [ -n "$portal_controller" ]; then DC="$portal_controller"; DC_FROM="the portal"; fi
      FIELD_SOURCE="the portal"

      say ""
      say "CREDENTIAL SOURCE: the portal, fetched for this run."
      say "  It was not typed, is not on this disk, and goes no further than"
      say "  this process and one memory-backed ticket cache."
      say ""
      say "  account:    ${PRINCIPAL}"
      if [ -n "$portal_realm" ]; then
        say "  domain:     ${REALM}"
      else
        say "  domain:     ${REALM}  (from ${SETTINGS}; the portal has none)"
      fi
      if [ -n "$portal_controller" ]; then
        say "  controller: ${DC}"
      else
        say "  controller: ${DC}  (from ${SETTINGS}; the portal has none)"
      fi
      CREDENTIAL_FROM="the portal, for this run"
      CREDENTIAL_SOURCE="portal"
      return 0
    fi

    # A refusal here is NOT a fall-through to the prompt. The box is enrolled
    # and was told a portal; if the portal would not hand it a credential,
    # that is the finding, and asking a human to type one instead would
    # paper over exactly the thing this run is testing.
    # WO-1004-L item 1: this read as REFUSED, and the binary exits the same way
    # when the portal refuses and when it cannot be reached. A failed fetch is
    # not evidence that anybody said no, so it is said as what this box knows.
    say ""
    say "NO CREDENTIAL: enrolled, and the fetch from the portal failed."
    say "  Nothing was typed and nothing was sent to the domain."
    say "  This box cannot tell a refusal from a portal that did not answer; the"
    say "  binary's own words are on stderr above. The usual causes are a revoked"
    say "  appliance, a clock more than five minutes out, no credential saved on"
    say "  that connection yet, or no route to the portal."
    CREDENTIAL_FROM="none: the fetch from the portal failed, refused or unanswered"
    CREDENTIAL_SOURCE="portal-failed"
    CRED_FAILED=1
    CRED_REASON="the credential fetch from the portal failed, and this box cannot tell a refusal from no answer"
    return 1
  fi

  if [ -z "${CAIRN_PASSWORD:-}" ] && [ -t 0 ]; then
    printf '\n  password for %s (not echoed): ' "${PRINCIPAL:-the service account}"
    IFS= read -rs CAIRN_PASSWORD
    printf '\n'
    export CAIRN_PASSWORD
    CREDENTIAL_TYPED=1
  fi

  if [ -n "${CAIRN_PASSWORD:-}" ]; then
    CONSENT_UNHEARD="the credential came from this terminal, and only the portal fetch carries a consent list"
    say ""
    say "CREDENTIAL SOURCE: this operator's terminal, for this run only."
    say "  This is the lab path. It is honest about what it is: the credential"
    say "  is held in this process and one memory-backed ticket cache, and"
    say "  nothing writes it down -- but it passed through a human's terminal,"
    say "  which is exactly what the portal fetch exists to avoid."
    say "  **Never use this at a customer.** See LAB-BUILD.md."
    if [ "${CREDENTIAL_TYPED:-0}" -eq 1 ]; then
      CREDENTIAL_FROM="this operator's terminal, typed for this run"
      CREDENTIAL_SOURCE="terminal"
    else
      CREDENTIAL_FROM="CAIRN_PASSWORD, set in the environment of this run"
      CREDENTIAL_SOURCE="environment"
    fi
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
  CREDENTIAL_FROM="none: no source, and no terminal to ask at"
  CREDENTIAL_SOURCE="none"
  CRED_FAILED=1
  CRED_REASON="no credential source, and no terminal to ask at"
  return 1
}
capability_credential_source || true

# ---------------------------------------------------------------------------
# What this collector may read, from the portal. WO-0927-M CURRENT, C1 and C2.
#
# The list arrives on the credential fetch, as data. **An answer with no list
# collects nothing**: a consent mechanism that fails open is not a consent
# mechanism. That covers a credential typed at a terminal or set in the
# environment too -- neither carries a list, so neither can authorize a read.
# The run is then reported as could-not-start, naming why.
# ---------------------------------------------------------------------------
. "${HERE}/consent.sh"
choose_dhcp_servers "$PC_DHCP_SERVERS" "${CAIRN_DHCP_SERVERS:-}" "$CREDENTIAL_SOURCE"
say ""
say "settled for this run:"
script_line
say "realm     ${REALM:-<unset>}${REALM:+ (from ${REALM_FROM})}"
say "dc        ${DC:-<unset>}${DC:+ (from ${DC_FROM})}"
say "principal ${PRINCIPAL:-<unset>}${PRINCIPAL:+ (from ${PRINCIPAL_FROM})}"
if [ -n "$DHCP_SERVERS" ]; then
  say "dhcp      ${DHCP_SERVERS} (from ${DHCP_SERVERS_FROM})"
elif [ -n "$DHCP_REFUSAL" ]; then
  say "dhcp      none asked: ${DHCP_REFUSAL}"
else
  say "dhcp      <unset>"
fi
say ""
settle_consent

# ---------------------------------------------------------------------------
# Recording what each capability did, so the run can be reported.
#
# **Derived from the counters that already exist, not from a second tally.**
# Every capability already increments exactly one of FOUND, REFUSED and
# UNASKED, so the state is whichever one moved. A parallel set of variables
# updated at each of the twenty-five increment sites would be a second
# description of the same fact, free to drift from the first -- and the one
# that drifts is whichever is read less, which would be the one that only
# a portal card ever sees.
#
# The capability function is redirected rather than piped. A pipeline puts
# it in a subshell and the counter it increments is lost, which would leave
# every capability reported as though it did nothing.
# ---------------------------------------------------------------------------
# **The names below are STORED VALUES, not labels.** They go into the
# portal's appliance_runs rows and onto a client's connection card, so they
# are US English and plain ASCII, and the set is asserted exactly by
# preflight-stored-values-test.sh. A sixth capability fails that test until
# somebody decides what it is called -- which is the point, because a token
# cannot be respelled after the first real run without splitting the history
# into rows that disagree with each other.
#
# The same applies to every REFUSED and NOT ASKED line: the first one a
# capability prints becomes its stored reason. json_safe deletes any byte
# above 0x7f, so a typographic apostrophe there arrives as nothing at all and
# the portal stores a word with a letter missing. Plain ASCII, in those lines
# specifically, whatever the prose around them does.
CAP_JSON=""

# A reason, reduced to something that cannot break the JSON it goes into.
#
# **Characters are dropped rather than escaped**, deliberately. Escaping in
# shell is the thing this project has lost a .env secret, a test file and a
# SQL placeholder to; dropping a quote costs a reader one punctuation mark
# and cannot produce a report the portal reads as something else.
json_safe() {
  printf '%s' "$1" | tr -d '\\"' | tr -cd '[:print:]' | cut -c1-300
}

# The first line in which the capability named a refusal or a skip.
#
# **A capability that did not answer must say why**, and the portal refuses
# a report where one does not -- so a reason that cannot be found is stated
# as exactly that rather than left blank. *A check that cannot run looks
# exactly like a check that found nothing*, and this is the one place the
# difference would otherwise disappear.
first_reason() {
  local log="$1" line
  line="$(grep -m1 -E '^(REFUSED|NOT ASKED|NOT RUN|COULD NOT TELL|PARTLY):' "$log" 2>/dev/null || true)"
  if [ -z "$line" ]; then
    # WO-1004-M item 3: this told a reader of the portal to read the appliance
    # output, which nobody reading the portal can reach. A step that recorded
    # no reason is a fault in this script, and that is what is said.
    printf '%s' "preflight.sh recorded no reason for this step, which is a fault in the script and says nothing about your network"
    return 0
  fi
  printf '%s' "${line#*: }"
}

# The step a consent refuses, run in place of the one that was not permitted so
# that its state and reason are recorded exactly as any other step's are.
step_not_consented() {
  local needs
  needs="$(step_capability "$STEP_NAME")"
  if [ "$CONSENT_KNOWN" -ne 1 ]; then
    # **Not a finding about the network**, so not one of the three states.
    # The run is reported as could-not-start with no capability list, which
    # is what the portal has always received here; this is the screen saying
    # the same thing rather than ten NOT ASKED lines nobody asked.
    say "NOT RUN: ${CONSENT_UNHEARD}."
    NOTRUN=$((NOTRUN + 1))
    return 1
  elif [ "$needs" = UNMAPPED ]; then
    say "NOT ASKED: step ${STEP_NAME} maps to no consent capability, so it never runs."
  elif [ "$needs" = PREREQUISITE ]; then
    say "NOT ASKED: nothing is consented, so there is nothing to sign in for."
  else
    say "NOT ASKED: consent for ${needs} is not recorded for this organization."
  fi
  UNASKED=$((UNASKED + 1))
  return 1
}

run_capability() {
  local name="$1" fn="$2"

  # Consent first: a step it does not permit is replaced, never run.
  STEP_NAME="$name"
  if [ "$CONSENT_KNOWN" -ne 1 ] || ! step_permitted "$name" "$CONSENTED"; then
    fn=step_not_consented
  fi
  local before_found=$FOUND before_refused=$REFUSED before_unasked=$UNASKED before_notrun=$NOTRUN
  local before_empty=$EMPTY before_untold=$UNTOLD
  local log state reason status

  # A qualification on an answer, set by the capability that gave it. The
  # portal stores it as the capability's note: a note qualifies a capability
  # that answered, and a reason belongs to one that did not. WO-1001-A item 1.
  CAP_NOTE=""
  # The scope counts a DHCP read printed, as a JSON object, or empty. Counts
  # only, R20. WO-1004-M item 3.
  CAP_SCOPES=""

  log="$(mktemp)"

  # **A line before the silence, because the silence is new.**
  #
  # The capability writes to a file and the file is printed when it finishes,
  # which is what keeps the counters in this shell -- a pipeline would put the
  # function in a subshell and every capability would report as having done
  # nothing. The cost is that a slow one now prints nothing while it runs, and
  # DHCP against several servers is slow.
  #
  # A box that looks hung is a box somebody interrupts, and an interrupted run
  # reports nothing at all. One line is cheaper than that.
  say "asking... (this capability prints its output when it finishes)"

  "$fn" >"$log" 2>&1
  status=$?

  cat "$log"

  if [ "$NOTRUN" -gt "$before_notrun" ]; then
    # Our own software could not attempt this step. WO-1001-E item 3: it is
    # could-not-run, never not-asked, because not-asked is a statement about
    # what this box was told and this is a statement about this box. Where the
    # whole run could not start, the list is not sent at all.
    state="could-not-run"
    reason="$(first_reason "$log")"
  elif [ "$FOUND" -gt "$before_found" ]; then
    state="reached"
    reason=""
  elif [ "$EMPTY" -gt "$before_empty" ]; then
    # An answer with nothing in it: carries its note, like reached. WO-1004-M item 6.
    state="empty"
    reason=""
  elif [ "$REFUSED" -gt "$before_refused" ]; then
    state="refused"
    reason="$(first_reason "$log")"
  elif [ "$UNTOLD" -gt "$before_untold" ]; then
    # Never folded into refused. WO-1004-M item 1.
    state="could-not-tell"
    reason="$(first_reason "$log")"
  elif [ "$UNASKED" -gt "$before_unasked" ]; then
    state="not-asked"
    reason="$(first_reason "$log")"
  else
    # No counter moved, which is not one of the three states and is not
    # silently folded into one. It is a defect in this script and the
    # report says so rather than reporting a network fact nobody observed --
    # which is why it is could-not-run and not not-asked (WO-1001-E item 3).
    state="could-not-run"
    reason="this capability recorded no outcome; that is a fault in preflight.sh"
  fi

  rm -f "$log"

  local entry scopes_json=""
  if [ -n "$CAP_SCOPES" ]; then
    scopes_json=",\"scopes\":${CAP_SCOPES}"
  fi
  if [ -n "$reason" ]; then
    entry="{\"name\":\"${name}\",\"state\":\"${state}\",\"reason\":\"$(json_safe "$reason")\"${scopes_json}}"
  elif { [ "$state" = "reached" ] || [ "$state" = "empty" ]; } && [ -n "$CAP_NOTE" ]; then
    entry="{\"name\":\"${name}\",\"state\":\"${state}\",\"note\":\"$(json_safe "$CAP_NOTE")\"${scopes_json}}"
  else
    entry="{\"name\":\"${name}\",\"state\":\"${state}\"${scopes_json}}"
  fi

  if [ -z "$CAP_JSON" ]; then
    CAP_JSON="$entry"
  else
    CAP_JSON="${CAP_JSON},${entry}"
  fi

  return $status
}

# ---------------------------------------------------------------------------
# 1. Kerberos
# ---------------------------------------------------------------------------
# What a directory tool said, and which of the states it is. WO-1004-RS items 1
# and 3: kinit and ldapsearch print a sentence when they fail, and the sentence
# -- never the exit code -- is what says whether the domain answered. A refusal
# is something the other end said; a string this script does not recognize is,
# by definition, not something anybody was understood to say.

# The line of a tool's output that says what happened: its own error line where
# it printed one, otherwise its last line. Quoted into the reason the portal
# stores, so a reader sees the tool's words rather than being sent to read
# output nobody reading the portal can reach.
tool_said() {
  local said
  said="$(printf '%s\n' "$1" | grep -m1 -E '^(kinit|ldap_[a-z_]+|SASL[^:]*|additional info): ' || true)"
  if [ -z "$said" ]; then
    said="$(printf '%s\n' "$1" | sed '/^[[:space:]]*$/d' | tail -n 1)"
  fi
  printf '%s' "${said:-it printed nothing}"
}

# ldapsearch's answer, as one of three words:
#   refused  the directory or the KDC answered no: invalid credentials,
#            insufficient access, stronger authentication or confidentiality
#            required, unwilling to perform, or no such service principal;
#   not-run  this host has no GSSAPI SASL mechanism, so nothing was attempted;
#   untold   anything else, "Can't contact LDAP server" included: this run
#            cannot tell a refusal from no answer.
ldap_outcome() {
  case "$1" in
    *"No worthy mechs found"*|*"Unknown authentication method"*) printf 'not-run' ;;
    *"Invalid credentials (49)"*|*"Insufficient access (50)"*|*"Strong(er) authentication required (8)"*|\
    *"Confidentiality required (13)"*|*"Unwilling to perform (53)"*|*"Server not found in Kerberos database"*)
      printf 'refused' ;;
    *) printf 'untold' ;;
  esac
}

rule "1. Kerberos"
# What kinit's failure was: a refusal the domain gave, or something this run
# cannot tell from one. Sets KINIT_VERDICT to refused or untold and prints the
# verdict in Kerberos's own words. Its own function so kerberos-verdict-test.sh
# can drive it with the sentences kinit prints, without a KDC or /dev/shm.
kinit_failure() {
  # What the KDC said, rather than a list of everything it might have meant.
  #
  # kinit distinguishes these and the first version of this message did not,
  # printing "the account, the password or the clock" over an answer that had
  # already named one of the three. A refusal that lists every possible cause
  # sends somebody to check all of them, starting with whichever they thought
  # of first.
  #
  # **Only an answer the KDC gave is a refusal.** WO-1004-RS item 1: every
  # kinit failure this script did not recognize printed REFUSED -- "Cannot
  # contact any KDC" included -- so a domain controller rebooting, a wrong DNS
  # record or a firewall rule changed at lunchtime would have told a client
  # their domain controller refused us. A refusal quotes Kerberos in its own
  # words; no answer, or one this script does not recognize, is could not
  # tell, quoted the same way.
  local kinit_out="$1" said
  KINIT_VERDICT=refused
  said="$(tool_said "$kinit_out")"
  case "$kinit_out" in

    *"Password incorrect"*)
      say "REFUSED: the domain answered that the password does not match. Kerberos said: ${said}"
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
      say "REFUSED: the domain answered that the clocks disagree by more than Kerberos allows. Kerberos said: ${said}"
      say "  Five minutes is the limit. Neither the password nor the account is"
      say "  implicated: this request never got as far as being judged."
      say "  Compare 'timedatectl status' here with the clock on ${DC}."
      ;;

    *"not found in Kerberos database"*|*"Client not found"*)
      say "REFUSED: the domain answered that it has no such principal as ${PRINCIPAL}. Kerberos said: ${said}"
      say "  The realm answered, so this is the NAME rather than the domain."
      say "  Check CAIRN_PRINCIPAL against the account's userPrincipalName, and"
      say "  remember the part after the @ is the realm and is case-sensitive."
      ;;

    *"Password has expired"*|*"password has expired"*)
      say "REFUSED: the domain answered that the password has expired. Kerberos said: ${said}"
      say "  The password is correct and the domain will not issue on it."
      say "  It has expired. A service account for this should be set not to"
      say "  expire -- see LAB-BUILD.md section 2 -- which is a change to the"
      say "  account rather than anything on this appliance."
      ;;

    *"credentials have been revoked"*)
      say "REFUSED: the domain answered that this account is disabled or locked out. Kerberos said: ${said}"
      say "  An administrator enables or unlocks it in the customer's directory."
      ;;

    *"Cannot contact any KDC"*|*"Cannot find KDC"*|*"Cannot resolve network address"*|*"Resource temporarily unavailable"*)
      # **Could not tell, not not run.** Nothing answered: the domain said
      # nothing about this account, so it is not a refusal, and the path to a
      # domain controller is the network's -- a controller rebooting, a DNS
      # record, a firewall -- not a fault in this box's software, which is what
      # NOT RUN means.
      KINIT_VERDICT=untold
      say "COULD NOT TELL: no domain controller answered, so this run cannot tell whether the domain would accept this account. Kerberos said: ${said}"
      say "  Check that ${DC:-the domain controller} is up and reachable from this box, and"
      say "  that its name resolves here. Nothing about the account is implied."
      ;;

    *)
      KINIT_VERDICT=untold
      say "COULD NOT TELL: kinit failed with a message this script does not recognize, so it is not called a refusal. Kerberos said: ${said}"
      say "  Its whole output is above. Kerberos refuses a request more than five"
      say "  minutes out from the KDC, and that error does not always say so in"
      say "  those words."
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
}

capability_kerberos() {
  if [ -z "$PRINCIPAL" ] || [ -z "$REALM" ]; then
    say "NOT ASKED: CAIRN_PRINCIPAL or CAIRN_REALM is unset in ${SETTINGS}."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  if [ -z "${CAIRN_PASSWORD:-}" ]; then
    say "NOT ASKED: no credential was available for this run; see step 0."
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

  # The prompt label goes; everything kinit said stays. See KINIT_PROMPT_STRIP.
  kinit_out="$(printf '%s' "$kinit_out" | sed "$KINIT_PROMPT_STRIP")"

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
        say "ANSWERED: a ticket was issued for ${PRINCIPAL} and is readable."
        say "  cache: ${KRB5CCNAME}"
        say "  in RAM (tmpfs), private to root, removed when this script ends."
        printf '%s\n' "$tickets" | sed 's/^/  /'
        # WO-1004-L item 4: klist prints its times with no zone, in this box's.
        say "  klist's times are this box's local time, $(date '+%Z, UTC%z'), and these tickets were issued in this run."
        FOUND=$((FOUND + 1))
        return 0
        ;;
    esac

    # WO-1004-M item 2: this printed REFUSED over a sentence saying it was not
    # a refusal by the domain. The domain accepted the request; the ticket did
    # not reach a cache this box can use, which is a fault on this box, and that
    # is NOT RUN -- could-not-run in the report -- never a refusal.
    say "NOT RUN: kinit reported success and the cache holds no usable ticket; that is a fault on this box, not a refusal by the domain."
    say "  The domain accepted the request."
    say "  What klist says about ${KRB5CCNAME}:"
    printf '%s\n' "$tickets" | sed 's/^/  /'
    NOTRUN=$((NOTRUN + 1))
    return 1
  fi

  kinit_failure "$kinit_out"

  if [ "$KINIT_VERDICT" = untold ]; then
    UNTOLD=$((UNTOLD + 1))
  else
    REFUSED=$((REFUSED + 1))
  fi
  return 1
}
# **The status is captured in the branch that runs on failure.** This read
# `run_capability kerberos ... || true` and then `KERBEROS_OK=$?`, which is
# the status of `true` -- always 0 -- so the DHCP step never saw a failed
# sign-in and would report whatever it got as though authentication had
# worked. kerberos-gate-test.sh drives these lines as written.
KERBEROS_OK=0
run_capability kerberos capability_kerberos || KERBEROS_OK=$?

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
  #
  # The attribute is one the domain object carries. Until WO-0930-F this asked
  # the domain head for dnsHostName, which lives on computer objects and on the
  # rootDSE, not on the domain -- so a good bind came back as a bare "dn:" line
  # and "answered" rested on the exit code alone. objectClass is on every
  # object, and domainDNS is the class of a domain head, so seeing it is seeing
  # the domain object read under this bind.
  local out
  out="$(ldapsearch -LLL -Y GSSAPI -H "ldap://${DC}" -b "$BASE_DN" -s base objectClass 2>&1)"
  local status=$?

  printf '%s\n' "$out" | sed 's/^/  /'

  if [ $status -eq 0 ] && printf '%s\n' "$out" | grep -qi '^objectClass: domainDNS$'; then
    say "ANSWERED: the directory answered a bound read of the domain object."
    FOUND=$((FOUND + 1))
    return 0
  fi

  # WO-1004-RS item 3: both of these printed REFUSED, the first for a read
  # that completed and the second for any failure, "Can't contact LDAP server"
  # included. A read that completed and returned something else is not the
  # directory saying no; a failure is a refusal only where ldapsearch says the
  # directory or the KDC answered no.
  if [ $status -eq 0 ]; then
    say "COULD NOT TELL: the read completed and did not return the domain object's class,"
    say "  so this is not evidence the bind can read the domain, and not a refusal"
    say "  either. The text above is what came back."
    UNTOLD=$((UNTOLD + 1))
    return 1
  fi

  local said verdict
  said="$(tool_said "$out")"
  verdict="$(ldap_outcome "$out")"
  case "$verdict" in
    refused) say "REFUSED: the directory answered no to the bind or the read. ldapsearch said: ${said}" ;;
    not-run) say "NOT RUN: this host has no GSSAPI SASL mechanism, so the bind was never attempted. ldapsearch said: ${said}" ;;
    *) say "COULD NOT TELL: the bind or the read did not complete, and this run cannot tell a refusal from no answer. ldapsearch said: ${said}" ;;
  esac

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

  case "$verdict" in
    refused) REFUSED=$((REFUSED + 1)) ;;
    not-run) NOTRUN=$((NOTRUN + 1)) ;;
    *) UNTOLD=$((UNTOLD + 1)) ;;
  esac
  return 1
}
# **The status is captured in the branch that runs on failure**, the way the
# Kerberos gate above has been since it was found broken: this read `|| true`
# and then `LDAP_OK=$?`, which is the status of `true` -- always 0 -- so the
# DNS-zone and authorized-server steps ran after a failed directory read as
# though it had answered. Found by the WO-1004-RS item 3 sweep; latent, because
# Active Directory is allowed nowhere and consent replaces all three steps.
LDAP_OK=0
run_capability ldap capability_ldap || LDAP_OK=$?

# ---------------------------------------------------------------------------
# 3. DNS held in the directory
#
# Directory-integrated DNS can live in three places, and a zone may be in any
# of them: CN=MicrosoftDNS in the DomainDnsZones partition, the same in the
# ForestDnsZones partition (under the forest root, which is not always this
# domain), and CN=MicrosoftDNS,CN=System in the domain partition, where zones
# made before the application partitions existed still sit. WO-0930-F item 5.
#
# Until then this read DomainDnsZones alone and took ANY non-zero exit as "no
# directory-integrated DNS" -- so a refused read, a timeout and a zone kept in
# the forest partition all came back as the same plausible answer. Now only
# ldapsearch's 32, "No such object", means a container is absent; every other
# failure is a read that did not happen, and says so. A domain whose DNS is not
# directory-integrated has none of the three, and that is still reported as a
# fact about the site rather than a failure.
# ---------------------------------------------------------------------------
rule "3. DNS zones in the directory"
capability_dns() {
  if [ "$LDAP_OK" -ne 0 ]; then
    say "NOT ASKED: the directory did not answer, so this cannot be asked separately."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  # The forest root, from the rootDSE, because ForestDnsZones hangs off it and
  # a child domain's own DN is not it. If it cannot be read, that container is
  # a read that could not be asked, not one that is absent.
  local root_out forest_dn
  root_out="$(ldapsearch -LLL -Y GSSAPI -H "ldap://${DC}" -b "" -s base rootDomainNamingContext 2>&1)"
  local root_status=$?
  forest_dn="$(printf '%s\n' "$root_out" | sed -n 's/^rootDomainNamingContext: //p')"

  local containers=(
    "CN=MicrosoftDNS,DC=DomainDnsZones,${BASE_DN}"
    "CN=MicrosoftDNS,CN=System,${BASE_DN}"
  )
  local unasked_forest=0
  if [ $root_status -eq 0 ] && [ -n "$forest_dn" ]; then
    containers+=("CN=MicrosoftDNS,DC=ForestDnsZones,${forest_dn}")
  else
    unasked_forest=1
  fi

  local zones="" present=0 absent=0 could_not=0 refused_at=0 notrun_at=0 container out status said=""
  # Each verdict quotes a place that gave that verdict: the first failure's words
  # under REFUSED would put "Can't contact LDAP server" beside a refusal.
  local refused_said="" notrun_said="" outcome
  for container in "${containers[@]}"; do
    say "looking under: ${container}"
    out="$(ldapsearch -LLL -Y GSSAPI -H "ldap://${DC}" -b "$container" \
            -s one '(objectClass=dnsZone)' dc 2>&1)"
    status=$?
    case $status in
      0)
        present=$((present + 1))
        zones="$(printf '%s\n%s\n' "$zones" "$(printf '%s\n' "$out" | sed -n 's/^dc: //p')")"
        ;;
      32)
        absent=$((absent + 1))
        say "  not present: this container does not exist here."
        ;;
      *)
        could_not=$((could_not + 1))
        printf '%s\n' "$out" | sed 's/^/  /'
        say "  COULD NOT BE ASKED: ldapsearch exited ${status}, which is not \"no such object\"."
        outcome="$(ldap_outcome "$out")"
        case "$outcome" in
          refused)
            refused_at=$((refused_at + 1))
            [ -z "$refused_said" ] && refused_said="$(tool_said "$out")"
            ;;
          not-run)
            notrun_at=$((notrun_at + 1))
            [ -z "$notrun_said" ] && notrun_said="$(tool_said "$out")"
            ;;
        esac
        [ -z "$said" ] && said="$(tool_said "$out")"
        ;;
    esac
  done
  if [ $unasked_forest -eq 1 ]; then
    could_not=$((could_not + 1))
    printf '%s\n' "$root_out" | sed 's/^/  /'
    say "  COULD NOT BE ASKED: the forest root was not readable from the rootDSE,"
    say "  so the ForestDnsZones partition was not looked in."
  fi

  # Counted and listed, never compared against an expectation.
  zones="$(printf '%s\n' "$zones" | sed '/^$/d' | sort -u)"
  local count
  count="$(printf '%s\n' "$zones" | grep -c . || true)"

  # WO-1004-RS item 3: this printed REFUSED for any place that could not be
  # read. It is a refusal only where the directory answered no for at least one
  # of them; a missing GSSAPI mechanism is this host; anything else is could not
  # tell. The forest root that could not be read from the rootDSE is counted in
  # could_not and is neither.
  if [ $could_not -gt 0 ]; then
    if [ $refused_at -gt 0 ]; then
      say "REFUSED: the directory answered no for ${refused_at} of the place(s) DNS zones can be kept. ldapsearch said: ${refused_said}"
    elif [ $notrun_at -gt 0 ]; then
      say "NOT RUN: this host has no GSSAPI SASL mechanism, so ${notrun_at} place(s) DNS zones can be kept were not asked. ldapsearch said: ${notrun_said}"
    else
      say "COULD NOT TELL: ${could_not} place(s) DNS zones can be kept could not be read, and this run cannot tell a refusal from no answer. ldapsearch said: ${said:-the forest root was not readable from the rootDSE}"
    fi
    say "  What follows is not the whole list: ${count} zone(s) read from ${present}."
    [ "$count" -gt 0 ] && printf '%s\n' "$zones" | sed 's/^/  /'
    if [ $refused_at -gt 0 ]; then
      REFUSED=$((REFUSED + 1))
    elif [ $notrun_at -gt 0 ]; then
      NOTRUN=$((NOTRUN + 1))
    else
      UNTOLD=$((UNTOLD + 1))
    fi
    return 1
  fi

  if [ $present -eq 0 ]; then
    say "NOT PRESENT: none of the ${absent} places directory-integrated DNS is kept exists here."
    say "  This is a normal state at a site whose DNS is not AD-integrated."
    say "  It is reported rather than treated as a failure."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  say "ANSWERED: ${count} zone(s) readable in the directory, from ${present} of ${#containers[@]} place(s)."
  printf '%s\n' "$zones" | sed 's/^/  /'
  say "  What is correct for this site is not something preflight can know."
  FOUND=$((FOUND + 1))
  return 0
}
run_capability dns-zones capability_dns || true

# ---------------------------------------------------------------------------
# 4. The authorized DHCP servers, from the directory
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
rule "4. Authorized DHCP servers, from the directory"
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

  # WO-1004-RS item 3: this printed REFUSED for any failure. It is a refusal
  # only where the directory answered no.
  if [ $status -ne 0 ]; then
    printf '%s\n' "$out" | sed 's/^/  /'
    local said verdict
    said="$(tool_said "$out")"
    verdict="$(ldap_outcome "$out")"
    case "$verdict" in
      refused)
        say "REFUSED: the directory answered no to reading the authorized-server list. ldapsearch said: ${said}"
        say "  This needs only an authenticated user, so a refusal here is a"
        say "  different fact from the DHCP interface refusing below."
        REFUSED=$((REFUSED + 1))
        ;;
      not-run)
        say "NOT RUN: this host has no GSSAPI SASL mechanism, so the list was never asked for. ldapsearch said: ${said}"
        NOTRUN=$((NOTRUN + 1))
        ;;
      *)
        say "COULD NOT TELL: the authorized-server list could not be read, and this run cannot tell a refusal from no answer. ldapsearch said: ${said}"
        UNTOLD=$((UNTOLD + 1))
        ;;
    esac
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
  # which is the authorized list rather than the container -- so this is a
  # hazard for the appliance census only, and it is separated here at the read
  # rather than left for the receiver to filter.
  local entries servers
  entries="$(printf '%s\n' "$out" | grep -c '^dn:' || true)"
  servers="$(printf '%s\n' "$out" | grep -c '^dhcpServers:' || true)"
  say "ANSWERED: ${entries} entr(ies) under the container, ${servers} carrying a"
  say "  dhcpServers attribute."
  printf '%s\n' "$out" | sed 's/^/  /' | head -40
  say ""
  say "  AN ENTRY IS NOT A SERVER. CN=DhcpRoot is a container Microsoft creates"
  say "  in every domain; it matches this filter and carries no dhcpServers"
  say "  attribute. Only the ${servers} above are authorized servers. An entry"
  say "  with no such attribute is NOT-A-SERVER, which is a different state from"
  say "  a server whose name does not resolve, and only the second is a finding."
  say ""
  say "  The authorized list is what the directory says; whether each of those"
  say "  servers still exists is a separate question this does not ask."
  FOUND=$((FOUND + 1))
  return 0
}
run_capability dhcp-authorized capability_authorized_servers || true

# ---------------------------------------------------------------------------
# 5. DHCP over MS-DHCPM
#
# The only capability here that is not a shell tool. It is a small Go program
# using go-msrpc, calling R_DhcpEnumSubnets and R_DhcpEnumSubnetClientsV5 --
# both reads, and the pair the collector itself would use.
# ---------------------------------------------------------------------------
# **The digest of what a submission sent, kept on the box.** WO-1001-C item 3.
#
# The portal stores a SHA-256 of each submission body as it arrived and never
# the body: R20 keeps lease lists on district equipment, and a portal holding
# raw bodies to audit itself would hold the thing it promised not to. So the
# evidence that what arrived is what was sent is two digests compared, and the
# box's half has to survive until somebody reads it. A run's screen does not --
# a hand run prints to a terminal, and a timed run to a journal whose retention
# this script does not set -- so the binary's digest line is appended here,
# with the time and the server, to a file of its own. Nothing in this
# repository configures rotation for it; whether the box's own logrotate
# configuration reaches /var/log/cairn-appliance has not been read from the
# box, and it is the first thing to check if this file is ever found short.
SUBMISSIONS_LOG="${SUBMISSIONS_LOG:-/var/log/cairn-appliance/submissions.log}"
keep_submission_digest() {
  local server="$1" output="$2" line
  if ! line="$(grep -m 1 'body SHA-256' "$output")"; then
    say "  SUBMISSION DIGEST NOT KEPT: the binary printed none for ${server}."
    return 0
  fi
  if mkdir -p "$(dirname "$SUBMISSIONS_LOG")" && printf '%s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$server" "$line" >>"$SUBMISSIONS_LOG"; then
    say "  kept: ${line}, in ${SUBMISSIONS_LOG}"
  else
    say "  SUBMISSION DIGEST NOT KEPT: ${SUBMISSIONS_LOG} could not be written."
  fi
}

rule "5. DHCP over MS-DHCPM"
capability_dhcp() {
  if [ "$KERBEROS_OK" -ne 0 ]; then
    say "NOT ASKED: there is no ticket."
    UNASKED=$((UNASKED + 1))
    return 1
  fi
  if [ -n "$DHCP_REFUSAL" ]; then
    say "NOT ASKED: ${DHCP_REFUSAL}"
    UNASKED=$((UNASKED + 1))
    return 1
  fi
  if [ -z "$DHCP_SERVERS" ]; then
    say "NOT ASKED: no DHCP server is named, in the portal or in ${SETTINGS}."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  local binary="${HERE}/preflight/preflight"

  # ---------------------------------------------------------------------
  # THIS SECTION NO LONGER BUILDS ANYTHING. It reads the binary it is about
  # to run and says which one it is.
  #
  # ## What it did, and why that was a finding rather than a feature
  #
  # Until 24 September 2026 this ran `go build` on every invocation. Under
  # the timer that meant **the appliance rebuilt and replaced its own
  # executable, unattended, on a schedule** -- the run at 05:44 that morning
  # produced a binary stamped 09d3eec where the day before it had been
  # adde78f. Nobody authorised a self-modifying collector, and every claim
  # anybody had made about which commit was running on that box was void
  # from the moment the timer fired.
  #
  # ## Removing it removes no check, and that is the argument
  #
  # The build was justified by a digest pin: the appliance would decline a
  # binary whose fingerprint disagreed with one the portal supplied. **There
  # is no such pin.** Nothing compares these bytes with anything, here or in
  # the portal, so the section compared the digest against NOTHING. What is
  # lost by not building is the certainty that the binary matches the tree,
  # and that certainty was bought by the thing that made the box
  # unpredictable.
  #
  # ## What replaces it
  #
  # The stamp is still READ, because it is the one question the binary can
  # answer about itself with certainty and it costs nothing. What changed is
  # that it is now a reading of what is installed rather than a read-back of
  # something this script just wrote -- which is the honest version of the
  # same line.
  #
  # ## A missing binary is COULD NOT RUN, never NOT ASKED or REFUSED
  #
  # `refused` means the domain was asked and said no; `not asked` means it
  # was never asked, for a reason about what this host was told. A binary
  # that is not installed is neither: it is a fault in our own software.
  # Until WO-1001-D it was routed to `not-asked`, which put our fault in the
  # customer's column; the order author's ruling of 1 October 2026
  # (WO-1001-E item 3) is that **a capability is never recorded as not asked
  # because of a failure in our own software**, and the word for it is the
  # one the run level already uses, one level down: `could-not-run`.
  # ---------------------------------------------------------------------
  if [ ! -x "$binary" ]; then
    say "NOT RUN: there is no DHCP probe at ${binary}; that is a fault in this installation, not in the network."
    say ""
    say "  This script no longer builds one. Nothing was asked of any DHCP"
    say "  server, and nothing about the domain, the account or the"
    say "  credential is implicated. Install the published binary by"
    say "  INSTALL-STEPS.md step 2b."
    NOTRUN=$((NOTRUN + 1))
    return 1
  fi

  # READ THE STAMP, and say plainly when there is not one.
  #
  # **This is a reading now rather than a read-back.** It used to prove that
  # a linker flag written seconds earlier had taken; it now says which commit
  # produced the bytes about to run, which is what a person reading a report
  # needs either way.
  #
  # An unstamped binary is not asked for the same reason a missing one is:
  # a probe that cannot say which commit built it cannot be matched to a
  # review, a report or a change somebody made, and running it anyway would
  # produce a finding nobody could trace.
  local reported
  reported="$("$binary" -version 2>&1)"

  case "$reported" in
    *unstamped*)
      say "NOT RUN: the installed probe carries no commit stamp; that is a fault in this installation, not in the network."
      say "  ${binary} -version says: ${reported}"
      say ""
      say "  A binary that cannot say which commit built it cannot be matched"
      say "  to a review, a report or a change somebody made. Install the"
      say "  published binary by INSTALL-STEPS.md step 2b."
      NOTRUN=$((NOTRUN + 1))
      return 1
      ;;
  esac

  # One line, not two. This printed `built:` twice in a row -- once with the
  # stamp and once with the file’s timestamp -- which reads as one fact
  # stated twice with different values rather than as two facts.
  #
  # WO-1004-L item 4: the time is when the file at this path was last
  # written -- an install, not this run -- and it printed with no zone beside
  # the ticket's, so the run read as having two clocks. Both are said now.
  #
  # WO-1004-P item 4b, kept as the example: on the next run the same field
  # read 18 seconds before the ticket, because the binary had just been
  # reinstalled. Five hours off one day and right to the second the next, for
  # a reason unconnected to what it seems to measure. A value that happens to
  # look correct is the hardest kind to find; the label is what makes it
  # readable either way.
  say "  probe: ${reported}"
  say "    file last written $(date -r "$binary" '+%Y-%m-%d %H:%M:%S %Z (UTC%z)' 2>/dev/null || echo '(not readable)'): the file's own modification time, not this run's"

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

  # **Submit, or say plainly that nothing was submitted.** WO-1001-A item 1.
  #
  # Until 1 October 2026 this step called the binary with -server alone: the
  # PROBE, which reads every scope and prints what it found on this box and
  # sends the portal nothing. -collect-dhcp, the mode that submits, was called
  # from nowhere -- so a box reported DHCP as reached every night and no
  # reading could ever have arrived, whatever binary it ran. Every other
  # reader was called in its collect mode; this one was the odd one out, and
  # its output looked exactly like work.
  #
  # **Submitting is held behind CAIRN_DHCP_SUBMIT=yes in settings.env**, set on
  # RVA's own appliance only, by the staging the order author set: the first
  # submission is from our own box, what crossed the boundary is read field by
  # field, and no client box submits until that has been read and said. A box
  # without it stays on the probe, and its run report says so in the note, so
  # a probe can no longer read as a delivery.
  local submit=0
  local -a mode_args=(-server)
  if [ "${CAIRN_DHCP_SUBMIT:-}" = "yes" ]; then
    if [ -z "${CAIRN_PORTAL:-}" ]; then
      say "NOT ASKED: CAIRN_DHCP_SUBMIT is yes, and no portal is named to submit to."
      UNASKED=$((UNASKED + 1))
      return 1
    fi
    submit=1
    mode_args=(-portal "${CAIRN_PORTAL}" -collect-dhcp -server)
  fi
  local submitted=0 asked=0 empty=0 answered=0 refused=0 untold=0
  # "1 of 1 DHCP server", "1 of 2 DHCP servers": the noun follows the number it counts.
  local noun
  local scopes_seen=0 scopes_attempted=0 scopes_unreadable=0 scopes_empty=0

  # One read of one server: its output shown exactly as before, and what the
  # server's answer WAS, set in DHCP_READ -- one of four, WO-1004-L item 1:
  #
  #   answered        the binary finished and sent what it read, if asked to;
  #   empty           every scope it attempted was read to the end and held no
  #                   lease, or it serves none -- nothing to send, and a read;
  #   refused         the server answered ERROR_ACCESS_DENIED;
  #   could-not-tell  anything else. This run cannot tell a refusal from a
  #                   server that did not answer, and says so rather than
  #                   choosing -- and, WO-1004-M item 1, counts it as that, never
  #                   with the refusals. A refusal is something the other end
  #                   said; this is something about us.
  #
  # **An empty scope is not a refusal.** In collect mode the binary exits
  # non-zero when it found no lease to send, and that exit used to be read as
  # the server saying no -- so the first reading from a real domain controller
  # reported a refusal for a scope that was simply empty. The binary prints its
  # own counts on two fixed lines, and those are read here: every scope
  # attempted, none unreadable, every one empty, and no device or unreadable
  # lease. Read from this script's own binary, whose format is ours, and when
  # the lines are not there the read is could-not-tell, never empty and never
  # refused. A server that serves no scopes at all exits 0 and says so in its
  # own sentence, which is an empty answer too, not one with leases in it.
  #
  # **The scope counts are kept, and only the counts.** WO-1004-M item 3: they
  # are what lets the portal say what a read found, and R20 allows counts and
  # nothing that names a scope. The "scopes:" line is the binary's; the lines
  # under it name scopes, and are never read into anything that leaves.
  #
  # The digest is kept only when the binary printed one. Its absence after a
  # read that sent nothing is not a problem and is said as what it is.
  DHCP_READ=""
  dhcp_read() {
    local output status=0 scopes devices
    output="$(mktemp)"
    CAIRN_PRINCIPAL="$PRINCIPAL" "$binary" "${mode_args[@]}" "$1" "${probe_args[@]}" >"$output" 2>&1 || status=$?
    sed 's/^/  /' "$output"
    scopes="$(grep -m 1 '^scopes: ' "$output")"
    devices="$(grep -m 1 '^devices: ' "$output")"
    if [[ "$scopes" =~ ^scopes:\ ([0-9]+)\ attempted,\ ([0-9]+)\ could\ not\ be\ read\ completely,\ ([0-9]+)\ empty$ ]]; then
      scopes_seen=1
      scopes_attempted=$((scopes_attempted + BASH_REMATCH[1]))
      scopes_unreadable=$((scopes_unreadable + BASH_REMATCH[2]))
      scopes_empty=$((scopes_empty + BASH_REMATCH[3]))
    fi
    if [ "$status" -eq 0 ] && grep -q '^the server answered and serves no scopes' "$output"; then
      scopes_seen=1
      DHCP_READ="empty"
    elif [ "$status" -eq 0 ]; then
      DHCP_READ="answered"
    elif [[ "$scopes" =~ ^scopes:\ ([1-9][0-9]*)\ attempted,\ 0\ could\ not\ be\ read\ completely,\ ([0-9]+)\ empty$ ]] \
         && [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ] \
         && [ "$devices" = "devices: 0, from leases whose hardware address could be read; 0 refused as unreadable" ]; then
      DHCP_READ="empty"
    elif grep -q 'ERROR_ACCESS_DENIED' "$output"; then
      DHCP_READ="refused"
    else
      DHCP_READ="could-not-tell"
    fi
    if [ "$submit" -eq 1 ]; then
      if grep -q 'body SHA-256' "$output" || [ "$DHCP_READ" = "answered" ]; then
        keep_submission_digest "$1" "$output"
      else
        say "  nothing was submitted from ${1}, so there is no submission digest to keep."
      fi
    fi
    rm -f "$output"
    return "$status"
  }

  local IFS=,
  for server in $DHCP_SERVERS; do
    server="$(printf '%s' "$server" | tr -d ' ')"
    [ -z "$server" ] && continue
    asked=$((asked + 1))

    say ""
    if [ "$submit" -eq 1 ]; then
      say "reading ${server} and submitting to the portal:"
    else
      say "asking ${server} (the probe: printed here, nothing is submitted):"
    fi
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
    dhcp_read "$server" || true
    case "$DHCP_READ" in
      answered)
        answered=$((answered + 1))
        if [ "$submit" -eq 1 ]; then
          submitted=$((submitted + 1))
        fi
        ;;
      empty)
        # A successful read that found nothing to send. Kept out of the refusal
        # count: it is evidence that nobody holds a lease on this server today,
        # and about nothing else.
        empty=$((empty + 1))
        say "  this server answered: every scope it serves was read and is empty. That is a read, not a refusal."
        ;;
      refused)
        # ERROR_ACCESS_DENIED from R_DhcpEnumSubnets is the server ANSWERING: the
        # mapper resolved, the interface bound, Kerberos authenticated and the
        # call was dispatched. Calling that silence would report a working DHCP
        # service as unreachable and send somebody to look at the network.
        refused=$((refused + 1))
        say "  this server refused (ERROR_ACCESS_DENIED). The others are still being asked."
        ;;
      *)
        untold=$((untold + 1))
        say "  this server did not complete the read, in the binary's words above. This run cannot tell a"
        say "  refusal from a server that did not answer, and counts it as that: could not tell."
        ;;
    esac
  done

  if [ "$asked" -eq 1 ]; then noun="DHCP server"; else noun="DHCP servers"; fi

  # The scope counts, summed over the servers that printed them, for the run
  # report. Counts only: R20.
  CAP_SCOPES=""
  if [ "$scopes_seen" -eq 1 ]; then
    CAP_SCOPES="$(printf '{"attempted":%d,"unreadable":%d,"empty":%d}' "$scopes_attempted" "$scopes_unreadable" "$scopes_empty")"
  fi

  # What the other servers said, beside the answer the capability reports.
  local others=""
  [ "$empty" -gt 0 ] && [ "$answered" -gt 0 ] && others="${others}; ${empty} answered with every scope empty, so nothing was sent from them"
  [ "$refused" -gt 0 ] && others="${others}; ${refused} refused (ERROR_ACCESS_DENIED)"
  [ "$untold" -gt 0 ] && others="${others}; ${untold} could not be told apart from a server that did not answer"

  if [ "$submit" -eq 1 ]; then
    CAP_NOTE="submitted to the portal from ${submitted} of ${asked} ${noun}${others}"
  else
    CAP_NOTE="probed on this box only; nothing was submitted, because CAIRN_DHCP_SUBMIT is not yes${others}"
    say ""
    say "NOT SUBMITTED: this box is held on the probe. What was read above stays on this box."
  fi

  # The capability's own answer, from the servers' answers: one that answered
  # with data, then one that answered empty, then a refusal, then could not
  # tell. Each prints the line the run report stores, and none names a server:
  # the portal named them, and a host name going up is an identifier it does
  # not need. WO-1004-M items 1 and 3.
  if [ "$answered" -gt 0 ]; then
    FOUND=$((FOUND + 1))
    return 0
  fi
  if [ "$empty" -gt 0 ]; then
    say ""
    say "EMPTY: ${empty} of ${asked} ${noun} answered with every scope read and empty, so nothing was sent. That is a read, not a refusal."
    if [ "$submit" -eq 1 ]; then
      CAP_NOTE="${empty} of ${asked} ${noun} answered with every scope read and empty, so nothing was sent${others}"
    fi
    EMPTY=$((EMPTY + 1))
    return 0
  fi
  if [ "$refused" -gt 0 ]; then
    local untold_note=""
    [ "$untold" -gt 0 ] && untold_note=" ${untold} more could not be told apart from a server that did not answer."
    say ""
    say "REFUSED: ${refused} of ${asked} ${noun} answered ERROR_ACCESS_DENIED to the account reading them.${untold_note}"
    REFUSED=$((REFUSED + 1))
    return 1
  fi
  say ""
  say "COULD NOT TELL: ${untold} of ${asked} ${noun} did not complete the read, and this run cannot tell a refusal from a server that did not answer."
  UNTOLD=$((UNTOLD + 1))
  return 1
}
run_capability dhcp capability_dhcp || true

# A reader's answer, from what the binary SAID rather than its exit status.
# WO-1004-M item 2: a refusal is something the other end said; an exit code is
# something our process did. Zabbix, vSphere, Configuration Manager and
# Proxmox VE all exit 1 for an empty list, a refusal and a failure alike, and
# all four printed REFUSED for every one of them.
#
# Read from this repository's own binary, whose sentences are ours:
#
#   exit 0                      answered
#   exit 3                      not asked: nothing was asked of anybody
#   "... listed no ..., so nothing was sent"
#                               empty: it answered, and there was nothing to send
#   "... refused ..."           refused: the other end said no, in its words
#   anything else               could not tell: a failure this run cannot tell
#                               from a refusal, said as that
#
# The binary's own last line is the stored reason, without its prefix, so a
# reader of the portal sees what happened rather than being sent to read
# output nobody can reach (WO-1004-M item 3).
#
# $1 the binary, $2 its collect flag, $3 who was asked ("the Zabbix server"),
# $4 what an answer lists ("hosts").
read_reader() {
  local binary="$1" flag="$2" who="$3" what="$4" output status=0 said
  output="$(mktemp)"
  "$binary" -portal "${CAIRN_PORTAL}" "$flag" >"$output" 2>&1 || status=$?
  cat "$output"
  said="$(grep '^preflight: ' "$output" | tail -n 1)"
  said="${said#preflight: }"
  rm -f "$output"
  if [ "$status" -eq 0 ]; then
    FOUND=$((FOUND + 1))
    return 0
  fi
  if [ "$status" -eq 3 ]; then
    say "NOT ASKED: the binary asked ${who} nothing; ${said:-it gave no reason}"
    UNASKED=$((UNASKED + 1))
    return 1
  fi
  case "$said" in
    *"listed no "*", so nothing was sent")
      say "EMPTY: ${who} answered and listed no ${what}, so nothing was sent. That is a read, not a refusal."
      CAP_NOTE="$said"
      EMPTY=$((EMPTY + 1))
      return 0
      ;;
    *" refused "*)
      say "REFUSED: ${said}"
      REFUSED=$((REFUSED + 1))
      return 1
      ;;
    *)
      say "COULD NOT TELL: ${who} did not answer with ${what}, and this run cannot tell a refusal from no answer: ${said:-the binary gave no reason}"
      UNTOLD=$((UNTOLD + 1))
      return 1
      ;;
  esac
}

# ---------------------------------------------------------------------------
# Zabbix: the hosts of an existing Zabbix server, WO-0928-F item 5a.
#
# The binary fetches the Zabbix address and token from the portal itself, on a
# signed request, and holds them in memory for one host.get -- they never pass
# through this shell. It needs no Kerberos ticket and reads no directory data.
#
# Exit 0 is found and 3 is NOT ASKED (Zabbix not granted, no server named, or
# the credential could not be fetched -- none of them the Zabbix server saying
# anything). Anything else is read from what the binary said: see read_reader.
capability_zabbix() {
  local binary="${HERE}/preflight/preflight"
  if [ ! -x "$binary" ]; then
    say "NOT RUN: there is no preflight binary at ${binary}; that is a fault in this installation, not in the network."
    NOTRUN=$((NOTRUN + 1))
    return 1
  fi
  if [ -z "${CAIRN_PORTAL:-}" ]; then
    say "NOT ASKED: no portal is named, so there is no Zabbix server to be told about."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  read_reader "$binary" -collect-zabbix "the Zabbix server" "hosts"
}
run_capability zabbix capability_zabbix || true

# ---------------------------------------------------------------------------
# vSphere: the virtual machines an existing vCenter lists. WO-0929-A item 9.
# The binary fetches the vCenter address and account itself, opens one
# session, reads the list, ends the session and submits five fields per
# machine. Exit 3 is NOT ASKED -- not granted, or no vCenter named.
capability_vsphere() {
  local binary="${HERE}/preflight/preflight"
  if [ ! -x "$binary" ]; then
    say "NOT RUN: there is no preflight binary at ${binary}; that is a fault in this installation, not in the network."
    NOTRUN=$((NOTRUN + 1))
    return 1
  fi
  if [ -z "${CAIRN_PORTAL:-}" ]; then
    say "NOT ASKED: no portal is named, so there is no vCenter to be told about."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  read_reader "$binary" -collect-vsphere "vCenter" "virtual machines"
}
run_capability vsphere capability_vsphere || true

# ---------------------------------------------------------------------------
# Configuration Manager: the systems a site has discovered. WO-0929-B item 8.
# The binary fetches the administration service address and its certificate
# fingerprint itself, presents the Kerberos ticket this script already holds,
# reads the system list and submits five fields per system. It trusts the one
# pinned certificate and returns redirects. Exit 3 is NOT ASKED.
capability_mecm() {
  local binary="${HERE}/preflight/preflight"
  if [ ! -x "$binary" ]; then
    say "NOT RUN: there is no preflight binary at ${binary}; that is a fault in this installation, not in the network."
    NOTRUN=$((NOTRUN + 1))
    return 1
  fi
  if [ -z "${CAIRN_PORTAL:-}" ]; then
    say "NOT ASKED: no portal is named, so there is no site to be told about."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  read_reader "$binary" -collect-mecm "the Configuration Manager site" "systems"
}
run_capability mecm capability_mecm || true

# ---------------------------------------------------------------------------
# Proxmox VE: the guests a cluster lists. WO-0929-C item 6. The binary fetches
# the address, the API token and the certificate fingerprint itself, reads the
# resource list once with the token on the request, and submits six fields per
# guest. It opens no session, trusts the one pinned certificate and returns
# redirects. Exit 3 is NOT ASKED.
capability_proxmox() {
  local binary="${HERE}/preflight/preflight"
  if [ ! -x "$binary" ]; then
    say "NOT RUN: there is no preflight binary at ${binary}; that is a fault in this installation, not in the network."
    NOTRUN=$((NOTRUN + 1))
    return 1
  fi
  if [ -z "${CAIRN_PORTAL:-}" ]; then
    say "NOT ASKED: no portal is named, so there is no cluster to be told about."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  read_reader "$binary" -collect-proxmox "the Proxmox VE cluster" "guests"
}
run_capability proxmox capability_proxmox || true

# ---------------------------------------------------------------------------
# The relay: read requests the portal queues for connections an administrator
# pointed at this appliance. WO-0928-G item 5, WO-0929-A item 3.
#
# The binary fetches the list of connections and their declared origins
# itself, checks every request against it, never follows a redirect, and
# refuses an answer over its limit. Exit 3 is NOT ASKED -- no connection
# names this appliance, or the credential could not be fetched.
capability_relay() {
  local binary="${HERE}/preflight/preflight"
  if [ ! -x "$binary" ]; then
    say "NOT RUN: there is no preflight binary at ${binary}; that is a fault in this installation, not in the network."
    NOTRUN=$((NOTRUN + 1))
    return 1
  fi
  if [ -z "${CAIRN_PORTAL:-}" ]; then
    say "NOT ASKED: no portal is named, so there is nothing to carry reads for."
    UNASKED=$((UNASKED + 1))
    return 1
  fi

  # WO-1004-RS item 3: any exit but 0 and 3 printed REFUSED. read_reader reads
  # what the binary said: the portal or a relayed system refusing in words is a
  # refusal, quoted; anything else is could not tell.
  read_reader "$binary" -relay "the relay" "reads to carry"
}
run_capability relay capability_relay || true

# ---------------------------------------------------------------------------
rule "what this appliance can reach"
# **Capabilities are counted as capabilities.** WO-1004-L item 2. Step 0 --
# where the credential came from -- was counted in FOUND here and not by the
# portal, so a run that answered one capability printed two and the tally and
# the card disagreed by one. It is a different fact, and it has its own line.
#
# **Five counts, printed as five.** WO-1004-M item 1. Answered, empty, refused,
# could not tell and not asked are five different facts, and only refused is
# something the customer's systems said. A count that adds a refusal to an
# unknown has two populations in one number: this tally printed could-not-tell
# inside refused until 5 October 2026, in the fix that had just taken empty out
# of it. Not run, which is about this box, is printed only when there is one.
say "answered:       ${FOUND}"
say "empty:          ${EMPTY}   (read to the end and held nothing -- a read, not a refusal)"
say "refused:        ${REFUSED}   (the other end said no)"
say "could not tell: ${UNTOLD}   (this run cannot tell a refusal from no answer -- about us, not them)"
say "not asked:      ${UNASKED}"
if [ "$NOTRUN" -gt 0 ]; then
  say "not run:        ${NOTRUN}   (a fault on this box -- nothing here is about the"
  say "                customer's network)"
fi
say "credential:     ${CREDENTIAL_FROM}   (not a capability, and counted in none of the above)"
say ""
say "Five answers, not two. Only a refusal is evidence of what the customer's"
say "systems allow; could not tell and not asked are about this run."
say ""

#
# **Partial credit, stated rather than left to be inferred from the counts.**
#
# The capabilities above need different rights: reading the authorized-server
# list needs an authenticated user, the DHCP interface needs DHCP Users. So a
# run can prove most of what matters and fail the last one, and that is a
# result worth carrying back rather than a wasted trip. Saying so here is the
# difference between an operator reading the output as *one right is missing*
# and reading it as *this does not work*.
#
if [ $((FOUND + EMPTY)) -gt 0 ] && [ "$REFUSED" -gt 0 ]; then
  say "PARTLY PROVEN: $((FOUND + EMPTY)) capabilit(ies) answered (${EMPTY} of them empty) and ${REFUSED} refused."
  say "  That is a result, not a failed run. The ones that answered are proven"
  say "  on this host with this credential, and what they proved stays true"
  say "  whatever refused after them -- these capabilities need different"
  say "  rights, so one refusal never stands in for the others."
  say ""
fi

# ---------------------------------------------------------------------------
# Reporting the run
#
# **What it reached, never what it found.** No device, no lease, no address
# goes through this door: inventory has its own, with its own paging, its
# own ledger and its own retirement rules, and a second writer into that
# table with none of them is what retirement by set difference is
# unforgiving about.
#
# **Nothing here is a verdict.** Whether four capabilities out of five is
# good is a judgement with a source and a review date and it belongs in the
# rule store. This says what happened.
# ---------------------------------------------------------------------------
# The installed binary's own account of its build, for the run report.
# WO-0930-J item 2.
#
# **The box reporting its own build is the only reliable signal of what runs
# here.** A fetch from the portal shows a download, not an install, and the
# timer runs whatever is at this path. So the report carries what the binary
# says about itself (-version, its commit stamp) and the SHA-256 of the file
# at the path the timer runs -- the digest the portal publishes binaries under.
#
# **Set into BINARY_JSON rather than printed**, because say() writes to the
# same stream a command substitution would capture: a message printed here
# would arrive inside the JSON.
#
# **A build that cannot be read is said out loud and not claimed.** The
# portal reads a report without it as "build not reported", which is true;
# a guessed or empty value would read as a build, which is not.
BINARY_JSON=""
binary_report_json() {
  local binary="$1" stamp digest
  BINARY_JSON=""
  if [ ! -x "$binary" ]; then
    say ""
    say "BUILD NOT REPORTED: there is no binary at ${binary} to ask."
    return 0
  fi
  stamp="$("$binary" -version 2>&1)" || stamp=""
  digest="$(sha256sum "$binary" | cut -c1-64)" || digest=""
  if [ -z "$stamp" ] || ! printf '%s' "$digest" | grep -Eq '^[0-9a-f]{64}$'; then
    say ""
    # WO-1004-M item 2: this predicted what a page would say. The box cannot
    # see a page; it says what it sends.
    say "BUILD NOT REPORTED: ${binary} did not say its build, or could not be hashed."
    say "  The run report carries no build, rather than a guessed one."
    return 0
  fi
  BINARY_JSON="$(printf ',"binary":{"stamp":"%s","sha256":"%s"}' "$(json_safe "$stamp")" "$digest")"
}

# Whether this run heard its consent list, for the run report. WO-1004-I
# item 1. Only the three values settle_consent writes are reported; anything
# else -- empty because the run never settled -- is left out, and the portal
# reads its absence as not reported rather than as any of the three.
CONSENT_JSON=""
consent_report_json() {
  CONSENT_JSON=""
  case "$CONSENT_LIST" in
    heard|not-sent|not-heard) CONSENT_JSON="$(printf ',"consentList":"%s"' "$CONSENT_LIST")" ;;
  esac
}

# Which preflight.sh this run is, for the run report. WO-1004-K item 1a.
#
# The binary reaches this box verified against a digest the portal published.
# This script reaches it by a person's git pull, verified against nothing, and
# until this field the portal could not say which version of it ran. So the box
# reports its own commit, and whether the tracked files here differ from that
# commit: clean, dirty, or -- when git cannot answer -- unknown, with git's own
# words for why. Untracked files are not counted, so the preflight.previous a
# binary install leaves beside the binary does not make a box read as dirty;
# an edited tracked file does.
SCRIPT_JSON=""
script_report_json() {
  SCRIPT_JSON=""
  script_identity
  if [ "$SCRIPT_ID_STATE" = "unknown" ]; then
    SCRIPT_JSON="$(printf ',"script":{"state":"unknown","reason":"%s"}' "$(json_safe "$SCRIPT_ID_REASON")")"
    return 0
  fi
  SCRIPT_JSON="$(printf ',"script":{"commit":"%s","state":"%s"}' "$SCRIPT_ID_COMMIT" "$SCRIPT_ID_STATE")"
}

submit_run_report() {
  local finished payload status
  finished="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  if [ ! -f "${CONFIG_DIR}/appliance.key" ] || [ -z "${CAIRN_PORTAL:-}" ]; then
    say ""
    say "NOT REPORTED: this box is not enrolled, or was not told a portal."
    say "  The run above stands on its own. Nothing was submitted anywhere."
    return 0
  fi

  payload="$(mktemp)"

  # **A run that could not start carries a reason and NO capability list.**
  # An empty list is a claim about the domain; an absent list is the absence
  # of a claim, and a box that never got a credential has made no claim.
  # **The schedule this box is on, declared only when it IS on one.**
  #
  # Jackie's ruling, 23 September 2026: the appliance declares its interval in
  # the submission and the portal holds no setting for it. The timer is the
  # truth; a portal field would be an intention, and the two would drift the
  # first time somebody edited the timer without opening the portal.
  #
  # The systemd service sets CAIRN_INTERVAL_MINUTES. **A hand run sets nothing
  # and therefore declares nothing**, which is correct rather than a gap: a
  # hand run is not a schedule, and the portal already has words for a
  # collector that has submitted and is not expected again.
  #
  # **Said out loud rather than quietly dropped** when it is set to something
  # that is not a schedule. The portal refuses such a value and would reject
  # the whole report over an optional field, so it is checked here too, where
  # the reason can be printed beside the run it belongs to. Not-found and
  # found-clean are different results.
  local interval_json=""
  if [ -n "${CAIRN_INTERVAL_MINUTES:-}" ]; then
    if printf '%s' "$CAIRN_INTERVAL_MINUTES" | grep -Eq '^[1-9][0-9]*$'; then
      interval_json=",\"intervalMinutes\":${CAIRN_INTERVAL_MINUTES}"
    else
      say ""
      say "SCHEDULE NOT DECLARED: CAIRN_INTERVAL_MINUTES is not a positive whole"
      say "  number of minutes, so the run report declares no schedule for this run"
      say "  rather than a number nobody set."
    fi
  fi

  binary_report_json "${HERE}/preflight/preflight"
  consent_report_json
  script_report_json

  # Where the credential came from, as one of the seven values the portal's
  # credential_source column accepts. WO-1004-L items 2 and 6. Left out when the
  # step never settled, which the portal reads as not reported.
  local credential_json=""
  case "$CREDENTIAL_SOURCE" in
    portal|portal-incomplete|portal-failed|not-fetched|environment|terminal|none)
      credential_json="$(printf ',"credentialSource":"%s"' "$CREDENTIAL_SOURCE")" ;;
  esac

  if [ "$CRED_FAILED" -eq 1 ]; then
    {
      printf '{"startedAt":"%s","finishedAt":"%s"' "$RUN_STARTED" "$finished"
      printf ',"outcome":"could-not-start","reason":"%s"' "$(json_safe "$CRED_REASON")"
      printf '%s%s%s%s%s}' "$interval_json" "$BINARY_JSON" "$CONSENT_JSON" "$SCRIPT_JSON" "$credential_json"
    } >"$payload"
  else
    {
      printf '{"startedAt":"%s","finishedAt":"%s"' "$RUN_STARTED" "$finished"
      printf ',"outcome":"ran","capabilities":[%s]' "$CAP_JSON"
      printf '%s%s%s%s%s}' "$interval_json" "$BINARY_JSON" "$CONSENT_JSON" "$SCRIPT_JSON" "$credential_json"
    } >"$payload"
  fi

  # The binary signs and sends. The file is written first and acted on
  # second: a payload travelling through a shell quote is the failure this
  # project has had nine of.
  # The binary's own words are kept, because they are what tell a refusal by
  # the portal from a report that never reached it. WO-1004-M item 2.
  local said words
  said="$(mktemp)"
  status=0
  "${HERE}/preflight/preflight" -portal "${CAIRN_PORTAL}" -report <"$payload" >/dev/null 2>"$said" \
    || status=$?

  rm -f "$payload"
  sed 's/^/  /' "$said"
  words="$(grep '^preflight: ' "$said" | tail -n 1)"
  words="${words#preflight: }"
  rm -f "$said"

  if [ "$status" -eq 0 ]; then
    say ""
    # WO-1004-L item 3: this said what the connection card now shows. The box
    # cannot see the card; what it knows is that the portal accepted the report.
    say "REPORTED: the portal accepted this run's report."
    return 0
  fi

  # **A report that did not land is said out loud rather than swallowed**, and
  # it says WHICH of three things happened. WO-1004-M item 2: this printed
  # "the portal refused the report" for any non-zero exit, no route to the
  # portal included -- the line a person reads at a terminal at night, sending
  # them to debug our own service when the box had no network. A refusal is
  # something the other end said; an exit code is something our process did.
  # The run itself still stands either way: what it reached is printed above.
  say ""
  case "$words" in
    "refused ("[0-9][0-9][0-9]")"*)
      say "NOT REPORTED: the portal answered and refused the report: ${words}"
      say "  The portal received it and said no, in the words above."
      ;;
    "reaching the portal:"*)
      say "NOT REPORTED: this box could not reach the portal, so the portal said nothing."
      say "  ${words}"
      say "  Check this box's network, and that ${CAIRN_PORTAL} resolves and answers from here."
      ;;
    *)
      say "NOT REPORTED: the report did not leave this box (exit ${status}): ${words:-the binary gave no reason}"
      say "  That is a fault on this box, not an answer from the portal."
      ;;
  esac
  say "  The run itself is unaffected: what it reached is printed above."
}
submit_run_report

say ""
say "Nothing was collected and nothing on the domain was changed."

# Exit non-zero only when something was genuinely refused. Nothing-asked is not
# a failure of this host; it is a gap in what it was told.
[ "$REFUSED" -eq 0 ]
