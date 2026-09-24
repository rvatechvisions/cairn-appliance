#!/usr/bin/env bash
#
# Prepare a Debian or Ubuntu host to be a Cairn collection appliance.
#
# ## What this does and does not do
#
# It installs packages, creates one directory and writes one template. It
# contacts no domain, reads nothing from Active Directory, and submits nothing
# anywhere. Preflight is a separate script and it is the one that talks to a
# customer's network.
#
# ## Idempotent, and no step aborts the run
#
# Run it twice and the second run changes nothing. More importantly, a step
# that fails does not stop the ones after it: a host with no Go in its
# repositories should still end up with Kerberos and LDAP configured, and the
# operator should be told exactly which piece is missing rather than being left
# with a half-prepared machine and one error at the top of the screen.
#
# So every step reports its own outcome and the summary at the end is the
# verdict. `set -e` is deliberately **not** used, and that is the reason.
#
set -uo pipefail

CONFIG_DIR=/etc/cairn-appliance
STEPS_OK=0
STEPS_FAILED=0
FAILURES=()

step() {
  local name="$1"
  shift
  printf '\n=== %s ===\n' "$name"
  if "$@"; then
    STEPS_OK=$((STEPS_OK + 1))
    printf 'ok: %s\n' "$name"
  else
    STEPS_FAILED=$((STEPS_FAILED + 1))
    FAILURES+=("$name")
    printf 'FAILED: %s -- the run continues; see the summary at the end.\n' "$name"
  fi
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This must run as root: it installs packages and writes to ${CONFIG_DIR}."
    exit 1
  fi
}

install_packages() {
  # krb5-user for kinit and klist; ldap-utils for ldapsearch; ca-certificates
  # and curl so a later step can fetch anything it needs over TLS.
  #
  # libsasl2-modules-gssapi-mit IS NOT OPTIONAL AND IS EASY TO MISS. ldapsearch
  # only *Recommends* the SASL mechanism packages, and --no-install-recommends
  # below means a recommendation is not installed -- so a host gets ldapsearch
  # with no GSSAPI mechanism behind it. The failure is
  #
  #   ldap_sasl_interactive_bind: Unknown authentication method (-6)
  #   SASL(-4): no mechanism available: No worthy mechs found
  #
  # which names neither SASL GSSAPI nor a package, and reads like the ticket or
  # the account being wrong when Kerberos has just succeeded a step earlier.
  # Found on the first live run against RVA's domain, 20 September 2026.
  #
  # DEBIAN_FRONTEND keeps krb5-user from opening its realm dialogue, which on
  # an unattended run waits for somebody who is not there.
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq || return 1
  # **No compiler.** `golang-go` was installed here until 24 September 2026,
  # and it is the ACQUISITION half of a rule that had only ever written down
  # the invocation half.
  #
  # The appliance never compiles and never obtains a compiler. Installing one
  # is what made the timer able to rebuild the collector: a distribution `go`
  # at 1.24 met `toolchain go1.27.1` in go.mod and obtained 1.27.1 to satisfy
  # it -- from a cache, or over the network, from a box whose whole premise is
  # outbound HTTPS to the portal and nothing else.
  #
  # **Two installations is what made it invisible.** A login shell found
  # 1.27.1 under /usr/local/go/bin and systemd found 1.24 under /usr/bin, so
  # `go version` by hand answered about a different program from the one the
  # timer ran. *There is more than one of it, and which one you get depends on
  # who is asking.*
  apt-get install -y -qq --no-install-recommends \
    krb5-user ldap-utils libsasl2-modules-gssapi-mit \
    dnsutils ca-certificates curl jq || return 1
}

report_versions() {
  # Printed rather than asserted. A version this script has not met is not a
  # failure, and pinning one here would make the script wrong on the next
  # release of a distribution nobody has tested it on.
  # `go` is deliberately not on this list. A version report for a compiler
  # this appliance must not have would read as a prerequisite somebody should
  # go and satisfy.
  for tool in kinit klist ldapsearch jq; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf '  %-12s %s\n' "$tool" "$(command -v "$tool")"
    else
      printf '  %-12s MISSING\n' "$tool"
    fi
  done

  # **And a compiler that IS present is reported as a finding**, because it
  # is one: this appliance does not compile, so a compiler on it is either a
  # leftover from before 24 September 2026 or something else put it there.
  if command -v go >/dev/null 2>&1; then
    printf '  %-12s %s  <- UNEXPECTED: this appliance does not compile\n' \
      "go" "$(command -v go)"
  fi

  return 0
}

make_config_dir() {
  # 700, because the appliance's private key and its settings live here. The
  # directory is created and locked down before anything is written into it,
  # so there is no window in which a key sits in a world-readable directory
  # while somebody fixes the permissions.
  #
  # It held a keytab in the withdrawn design. It does not now -- the client's
  # credential is fetched from the portal per run and never written here --
  # and preflight refuses to start if it finds one.
  mkdir -p "$CONFIG_DIR" || return 1
  chmod 700 "$CONFIG_DIR" || return 1
  chown root:root "$CONFIG_DIR" || return 1
  ls -ld "$CONFIG_DIR"
}

write_settings_template() {
  local target="${CONFIG_DIR}/settings.env"

  if [ -f "$target" ]; then
    echo "already present, left alone: ${target}"
    return 0
  fi

  cat > "$target" <<'SETTINGS'
# What this appliance is pointed at. Filled in by the technician who installs
# it; preflight reads it and asserts nothing about the values.
#
# Every one of these is read-only against the customer's systems.

# The Active Directory domain, upper case, as Kerberos spells it.
CAIRN_REALM=

# One domain controller, by name. Single-homed and one explicit resolver: this
# host must resolve the domain through the customer's DNS and nothing else, or
# a lookup that silently answers from a public resolver will read as the domain
# being reachable when it is not.
CAIRN_DC=

# The service account, which is an ordinary domain user plus membership of
# DHCP Users. Nothing else. It needs no administrative rights anywhere.
CAIRN_PRINCIPAL=

# Where this appliance fetches that account's credential from, per run.
#
# THERE IS DELIBERATELY NO PASSWORD IN THIS FILE, AND NO KEYTAB BESIDE IT.
# The customer enters the credential into the portal; this appliance connects
# out, authenticates with the key enroll.sh generated here, and holds the
# credential only for the length of a run, in memory. A copy on this box would
# be a second place it lives that nobody rotates and nobody can revoke without
# knowing it exists -- and preflight refuses to run if it finds one.
CAIRN_PORTAL=

# The DHCP servers to ask, comma separated, by name. Preflight asks each one
# and reports each answer separately -- a server that refuses is a different
# fact from a server with no scopes.
CAIRN_DHCP_SERVERS=
SETTINGS

  chmod 600 "$target" || return 1
  echo "written: ${target}"
}

check_resolver() {
  # Reported, never corrected. A host with two resolvers or two interfaces is
  # a real configuration decision and this script is not entitled to make it --
  # but an appliance that resolves the customer's domain through a public
  # resolver will produce preflight results that mean nothing, so the operator
  # is shown what this host will actually do.
  echo "resolvers this host will use:"
  if [ -r /etc/resolv.conf ]; then
    grep -E '^(nameserver|search|domain)' /etc/resolv.conf | sed 's/^/  /' || true
  else
    echo "  /etc/resolv.conf is not readable"
  fi

  echo
  echo "interfaces carrying an address:"
  ip -brief address show 2>/dev/null | sed 's/^/  /' || echo "  ip(8) is not available"

  echo
  echo "This appliance is meant to be single-homed with one resolver, the"
  echo "customer's. If more than one of either is listed above, decide about it"
  echo "before running preflight -- nothing here will change it for you."
  return 0
}

require_root

echo "Cairn collection appliance -- bootstrap"
echo "Nothing here contacts a domain. Preflight does that, separately."

step "install packages" install_packages
step "tools present" report_versions
step "configuration directory" make_config_dir
step "settings template" write_settings_template
step "network shape" check_resolver

echo
echo "=== summary ==="
echo "${STEPS_OK} step(s) ok, ${STEPS_FAILED} failed"

if [ "${STEPS_FAILED}" -gt 0 ]; then
  for name in "${FAILURES[@]}"; do
    echo "  failed: ${name}"
  done
  echo
  echo "The host is partly prepared. Each failure above is independent of the"
  echo "others: fix what is named and run this again, which changes nothing"
  echo "that already succeeded."
  exit 1
fi

echo
echo "Next, in order:"
echo "  1. Fill in ${CONFIG_DIR}/settings.env"
echo "  2. Run ./enroll.sh, which generates this appliance's key pair here"
echo "  3. Run ./preflight.sh"
echo
echo "There is no keytab and no password on this box, deliberately. The"
echo "credential is held in the portal and fetched per run, so preflight"
echo "REFUSES to start if it finds either one here."
