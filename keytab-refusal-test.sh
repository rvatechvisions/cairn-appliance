#!/usr/bin/env bash
#
# A keytab on this box stops the run.
#
# ## Why this test exists, and why it did not until 24 September 2026
#
# **`a collector must not be a member of the trust boundary it reads` is
# Jackie's decision of 20 September 2026**, and the keytab is the artifact the
# design it withdrew placed by hand. The refusal in `preflight.sh` is the only
# thing enforcing it on the box.
#
# A security audit of the eighteen promises this product makes found fifteen
# held by a test, two that nothing local can hold — an Azure RBAC denial and
# the single staff authenticator — and **one held by code and nothing else.
# This was that one**, and it is the only one of the eighteen that is a promise
# about a client's domain controller.
#
# It could not have been tested before, and the reason is worth keeping: the
# scan was a block with `CONFIG_DIR` as a literal, so nothing could point it at
# a directory that was not this machine's `/etc`. **A guarantee that cannot be
# driven is a guarantee nobody can check**, and the fix was to the subject
# rather than to the test.
#
# ## It reads the function out of the shipping script
#
# Never a copy. *Two copies of one fact is what produced the miss this project
# keeps finding* — a test carrying its own version agrees with the author's
# recollection and with nothing else. `preflight-credential-test.sh` already
# works this way, and an extraction that finds nothing REFUSES here rather than
# passing over zero assertions.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="${HERE}/preflight.sh"

fails=0
checks=0

ok()  { checks=$((checks + 1)); printf 'ok:   %s\n' "$1"; }
bad() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL: %s\n' "$1"; }

if [ ! -r "$SCRIPT" ]; then
  printf 'FAIL: cannot read %s. Nothing was checked.\n' "$SCRIPT"
  exit 2
fi

extract() {
  sed -n "/^${1}() {/,/^}/p" "$SCRIPT"
}

body="$(extract durable_credentials)"
if [ -z "$body" ]; then
  printf 'FAIL: durable_credentials is not defined in preflight.sh.\n'
  printf '      This test read nothing, which is a broken check and not a clean run.\n'
  exit 2
fi
eval "$body"
ok "durable_credentials was found in preflight.sh and evaluated"

# A box that is not this one, so nothing here depends on /etc.
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT

CONFIG="${SANDBOX}/config"
UNITS="${SANDBOX}/units"
mkdir -p "$CONFIG" "$UNITS"
NO_KEYTAB="${SANDBOX}/absent-krb5.keytab"
SETTINGS="${CONFIG}/settings.env"
printf 'CAIRN_DOMAIN=example.test\n' > "$SETTINGS"

drive() {
  durable_credentials "$CONFIG" "$NO_KEYTAB" "$SETTINGS" "$UNITS"
}

# ---------------------------------------------------------------------------
# The clean box, first — because a refusal that fires on everything proves
# nothing about the case it was written for.
# ---------------------------------------------------------------------------
report="$(drive)"; status=$?
if [ "$status" -eq 0 ] && [ -z "$report" ]; then
  ok "a box with no keytab and no stored password is clean"
else
  bad "a clean box was reported dirty: exit ${status}, report: ${report}"
fi

# ---------------------------------------------------------------------------
# A keytab in the configuration directory. This is the artifact the withdrawn
# domain-join design placed by hand.
# ---------------------------------------------------------------------------
printf 'not a real keytab\n' > "${CONFIG}/appliance.keytab"
report="$(drive)"; status=$?
if [ "$status" -ne 0 ]; then
  ok "a .keytab in the configuration directory makes the scan refuse"
else
  bad "a .keytab in the configuration directory was NOT caught"
fi
case "$report" in
  *"FOUND A KEYTAB"*appliance.keytab*) ok "the refusal names the file it found" ;;
  *) bad "the refusal did not name the keytab: ${report}" ;;
esac
rm -f "${CONFIG}/appliance.keytab"

# ---------------------------------------------------------------------------
# The `.kt` spelling, which is the same artifact under the other extension.
# Asserted separately because a scan that knew one and not the other would
# pass the test above and miss half its subject.
# ---------------------------------------------------------------------------
printf 'not a real keytab\n' > "${CONFIG}/appliance.kt"
report="$(drive)"; status=$?
if [ "$status" -ne 0 ]; then
  ok "a .kt in the configuration directory makes the scan refuse"
else
  bad "a .kt was NOT caught — the scan knows one keytab extension and not the other"
fi
rm -f "${CONFIG}/appliance.kt"

# ---------------------------------------------------------------------------
# The system keytab, which is where a domain join would put one. The parameter
# is a path that does not exist in the clean case, so this is the only
# assertion that exercises it.
# ---------------------------------------------------------------------------
printf 'not a real keytab\n' > "$NO_KEYTAB"
report="$(drive)"; status=$?
if [ "$status" -ne 0 ]; then
  ok "the system keytab makes the scan refuse — the domain-join artifact"
else
  bad "a system keytab was NOT caught"
fi
rm -f "$NO_KEYTAB"

# ---------------------------------------------------------------------------
# A password parked in the settings file, which is the other way the same
# property is lost: something durable that nobody rotates and nobody revokes.
# ---------------------------------------------------------------------------
printf 'CAIRN_PASSWORD=hunter2\n' >> "$SETTINGS"
report="$(drive)"; status=$?
if [ "$status" -ne 0 ]; then
  ok "a password in the settings file makes the scan refuse"
else
  bad "a stored password was NOT caught"
fi
case "$report" in
  *"FOUND A PASSWORD"*) ok "the refusal says it was a password rather than a keytab" ;;
  *) bad "the refusal did not distinguish a password from a keytab: ${report}" ;;
esac
printf 'CAIRN_DOMAIN=example.test\n' > "$SETTINGS"

# ---------------------------------------------------------------------------
# An EnvironmentFile in a systemd unit naming cairn. **This is the shape the
# obvious way to make an unattended run work would take**, which is why the
# scan looks for the directive itself rather than only for a variable name.
# ---------------------------------------------------------------------------
printf '[Service]\nEnvironmentFile=/etc/cairn-appliance/secret\n' > "${UNITS}/cairn-preflight.service"
report="$(drive)"; status=$?
if [ "$status" -ne 0 ]; then
  ok "a unit carrying EnvironmentFile makes the scan refuse"
else
  bad "a unit carrying a credential was NOT caught"
fi
rm -f "${UNITS}/cairn-preflight.service"

# ---------------------------------------------------------------------------
# And clean again at the end, so the refusals above are about what was planted
# rather than about state the earlier cases left behind.
# ---------------------------------------------------------------------------
report="$(drive)"; status=$?
if [ "$status" -eq 0 ] && [ -z "$report" ]; then
  ok "the sandbox is clean again, so each refusal was about its own plant"
else
  bad "the sandbox did not return to clean: exit ${status}, report: ${report}"
fi

printf '\nchecks: %s, failures: %s\n' "$checks" "$fails"
if [ "$checks" -lt 9 ]; then
  printf 'FAIL: only %s checks ran. A run this short is a broken test.\n' "$checks"
  exit 2
fi
[ "$fails" -eq 0 ] || exit 1
printf 'PASS: a durable credential on this box stops the run.\n'
