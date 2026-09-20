#!/usr/bin/env bash
#
# Give this appliance an identity, generated here and never transmitted.
#
# ## Why a keypair rather than a token the portal issues
#
# The appliance fetches a customer's read-only directory credential from the
# portal at run time. So whatever secret sits on this box is, in effect, the
# thing standing between an attacker and that credential — and the two
# candidates are not equivalent.
#
# **A bearer token exists in at least two places.** The portal minted it, so it
# was in the portal's memory, in the response that delivered it, in whatever
# the operator pasted it into, and in any backup or configuration system that
# touched it afterwards. Every one of those is a place it can leak from without
# anybody touching this machine.
#
# **A private key generated here exists in one place.** The portal never had
# it, so the portal cannot leak it; nothing transmitted it, so nothing in
# between can have kept a copy. Only the public half leaves this box.
#
# **What it does not change, stated rather than implied:** an attacker who
# reaches this filesystem as root gets the private key and can then ask the
# portal for the credential, exactly as a stolen token would let them. The
# difference is the number of copies and the paths they travelled, not the
# consequence of this host being compromised. Both are revocable centrally,
# which is the other half of why either beats a credential file.
#
set -uo pipefail

CONFIG_DIR=/etc/cairn-appliance
KEY="${CONFIG_DIR}/appliance.key"

# WE name this now, because openssl writes exactly where it is told.
#
# ssh-keygen used to decide it -- the public half went to the private half's
# path with .pub appended -- and naming it independently was how the first
# version came to chmod, chown and cat a file that was never created, then
# print the paths of both keys as though both existed. The lesson survives the
# tool change: the reads below check each file exists rather than trusting the
# generator to have made it.
PUB="${KEY}.pub"

if [ "$(id -u)" -ne 0 ]; then
  echo "This must run as root: it writes to ${CONFIG_DIR}."
  exit 1
fi

if [ ! -d "$CONFIG_DIR" ]; then
  echo "No ${CONFIG_DIR}. Run bootstrap.sh first."
  exit 1
fi

if [ -f "$KEY" ]; then
  echo "This appliance is already enrolled."
  echo
  echo "Its key is at ${KEY} and was generated here. There is deliberately no"
  echo "way to re-issue it from the portal: a key the portal could reissue is a"
  echo "key the portal has held, which is the property this design exists for."
  echo
  echo "To replace it, revoke this appliance in the portal, delete both files"
  echo "below, and run this again."

  # The error stream is kept rather than discarded. A missing public half is
  # exactly the state the first version of this script produced, and sending
  # the complaint to the null device would print a list with one entry and let
  # it read as a complete pair.
  ls -l "$KEY" "$PUB"
  exit 0
fi

echo "Generating this appliance's key. It does not leave this machine."

# ed25519: small, fast, and no parameters to get wrong. No passphrase, because
# this runs unattended -- the protection is the file mode and the fact that the
# key is useless without the portal also agreeing this appliance is enrolled.
#
# OPENSSL RATHER THAN ssh-keygen, AND THE REASON IS THAT WE WRITE NO
# FORMAT-PARSING CODE. Jackie's decision, 20 September 2026.
#
# An ssh-keygen key cannot be verified by the portal without us owning a
# parser. Measured, not assumed: Node refuses `createPublicKey` with format
# openssh, refuses the OpenSSH private key outright with
# `DECODER routines::unsupported`, and `ssh-keygen -e -m PKCS8` refuses
# ED25519. So neither end converts, and signing would have to go through
# `ssh-keygen -Y sign` -- SSHSIG, which has an armoured envelope, a magic
# string, a namespace, a reserved field and a pre-hash step. Parsing that
# means owning crypto-adjacent parsing for ever and getting it subtly wrong
# eventually.
#
# openssl gives PKCS8 in and SPKI out, and a raw 64-byte signature that
# Node's own crypto.verify takes. Neither end is our code.
#
# SSHSIG is for a different job -- a human's SSH key signing files and
# commits, with namespaces existing specifically to prevent cross-protocol
# reuse. This is machine auth with a purpose-built keypair.
#
# AND THE APPARENT ADVANTAGE WAS A DISADVANTAGE: an ssh-format key could
# double as an SSH login key to this box. The identity key does one job.
if ! openssl genpkey -algorithm ed25519 -out "$KEY" >/dev/null 2>&1; then
  echo "FAILED: could not generate a key. Is openssl installed?"
  exit 1
fi

# The public half, written where we said. SPKI PEM, which is what the portal
# reads with no parsing of ours in between.
if ! openssl pkey -in "$KEY" -pubout -out "$PUB" >/dev/null 2>&1; then
  echo "FAILED: a private key was generated and its public half was not."
  echo "  Remove ${KEY} and run this again rather than leaving a key whose"
  echo "  public half nobody has."
  exit 1
fi

# Read the outcome rather than reporting the attempt.
#
# The first version ran these three unchecked and then printed both key paths
# and a success block, on a run where the public half did not exist under the
# name it was looking for. Every line of that output was a claim nothing had
# verified -- which is the failure this project already names, arriving inside
# the script whose whole job is to produce one artifact.
for required in "$KEY" "$PUB"; do
  if [ ! -f "$required" ]; then
    echo "FAILED: openssl reported success and ${required} is not there."
    echo "  Nothing was enrolled. Do not treat this appliance as having a key."
    exit 1
  fi
done

if ! chmod 600 "$KEY" || ! chmod 644 "$PUB" || ! chown root:root "$KEY" "$PUB"; then
  echo "FAILED: the keys were generated and could not be secured."
  echo "  ${KEY} may be readable by somebody other than root. Check it, remove"
  echo "  both files, and run this again rather than leaving them in place."
  exit 1
fi

echo
echo "=== the public half, which is what the portal needs ==="
echo "(SPKI PEM. The portal reads this with no format conversion.)"
cat "$PUB"
echo
echo "=== what happens now ==="
echo
echo "**The portal side of enrolment is not built yet.** There is no endpoint"
echo "to post this to and no page to paste it into, and saying so here is"
echo "deliberate: an appliance that printed a key and implied it had registered"
echo "would be the most confidently wrong output this script could produce."
echo
echo "For the lab, that does not block anything. See LAB-BUILD.md, which gives"
echo "the credential path that works today and says plainly which part of it is"
echo "a lab-only stand-in for the design above."
echo
echo "private key: ${KEY} (mode 600, root only, never transmitted)"
echo "public key:  ${PUB}"
