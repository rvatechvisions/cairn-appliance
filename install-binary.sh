#!/usr/bin/env bash
#
# Install a binary the portal published, carried here by a person.
#
#   sudo ./install-binary.sh <file> <sha256 published by the portal>
#
# ## Why this is the install path
#
# The order author's ruling, WO-1001-D item 1, 1 October 2026: **the portal
# publishes, a person carries, the box verifies against the published digest
# before anything runs. -update is the maintenance path, not the install
# path.** A box whose binary predates -update can never reach a newer one on
# its own, and every box left unattended long enough predates something -- so
# a product whose only upgrade route needs the feature being installed has no
# upgrade route.
#
# None of the four appliance refusals is touched. This box compiles nothing,
# acquires no compiler, runs nothing it has not verified, and fetches nothing:
# the origin is the portal and the person is the carrier.
#
# ## What it checks, in order, and what it does when a check fails
#
# 1. The digest typed is a SHA-256.
# 2. **The file hashes to it.** Both digests are printed one above the other,
#    so the person sees the comparison rather than being told about it.
# 3. The copy staged beside the installed binary still hashes to it.
# 4. The staged binary declares the consent list (-speaks), because preflight.sh
#    refuses to run one that does not.
#
# **Any failure refuses, loudly, and leaves the installed binary exactly as it
# was.** The new bytes never reach the path the timer runs until every check
# has passed, and they arrive there by one rename. The previous binary is kept
# beside it as preflight.previous, so going back is a person's decision rather
# than a rebuild.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say() { printf '%s\n' "$*"; }

# Refuse, naming why, with the installed binary untouched and said to be.
refuse_install() {
  local target="$1" why="$2" installed
  say ""
  say "REFUSED: ${why}"
  if [ -x "$target" ]; then
    installed="$("$target" -version 2>&1)" || installed="${installed:-it did not say}"
    say "  Nothing was installed. ${target} is unchanged: ${installed}"
  else
    say "  Nothing was installed. There is still no binary at ${target}."
  fi
  return 1
}

# Verify the carried file against the digest the person read off the card, and
# put it in place only if every check passes. Returns 0 installed, 1 refused.
verify_and_install() {
  local file="$1" typed="$2" target="$3"
  local expected actual staged staged_digest speaks

  expected="$(printf '%s' "$typed" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  if ! printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$'; then
    refuse_install "$target" "the digest given is not a SHA-256 (64 hexadecimal characters): ${typed}"
    return 1
  fi
  if [ ! -s "$file" ]; then
    refuse_install "$target" "there is no file at ${file}, or it is empty."
    return 1
  fi

  actual="$(sha256sum "$file" | cut -c1-64)"
  # The digest it was GIVEN. It cannot know where that came from, and saying
  # "the card" made a wrong digest read as the portal's. WO-1004-F item 4.
  say "the digest you gave:        ${expected}"
  say "the file you carried:       ${actual}"
  if [ "$actual" != "$expected" ]; then
    refuse_install "$target" "THE FILE DOES NOT MATCH THE DIGEST YOU GAVE.
  Either the digest is not the one the portal published, or the file is not the
  binary the portal offers, or it was damaged on the way. Do not run it."
    return 1
  fi
  say "they match."

  # **The build already installed is a no-op, named as one, and allowed.**
  # WO-1004-P item 4a. On 4 October 2026 a person installed the build the box
  # was already running, twice, because the card told him to; both succeeded,
  # and the second moved preflight.previous onto the same build, so the
  # rollback that file implies was gone. Refusing a harmless action is how a
  # person learns to work around a script, so it is allowed -- and changes
  # nothing, so preflight.previous keeps the build that came before.
  if [ -x "$target" ] && [ "$(sha256sum "$target" | cut -c1-64)" = "$expected" ]; then
    say ""
    say "ALREADY INSTALLED: ${target} is already this build. Nothing was changed."
    say "  it says:   $("$target" -version 2>&1)"
    if [ -e "${target}.previous" ]; then
      say "  previous:  ${target}.previous is left as it was ($("${target}.previous" -version 2>&1 || true))"
    fi
    return 0
  fi

  staged="${target}.incoming"
  if ! cp "$file" "$staged" || ! chmod 755 "$staged"; then
    rm -f "$staged"
    refuse_install "$target" "could not stage the file beside ${target}."
    return 1
  fi
  staged_digest="$(sha256sum "$staged" | cut -c1-64)"
  if [ "$staged_digest" != "$expected" ]; then
    rm -f "$staged"
    refuse_install "$target" "the staged copy hashes to ${staged_digest}, not to the published digest."
    return 1
  fi

  speaks="$("$staged" -speaks 2>&1)" || speaks="${speaks:-it answered nothing}"
  case " ${speaks#credential-block:} " in
    *" capabilities "*) ;;
    *)
      rm -f "$staged"
      refuse_install "$target" "this binary does not declare the consent list, so preflight.sh would refuse to run it.
  -speaks answered: ${speaks}"
      return 1
      ;;
  esac

  if [ -e "$target" ] && ! cp -p "$target" "${target}.previous"; then
    rm -f "$staged"
    refuse_install "$target" "could not keep the installed binary as ${target}.previous."
    return 1
  fi
  if ! mv -f "$staged" "$target"; then
    rm -f "$staged"
    refuse_install "$target" "could not put the verified binary in place."
    return 1
  fi

  say ""
  say "INSTALLED: ${target}"
  say "  it says:   $("$target" -version 2>&1)"
  say "  SHA-256:   $(sha256sum "$target" | cut -c1-64)"
  if [ -e "${target}.previous" ]; then
    say "  previous:  ${target}.previous ($("${target}.previous" -version 2>&1 || true))"
  fi
  return 0
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  if [ "$#" -ne 2 ]; then
    say "usage: sudo ./install-binary.sh <file> <sha256 published by the portal>"
    exit 2
  fi
  if [ "$(id -u)" -ne 0 ]; then
    say "This must run as root: it replaces the binary the timer runs."
    exit 2
  fi
  verify_and_install "$1" "$2" "${HERE}/preflight/preflight"
fi
