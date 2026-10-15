#!/usr/bin/env bash
#
# US English over every string an operator reads on the box.
#
# ## Why "spelling done" missed this repository entirely
#
# The portal's scan walks `clientFacingFiles()` -- TypeScript under `src` in the
# portal -- and its own header says so. **That scope was written down and was
# still the wrong one**: an operator standing at a district's domain controller
# reads `preflight.sh` and the Go binary, not a web page, and those words are as
# client-facing as anything the portal renders.
#
# The scope was stated honestly and nobody asked whether it was the right scope.
# That is *a check scoped to one member of a set makes every other member drift
# silently*, in its quietest form: the check was correct, its reach was
# documented, and the documentation of the reach read as coverage.
#
# ## What it reads
#
# ~~**KNOWN GAP, recorded 1 October 2026: this checker reports checked on text
# it never read.**~~ *Closed by WO-1015-N28 item 5, 15 October 2026.* A helper
# that printed through say rather than printf or echo was invisible to the
# helper detector -- refuse_install in install-binary.sh and
# refuse_disagreement in preflight.sh were the two -- and the extractor read
# only the first quoted argument on one line. The detector now counts a call to
# say, rule or step as printing, and follows any positional argument through a
# local; the two helpers are read below by the position their text arrives in,
# across lines.
#
# The text these programs PRINT, not their code. A shell variable name and a Go
# identifier are not read as English by anybody, and checking them would produce
# noise that teaches a reader to skip the result.
#
#   - `say`, `rule`, `step`, `keep_submission_digest`, `echo` and `printf` in
#     every tracked shell script. The fourth prints a server name it is
#     handed, so its callers pass a variable and nothing is extracted today;
#     it is listed so a literal handed to it later is read.
#   - `fmt.Print*`, `fmt.Errorf` and `errors.New` in every tracked Go file
#
# **`rule` and `step` are in that list because the first version left them
# out, and the string the work order named was one of theirs.** preflight.sh
# prints its section headings through `rule`, so
# `--- 4. Authorised DHCP servers ---` -- the line an operator sees at the top
# of a section -- was invisible to a checker that read `say` alone. The
# detector was narrower than its subject and its silence looked like a clean
# run, on the exact string it was built to catch.
#
# **The list is asserted, not remembered**: section 2 of `spellcheck-test.sh`
# finds every helper in these scripts that PRINTS ITS OWN ARGUMENTS and fails
# unless this list knows it. A helper added next month fails until somebody
# decides about it.
#
# It reads one line or many. The first version read one, which is how all
# three of these are written, and that limit was documented rather than
# closed until 22 September 2026 -- a detector narrower than its subject,
# whose silence has the same shape as a clean run.
#
# ## What it deliberately does not govern
#
# **The stored values.** Capability names like `dhcp-authorized` are data the
# portal parses, and they are held by `preflight-stored-values-test.sh`, which
# asserts the exact set. Two checks with an opinion about one string is how two
# copies of a fact come to disagree -- so this reads printed text and that one
# reads the vocabulary. **Jackie’s ruling, 22 September 2026**, when widening
# the extractor surfaced `json_safe`: the boundary is where it was.
#
# **And what a helper HANDLES is the weaker test; where its output GOES is the
# stronger one.** `json_safe` would be out of scope on either reading, and the
# second is the one that generalises: every call site captures it
# -- `$(json_safe "$reason")` -- so nothing it emits reaches a terminal. Same
# for `agrees`, which lowercases two strings and is read for an exit status.
# Both use `printf` as a STRING OPERATION, and neither prints to anybody.
#
# So the classification in `spellcheck-test.sh` is mechanical rather than a
# list: a helper whose every call site consumes its output is a transformer
# and drops out by construction. **Default is inclusion** -- a helper whose
# call sites are not all consumed stays in scope and fails until somebody
# decides, which is the direction whose failure mode is a conversation.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE" || { printf 'FATAL: cannot enter %s\n' "$HERE"; exit 2; }

# The not-found branch first, and loud. A spell checker that cannot find its
# checker prints nothing, and nothing looks exactly like no mistakes.
CSPELL="/c/dev/portal/node_modules/.bin/cspell"
CONFIG="${HERE}/cspell.json"

if [ ! -f "$CSPELL" ]; then
  printf 'COULD NOT CHECK: cspell is not at %s\n' "$CSPELL"
  printf '                 Run `npm install` in the portal repository first.\n'
  printf '                 This is a broken check, not a clean result.\n'
  exit 2
fi

if [ ! -f "$CONFIG" ]; then
  printf 'COULD NOT CHECK: no cspell.json beside this script.\n'
  exit 2
fi

# ## The extract lives in the repository, and that is forced rather than chosen
#
# cspell reports only on files inside its configuration's root: pointed at a
# file in the system temp directory it exits 1 and prints NOTHING -- a checker
# that cannot see its subject, answering in exactly the same shape as a clean
# run. That cost one debugging round and is written down so the next person
# does not spend it.
#
# So the extract is a dot-file here, git-ignored, and removed on the way out.
OUT="${HERE}/.operator-text.txt"
trap 'rm -f "$OUT"' EXIT
: > "$OUT"

shell_files=0
go_files=0

while IFS= read -r file; do
  [ -f "$file" ] || continue
  shell_files=$((shell_files + 1))
  # say/echo/printf, with the quotes, the format directives and the shell
  # expansions removed. What is left is the sentence.
  grep -hoE '(^|[[:space:]])(say|rule|step|keep_submission_digest|echo|printf)[[:space:]]+["'"'"'][^"'"'"']*' "$file" \
    | sed -E 's/^[[:space:]]*(say|rule|step|keep_submission_digest|echo|printf)[[:space:]]+["'"'"']//' \
    | sed -E 's/\$\{[^}]*\}/ /g; s/\$[A-Za-z_][A-Za-z0-9_]*/ /g' \
    | sed -E 's/%-?[0-9]*[a-zA-Z]/ /g; s/\\[nrt]/ /g' \
    >> "$OUT"
done < <(git ls-files '*.sh')

# Helpers whose sentence is not their first argument, or runs over several
# lines: each is read at the position its text arrives in, as name:position.
# refuse_install takes the target, then the sentence; refuse_disagreement takes
# the field's label, then two values nobody spells; read_reader takes the
# binary and a flag, then the source's name and what it lists. The quoted
# argument is read whole, newlines included, which a line-by-line grep cannot
# do, and an unquoted argument counts toward the position without being read.
#
# verify_and_install, binary_report_json and capability_dhcp print what they
# are handed and every caller today hands them a variable or nothing, so
# nothing is extracted from them; they are listed, as keep_submission_digest
# is above, so a literal handed to one later is read. WO-1015-N28 item 5.
POSITIONED='refuse_install:2 refuse_disagreement:1 read_reader:3 read_reader:4 verify_and_install:1 verify_and_install:2 verify_and_install:3 binary_report_json:1 capability_dhcp:1'
while IFS= read -r file; do
  [ -f "$file" ] || continue
  for entry in $POSITIONED; do
    HELPER="${entry%%:*}" POSITION="${entry##*:}" perl -0777 -ne '
      my $name = $ENV{HELPER}; my $at = $ENV{POSITION};
      while (/(?:^|[\s;])\Q$name\E((?:[ \t]+(?:"(?:[^"\\]|\\.)*"|[^\s"]+)){$at})/g) {
        my @tokens;
        my $seq = $1;
        while ($seq =~ /"((?:[^"\\]|\\.)*)"|([^\s"]+)/g) { push @tokens, defined $1 ? [1, $1] : [0, $2]; }
        my $t = $tokens[$at - 1];
        print "$t->[1]\n" if defined $t && $t->[0];
      }
    ' "$file" \
      | sed -E 's/\$\{[^}]*\}/ /g; s/\$[A-Za-z_][A-Za-z0-9_]*/ /g' \
      >> "$OUT"
  done
done < <(git ls-files '*.sh')

while IFS= read -r file; do
  [ -f "$file" ] || continue
  go_files=$((go_files + 1))
  grep -hoE '(fmt\.(Print|Printf|Println|Fprintf|Fprintln|Errorf)|errors\.New)\([^)]*"[^"]*"' "$file" \
    | grep -oE '"[^"]*"' \
    | tr -d '"' \
    | sed -E 's/%-?[0-9]*[a-zA-Z]/ /g; s/\\[nrt]/ /g' \
    >> "$OUT"
done < <(git ls-files '*.go')

lines="$(wc -l < "$OUT" | tr -d ' ')"
printf 'operator-facing text: %s lines, from %s shell scripts and %s Go files\n' \
  "$lines" "$shell_files" "$go_files"

# A floor. A walk that extracts nothing passes everything, and the extraction
# here is regular expressions over somebody's formatting -- exactly the thing
# that rots quietly.
if [ "$shell_files" -lt 4 ] || [ "$go_files" -lt 1 ] || [ "$lines" -lt 100 ]; then
  printf 'COULD NOT CHECK: the extraction has collapsed (%s shell, %s go, %s lines).\n' \
    "$shell_files" "$go_files" "$lines"
  printf '                 This is a broken check, not a clean result.\n'
  exit 2
fi

printf '\n'
if "$CSPELL" lint --no-progress --no-summary --config "$CONFIG" "$OUT"; then
  printf '\nPASS: every word an operator reads is US English or a listed term.\n'
  exit 0
fi

printf '\n'
printf 'FAIL: a word above is printed to an operator and is not US English.\n'
printf '      Line numbers are into the extracted text, not the script: grep the\n'
printf '      word in the repository to find it.\n'
exit 1
