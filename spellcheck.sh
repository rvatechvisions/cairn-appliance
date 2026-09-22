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
# The text these programs PRINT, not their code. A shell variable name and a Go
# identifier are not read as English by anybody, and checking them would produce
# noise that teaches a reader to skip the result.
#
#   - `say`, `rule`, `step`, `echo` and `printf` in every tracked shell script
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
  grep -hoE '(^|[[:space:]])(say|rule|step|echo|printf)[[:space:]]+["'"'"'][^"'"'"']*' "$file" \
    | sed -E 's/^[[:space:]]*(say|rule|step|echo|printf)[[:space:]]+["'"'"']//' \
    | sed -E 's/\$\{[^}]*\}/ /g; s/\$[A-Za-z_][A-Za-z0-9_]*/ /g' \
    | sed -E 's/%-?[0-9]*[a-zA-Z]/ /g; s/\\[nrt]/ /g' \
    >> "$OUT"
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
