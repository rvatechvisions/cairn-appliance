#!/usr/bin/env bash
#
# Run every test in this repository and state the denominator.
#
# ## Why this exists
#
# There was no runner here. Seven test scripts, each started by hand, and
# **the one that would have caught the 22 September defect was written the day
# after it** -- a check nobody reaches for is a rule again.
#
# It earned its keep on its first run, which is the argument for it:
# `enrol-secret-test.sh` had been **unable to look at its subject** because Go
# was not on the PATH. It refused correctly, exit 2, and said so -- and nobody
# would ever have seen that, because nothing ran it.
#
# ## The three things it refuses to do
#
# **It discovers rather than lists.** A hand-maintained list of test scripts is
# a second description of the set, free to lag the directory by exactly one
# file -- which is the file somebody just added.
#
# **It runs every one before reporting**, rather than stopping at the first
# failure. A run that stops early states a denominator it did not reach, and
# `2 of 7` read as `2 of 2` is the whole of the class this repository keeps
# tripping over.
#
# **It counts could-not-run apart from failed.** Every harness here exits 2
# when it could not look at its subject and 1 when it looked and found
# something wrong. Those are opposite messages: the first is a broken check and
# the second is a finding, and a runner that prints one number for both is the
# collapse they were each written against.
#
# And a run that found no tests exits non-zero: there is no reading of "nothing
# to run" that is a clean result.
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE" || { printf 'FATAL: cannot enter %s\n' "$HERE"; exit 2; }

attempted=0
passed=0
failed=0
unrunnable=0
failures=''
could_not_run=''

for test in *-test.sh; do
  [ -f "$test" ] || continue
  attempted=$((attempted + 1))

  printf '\n===== %s =====\n' "$test"

  # Started with `bash` deliberately: these are harnesses a person or this
  # runner invokes, never something the runbook tells an operator to type, so
  # their committed mode is not load-bearing. The scripts whose mode IS
  # load-bearing are asserted by script-modes-test.sh, which is in this set.
  bash "$test"
  status=$?

  case "$status" in
    0)
      passed=$((passed + 1))
      ;;
    2)
      unrunnable=$((unrunnable + 1))
      could_not_run="${could_not_run}  ${test}"$'\n'
      ;;
    *)
      failed=$((failed + 1))
      failures="${failures}  ${test} (exit ${status})"$'\n'
      ;;
  esac
done

printf '\n==================================================\n'
printf 'test scripts attempted: %s, passed: %s, failed: %s, could not run: %s\n' \
  "$attempted" "$passed" "$failed" "$unrunnable"

if [ "$attempted" -eq 0 ]; then
  printf 'FAIL: no test script matched *-test.sh, so this run is evidence about nothing.\n'
  exit 2
fi

if [ "$unrunnable" -ne 0 ]; then
  printf '\ncould not run -- a broken check, not a clean result:\n%s' "$could_not_run"
fi

if [ "$failed" -ne 0 ]; then
  printf '\nfailed:\n%s' "$failures"
fi

# A harness that could not look is a failure of this run, reported as one.
if [ "$failed" -ne 0 ] || [ "$unrunnable" -ne 0 ]; then
  exit 1
fi

printf 'PASS: all %s test scripts ran and passed.\n' "$attempted"
