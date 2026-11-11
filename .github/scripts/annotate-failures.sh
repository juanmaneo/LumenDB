#!/bin/sh
# usage: annotate-failures.sh COMMAND...
#
# Runs COMMAND, passing its output through. When it fails, every failing test
# and panic message becomes an `::error::` annotation: annotations show on the
# run page and in the API, where the log of a failed job can be hard to reach.
# The exit status is COMMAND's.
log="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/annotate-failures.$$"
{ "$@"; echo $? > "$log.status"; } 2>&1 | tee "$log.out"
status=$(cat "$log.status")
if [ "$status" -ne 0 ]; then
  # (the colors cargo is asked for would hide the word FAILED from grep)
  esc=$(printf '\033')
  sed "s/$esc\[[0-9;]*m//g" "$log.out" | grep -E '^test .* \.\.\. FAILED$|panicked at ' | sort -u | head -n 20 |
    while IFS= read -r line; do
      echo "::error title=failing test::$line"
    done
fi
rm -f "$log.status" "$log.out"
exit "$status"
