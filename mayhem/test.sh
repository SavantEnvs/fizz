#!/usr/bin/env bash
#
# mayhem/test.sh — RUN fizz's own gtest suite (the binaries mayhem/build.sh built into
# mayhem/build-tests/bin, listed in mayhem/build-tests/mayhem-tests.txt). exit 0 = pass. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Each gtest binary prints "[  PASSED  ] N tests." and, on failure, "[  FAILED  ] N tests, ...".
# Counts come from those summary lines, not exit codes: a binary that prints no summary (crashed,
# or neutered into a no-op) counts as one failure.
BIN="$SRC/mayhem/build-tests/bin"
LIST="$SRC/mayhem/build-tests/mayhem-tests.txt"
[ -f "$LIST" ] || { echo "missing $LIST — run mayhem/build.sh first" >&2; emit_ctrf gtest 0 1 0; exit 1; }
passed=0 failed=0 skipped=0
while read -r t; do
  [ -n "$t" ] || continue
  if [ ! -x "$BIN/$t" ]; then
    echo "MISSING test binary $BIN/$t" >&2; failed=$((failed + 1)); continue
  fi
  out=$(cd "$SRC/fizz" && "$BIN/$t" --gtest_color=no 2>&1); rc=$?
  p=$(printf '%s\n' "$out" | sed -n 's/^\[  PASSED  \] \([0-9]*\) tests\{0,1\}\..*/\1/p' | tail -1)
  f=$(printf '%s\n' "$out" | sed -n 's/^\[  FAILED  \] \([0-9]*\) tests\{0,1\}, listed below.*/\1/p' | tail -1)
  s=$(printf '%s\n' "$out" | sed -n 's/^\[  SKIPPED \] \([0-9]*\) tests\{0,1\}, listed below.*/\1/p' | tail -1)
  if [ -z "$p" ]; then
    echo "$t: no gtest summary (rc=$rc)"; printf '%s\n' "$out" | tail -20
    failed=$((failed + 1)); continue
  fi
  passed=$((passed + p)); failed=$((failed + ${f:-0})); skipped=$((skipped + ${s:-0}))
  [ "$rc" -eq 0 ] || [ -n "$f" ] || { echo "$t: exit $rc with no failures listed"; failed=$((failed + 1)); }
  echo "$t: passed=$p failed=${f:-0} skipped=${s:-0}"
  [ -z "$f" ] || printf '%s\n' "$out" | grep '^\[  FAILED  \]'
done < "$LIST"
emit_ctrf gtest "$passed" "$failed" "$skipped"
