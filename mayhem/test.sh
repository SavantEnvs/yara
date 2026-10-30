#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
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

# yara's own suite is a set of statically-linked test-* programs (each asserts with its own checks and
# exits non-zero on failure), built by build.sh under mayhem/build-test. They are static, so a neutered
# (exit(0)) program cannot disturb them — hence the known-answer probes through the dynamically linked
# `yara`/`yarac` CLI below, whose exact output is compared in bash.
BUILD="$SRC/mayhem/build-test"
KAT="$SRC/mayhem/kat"
YARA="$BUILD/yara"
YARAC="$BUILD/yarac"
passed=0 failed=0

for exe in "$YARA" "$YARAC"; do
  [ -x "$exe" ] || { echo "FATAL: $exe missing (build.sh should have built it)" >&2; emit_ctrf yara 0 1 0; exit 1; }
done

tests="$(find "$BUILD" -maxdepth 1 -type f -name 'test-*' -perm -u+x | sort)"
[ -n "$tests" ] || { echo "FATAL: no test-* programs in $BUILD (build.sh should have built them)" >&2; emit_ctrf yara 0 1 0; exit 1; }

for t in $tests; do
  # Like `make check`: run from the build dir (test-rules spawns ./tests/mapper) with TOP_SRCDIR set.
  if (cd "$BUILD" && TOP_SRCDIR="$SRC" TOP_BUILDDIR="$BUILD" "$t" >/tmp/yara-test.out 2>&1); then
    passed=$((passed+1)); echo "PASS $(basename "$t")"
  else
    failed=$((failed+1)); echo "FAIL $(basename "$t")"; tail -20 /tmp/yara-test.out
  fi
done

# kat <name> <expected> <actual>: exact-match known-answer assertion (unconditional).
kat() {
  if [ "$2" = "$3" ]; then passed=$((passed+1)); echo "PASS kat:$1"
  else failed=$((failed+1)); echo "FAIL kat:$1"; printf '  expected: %s\n  actual:   %s\n' "$2" "$3"; fi
}

kat string-matches \
  "$(printf 'kat_two_hellos [author="kat"] %s\n0x4:$a: hello\n0x11:$a: hello' "$KAT/hello.txt")" \
  "$("$YARA" -s -m "$KAT/kat.yar" "$KAT/hello.txt" 2>&1)"
kat match-count "1" "$("$YARA" -c "$KAT/kat.yar" "$KAT/hello.txt" 2>&1)"
kat hash-module \
  "$(printf 'kat_md5 %s\nkat_sha256 %s' tests/data/tiny tests/data/tiny)" \
  "$("$YARA" "$KAT/hash.yar" tests/data/tiny 2>&1 | sort)"
kat pe-module "kat_pe tests/data/tiny" "$("$YARA" "$KAT/pe.yar" tests/data/tiny 2>&1)"
kat pe-imports \
  "$(printf '\t\t\tlibrary_name = "KERNEL32.dll"\n\t\t\tnumber_of_functions = 21')" \
  "$("$YARA" -D "$KAT/pe.yar" tests/data/tiny 2>&1 | grep -E 'library_name|number_of_functions' | sed -n 1,2p)"
SCRATCH="$(mktemp -d)"
"$YARAC" "$KAT/kat.yar" "$SCRATCH/kat.yarc" >/dev/null 2>&1
kat compiled-rules "1" "$("$YARA" -C -c "$SCRATCH/kat.yarc" "$KAT/hello.txt" 2>&1)"
rm -rf "$SCRATCH"

emit_ctrf "yara-test-programs+kat" "$passed" "$failed" 0
