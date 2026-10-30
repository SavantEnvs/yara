#!/usr/bin/env bash
#
# mayhem/build.sh — build yara's sanitized fuzz harnesses (upstream's tests/oss-fuzz/*_fuzzer.cc)
# AND the project's own test suite (normal flags). Runs in the commit image as `mayhem` in /mayhem.
# Re-runnable and offline: only bootstrap (autoreconf) + configure + make; nothing is fetched.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Same module set OSS-Fuzz builds (dotnet/macho/dex) plus OpenSSL for pe/hash.
CONFIG_FLAGS="--enable-dotnet --enable-macho --enable-dex --with-crypto --disable-shared"

# Generates configure/Makefile.in in-tree (all gitignored upstream); the builds below are out-of-tree
# under mayhem/build-* (gitignored by mayhem/.gitignore) so the two never share objects.
sh ./bootstrap.sh

# Relaxed UBSan check (everything else stays on and halting): -fsanitize=function fires on every scan
# that initializes the hash module — libyara/hash.c registers yr_object_destroy (int (*)(YR_OBJECT*)) as
# a void-pointer-argument destructor callback — a benign C idiom that aborts all harnesses at startup.
RELAX="-fno-sanitize=function"

# 1) Sanitized + instrumented library. fuzzer-no-link adds SanCov to the library itself (the
#    engine only covers the harness TU), and stays on when SANITIZER_FLAGS is empty.
FUZZ_BUILD="$SRC/mayhem/build-fuzz"
mkdir -p "$FUZZ_BUILD"
(
  cd "$FUZZ_BUILD"
  "$SRC/configure" $CONFIG_FLAGS CC="$CC" CXX="$CXX" \
    CFLAGS="$SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -fsanitize=fuzzer-no-link" \
    LDFLAGS="$SANITIZER_FLAGS $RELAX"
  make -j"$MAYHEM_JOBS" libyara.la
)

# 2) Harnesses: libFuzzer binary + standalone run-once reproducer, both with LSan switched off.
BIN="$SRC/mayhem/bin"
mkdir -p "$BIN"
LIBS_LINK="$(sed -n 's/^LIBS = //p' "$FUZZ_BUILD/Makefile")"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$BIN/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$BIN/standalone_main.o"
for src in "$SRC"/tests/oss-fuzz/*_fuzzer.cc; do
  name="$(basename "$src" .cc)"
  $CXX $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -I"$SRC/libyara/include" "$src" \
    $LIB_FUZZING_ENGINE "$BIN/lsan_off.o" "$FUZZ_BUILD/.libs/libyara.a" $LIBS_LINK \
    -o "$BIN/$name"
  $CXX $SANITIZER_FLAGS $RELAX $DEBUG_FLAGS -I"$SRC/libyara/include" "$src" \
    "$BIN/standalone_main.o" "$BIN/lsan_off.o" "$FUZZ_BUILD/.libs/libyara.a" $LIBS_LINK \
    -o "$BIN/$name-standalone"
done

# 3) Oracle build: upstream's test programs and the yara CLI with NORMAL flags (no sanitizer, no
#    -gdwarf-3), so test.sh only runs them.
TEST_BUILD="$SRC/mayhem/build-test"
mkdir -p "$TEST_BUILD"
(
  cd "$TEST_BUILD"
  env -u CFLAGS -u CXXFLAGS -u LDFLAGS "$SRC/configure" $CONFIG_FLAGS CC="$CC" CXX="$CXX" \
    CFLAGS="$COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS"
  make -j"$MAYHEM_JOBS"
  make -j"$MAYHEM_JOBS" check TESTS=
)
