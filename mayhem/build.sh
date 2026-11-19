#!/usr/bin/env bash
#
# mayhem/build.sh — build fizz's fuzz harnesses and its gtest suite.
#
# 1) mayhem/build-fuzz: upstream's fizz/CMakeLists.txt (pulled in by
#    mayhem/harnesses/CMakeLists.txt) compiled with $SANITIZER_FLAGS, SanCov
#    (-fsanitize=fuzzer-no-link) and DWARF 3, plus one libFuzzer binary and one
#    standalone reproducer per mayhem/harnesses/fizz_*.cpp -> mayhem/out/.
# 2) mayhem/build-tests: fizz/ configured with BUILD_TESTS=ON and the project's
#    normal flags; the gtest binaries mayhem/test.sh runs.
#
# Dependencies come from apt and from /opt/toolchains/deps (folly, fmt, libaegis, liboqs;
# see mayhem/Dockerfile), so a re-run needs no network.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${FIZZ_DEPS_PREFIX:?FIZZ_DEPS_PREFIX must name the folly/fmt/aegis/liboqs prefixes (set by mayhem/Dockerfile)}"
export CC CXX

cd "$SRC"
M="$SRC/mayhem"
mkdir -p "$M/build-fuzz" "$M/out"

# --- 1) sanitized fizz + harnesses -------------------------------------------
# Every fuzz and -standalone binary also links mayhem/lsan_off.cc (LeakSanitizer
# off at build time; ASan/UBSan stay on).
FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -x c -c "$STANDALONE_FUZZ_MAIN" -o "$M/build-fuzz/standalone_main.o"

cmake -S "$M/harnesses" -B "$M/build-fuzz" -G Ninja \
  -DCMAKE_BUILD_TYPE=None \
  -DCMAKE_PREFIX_PATH="$FIZZ_DEPS_PREFIX" \
  -DCMAKE_C_FLAGS="$FUZZ_FLAGS" \
  -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS -O1" \
  -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
  -DSTANDALONE_MAIN_OBJ="$M/build-fuzz/standalone_main.o" \
  -DHARNESS_OUT_DIR="$M/out" \
  -DLSAN_OFF_SRC="$M/lsan_off.cc"
cmake --build "$M/build-fuzz" -j"$MAYHEM_JOBS"
# The full build: every optional backend upstream's getdeps build has must be on.
for f in FIZZ_HAVE_OQS FIZZ_HAVE_LIBAEGIS FIZZ_HAVE_SODIUM; do
  grep -rqs "^#define $f 1" "$M/build-fuzz" --include=fizz-config.h \
    || { echo "$f is off in the fuzz build (missing dependency?)" >&2; exit 1; }
done

# --- 2) the upstream gtest suite, normal flags -------------------------------
# Every add_gtest() target upstream registers (fizz/CMakeLists.txt), the same
# set upstream CI runs through ctest. The list mayhem/test.sh runs is read back
# from ctest's own registry, so it tracks upstream's CMakeLists as it changes.
cmake -S "$SRC/fizz" -B "$M/build-tests" -G Ninja \
  -DCMAKE_PREFIX_PATH="$FIZZ_DEPS_PREFIX" \
  -DBUILD_TESTS=ON -DBUILD_EXAMPLES=OFF \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$COVERAGE_FLAGS"
cmake --build "$M/build-tests" -j"$MAYHEM_JOBS"
(cd "$M/build-tests" && ctest -N) | sed -n 's/^ *Test *#[0-9]*: *\([^ ]*\).*/\1/p' \
  > "$M/build-tests/mayhem-tests.txt"
n=$(wc -l < "$M/build-tests/mayhem-tests.txt")
[ "$n" -gt 0 ] || { echo "no gtest targets registered in $M/build-tests" >&2; exit 1; }
echo "registered gtest binaries: $n"

ls -l "$M/out"
