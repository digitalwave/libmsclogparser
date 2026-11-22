#!/bin/sh
# Builds and runs the test programs of "make check" without configure,
# e.g. with sanitizers or on a system where configure doesn't run:
#
#   tests/run-tests.sh
#   CFLAGS="-g -fsanitize=address,undefined" tests/run-tests.sh
#
# The list of programs is check_PROGRAMS in Makefile.am; each one is a
# single source file (tests/NAME.c) that includes src/msclogparser.c, except
# tests/test_header_c89.c, which includes only the header.

set -e
cd "$(dirname "$0")/.."
CC=${CC:-cc}
CFLAGS=${CFLAGS:-"-g -O1"}
OUT=${TMPDIR:-/tmp}/msclogparser-test-$$
trap 'rm -f "$OUT"' EXIT

PROGRAMS=$(sed -n 's/^check_PROGRAMS *= *//p' Makefile.am)
[ -n "$PROGRAMS" ] || { echo "no check_PROGRAMS in Makefile.am" >&2; exit 1; }

for p in $PROGRAMS; do
    echo "== $p"
    # the header test is built as ISO C90 (tests_test_header_c89_CFLAGS)
    STD=""
    case "$p" in *_c89) STD="-std=c89 -pedantic-errors" ;; esac
    $CC $CFLAGS $STD -Wall -Isrc -o "$OUT" "$p.c"
    "$OUT"
done
