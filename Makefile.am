
AM_CLFAGS = -O0 -g -Wall
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = . src examples bindings

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = msclogparser.pc

# Tests: make check. Each test program includes src/msclogparser.c, so the
# library and the test are built with the same flags (the tiny build defines
# its buffer sizes in tests/test_bounds_tiny.c). tests/run-tests.sh builds
# the same list without configure, e.g. with sanitizers.
check_PROGRAMS = tests/test_bounds tests/test_bounds_tiny tests/test_warning_msg
tests_test_bounds_SOURCES = tests/test_bounds.c tests/test_util.h
tests_test_bounds_tiny_SOURCES = tests/test_bounds_tiny.c tests/test_util.h
tests_test_warning_msg_SOURCES = tests/test_warning_msg.c tests/test_util.h
TESTS = $(check_PROGRAMS)
EXTRA_DIST = tests/run-tests.sh
