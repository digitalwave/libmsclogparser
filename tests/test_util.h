/*
This file is part of the libmsclogparser project.

Helpers for the tests ("make check"). Every test program includes
src/msclogparser.c itself, so the library and the test are always
built with the same flags (see tests/test_bounds_tiny.c).
*/

#ifndef MSCLOG_TEST_UTIL_H
#define MSCLOG_TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failed = 0;
static int checks = 0;

#define CHECK(cond, ...) do { checks++; if (!(cond)) { failed++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

// 1 if the error messages of the parsed line contain msg
static inline int has_error(logdata *l, const char *msg) {
    l->lineerrpool.currptr = l->lineerrpool.pool;
    for (int c = 0; c < l->log_entry_errors_cnt; c++) {
        msclogerr err;
        read_msclog_err(&l->lineerrpool, &err);
        if (strcmp(err.errmsg, msg) == 0) return 1;
    }
    return 0;
}

// exit code for main()
static inline int test_result(const char *name) {
    if (failed > 0) {
        printf("%s: %d of %d check(s) failed\n", name, failed, checks);
        return 1;
    }
    printf("%s: all %d checks passed\n", name, checks);
    return 0;
}

#endif
