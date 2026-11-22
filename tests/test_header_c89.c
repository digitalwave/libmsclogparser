/*
This file is part of the libmsclogparser project.

The installed header must compile as ISO C90 too (an application can be
built with -std=c89 -pedantic-errors): make check builds this program with
these flags (tests_test_header_c89_CFLAGS in Makefile.am, and
tests/run-tests.sh). It only includes the header and uses its types.
*/

#include <stdio.h>
#include "msclogparser.h"

int main(void) {
    logdata *l = NULL;
    loglinetype t = LOG_TYPE_NGINX;
    msclogerr err;

    (void)l;
    (void)t;
    (void)err;
    printf("test_header_c89: the header compiles as C90 (logdata is %lu bytes)\n", (unsigned long)sizeof(logdata));
    return 0;
}
