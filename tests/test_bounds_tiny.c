/*
This file is part of the libmsclogparser project.

The bounds tests with tiny buffers, so every field and both pools hit
their limits. The sizes are defined before the library source is
included, so the library and the test see the same logdata.
MSCLOG_TEST_POOL_SIZE is only for this test, see src/msclogparser.h.
*/

#define MSCLOG_TEST_POOL_SIZE 128
#define MSCLOG_TBUFF_SIZE 128
#define MSCLOG_TLEN_SIZE 32

#include "test_bounds.c"
