/* =============================================================================
 * test/runner.c
 * Central test runner.
 * ========================================================================== */

#include "unity.h"
#include "./ascon/ascon.h"
/* #include "auxiliary/memory.h" */

int main(void)
{
    int failures = 0;

    failures += run_aead_tests();
    failures += run_hash256_tests();
    /* failures += run_memory_tests(); */

    return failures;
}
