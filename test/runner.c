/**
 * @file      runner.c
 * @brief     Auto-generated test runner.
 * @details   Do not edit manually — regenerate with scripts/test/generators/all.py.
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */

#include "unity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "define.h"
#include "macro.h"
#include "./suite/ascon/ascon.h"

VERUM_ATTR_NORETURN void VERUM_FAULT_HANDLER(void);
VERUM_ATTR_NORETURN void VERUM_FAULT_HANDLER(void)
{
    fprintf(stderr, "\n[FATAL] VERUM_FAULT_HANDLER invoked: FIPS 140-3 fault detected!\n");
    abort();
}

#define LINE_BUF_SIZE 1024
static char s_buf[LINE_BUF_SIZE];
static int s_pos = 0;

void runner_putchar(int c)
{
    if (c == '\n')
    {
        s_buf[s_pos] = '\0';
        int print_it =
            (strstr(s_buf, ":FAIL") != NULL) ||
            (strstr(s_buf, ":IGNORE") != NULL) ||
            (strstr(s_buf, " Tests ") != NULL) ||
            (strcmp(s_buf, "OK") == 0) ||
            (strcmp(s_buf, "FAIL") == 0);
        if (print_it)
        {
            puts(s_buf);
            fflush(stdout);
        }
        s_pos = 0;
    }
    else
    {
        if (s_pos < LINE_BUF_SIZE - 1)
        {
            s_buf[s_pos++] = (char) c;
        }
    }
}

static int run_suite(const char *name,
                     int (*suite)(void))
{
    printf("\n=== %-40s ===\n", name);
    fflush(stdout);
    int result = suite();
    printf("=== %-40s ===\n", result == 0 ? "PASSED" : "FAILED");
    fflush(stdout);
    return result;
}

void setUp(void)
{
}

void tearDown(void)
{
}

int run_aead_tests(void);
int run_hash256_tests(void);
int run_xof128_tests(void);
int run_cxof128_tests(void);
#ifdef VERUM_STANDARD_FIPS_140_3_DEF
int run_fips1403_tests(void);
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */

int main(void)
{
    int failures = 0;

    failures += run_suite("ASCON AEAD-128", run_aead_tests);
    failures += run_suite("ASCON Hash-256", run_hash256_tests);
    failures += run_suite("ASCON XOF-128", run_xof128_tests);
    failures += run_suite("ASCON CXOF-128", run_cxof128_tests);
#ifdef VERUM_STANDARD_FIPS_140_3_DEF
    failures += run_suite("ASCON FIPS 140-3 Self-Tests", run_fips1403_tests);
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */

    printf("\n%s: %d\n", failures == 0 ? "ALL SUITES PASSED" : "SOME SUITES FAILED", failures);
    return failures;
}
