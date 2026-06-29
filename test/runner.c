/**
 * @file      runner.c
 * @brief     Auto-generated test runner.
 * @details   Do not edit manually — regenerate with test/generators/all.py.
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
#include <string.h>
#include "./suite/ascon/ascon.h"

#define LINE_BUF_SIZE 1024
static char s_buf[LINE_BUF_SIZE];
static int  s_pos = 0;

void runner_putchar(int c)
{
    if (c == '\n')
    {
        s_buf[s_pos] = '\0';
        int print_it =
            (strstr(s_buf, ":FAIL")   != NULL) ||
            (strstr(s_buf, ":IGNORE") != NULL) ||
            (strstr(s_buf, " Tests ") != NULL) ||
            (strcmp(s_buf, "OK")   == 0)       ||
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

static int run_suite(const char *name, int (*suite)(void))
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

int main(void)
{
    int failures = 0;

    failures += run_suite("ASCON AEAD-128", run_aead_tests);
    failures += run_suite("ASCON Hash-256", run_hash256_tests);
    failures += run_suite("ASCON XOF-128", run_xof128_tests);

    printf("\n%s: %d\n", failures == 0 ? "ALL SUITES PASSED" : "SOME SUITES FAILED", failures);
    return failures;
}
