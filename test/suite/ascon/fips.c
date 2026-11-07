/**
 * @file      fips.c
 * @brief     FIPS 140-3 Power-On Self-Tests (POST) test suite.
 * @details   Validates Ascon AEAD128, Hash256, XOF128, and CXOF128 self-tests.
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
#include "define.h"
#include "verum/ascon/aead.h"
#include "verum/ascon/hash.h"
#include "verum/ascon/xof.h"
#include "verum/ascon/cxof.h"

#ifdef VERUM_STANDARD_FIPS_140_3_DEF

static void test_VERUM_FIPS1403_ASCON_AEAD128_self_test(void)
{
    TEST_ASSERT_EQUAL_UINT32(0U, VERUM_FIPS1403_ASCON_AEAD128_self_test());
}

static void test_VERUM_FIPS1403_ASCON_HASH256_self_test(void)
{
    TEST_ASSERT_EQUAL_UINT32(0U, VERUM_FIPS1403_ASCON_HASH256_self_test());
}

static void test_VERUM_FIPS1403_ASCON_XOF128_self_test(void)
{
    TEST_ASSERT_EQUAL_UINT32(0U, VERUM_FIPS1403_ASCON_XOF128_self_test());
}

static void test_VERUM_FIPS1403_ASCON_CXOF128_self_test(void)
{
    TEST_ASSERT_EQUAL_UINT32(0U, VERUM_FIPS1403_ASCON_CXOF128_self_test());
}

int run_fips1403_tests(void);
int run_fips1403_tests(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_VERUM_FIPS1403_ASCON_AEAD128_self_test);
    RUN_TEST(test_VERUM_FIPS1403_ASCON_HASH256_self_test);
    RUN_TEST(test_VERUM_FIPS1403_ASCON_XOF128_self_test);
    RUN_TEST(test_VERUM_FIPS1403_ASCON_CXOF128_self_test);
    return UNITY_END();
}

#else /* VERUM_STANDARD_FIPS_140_3_DEF */

typedef int verum_fips_non_compliant_translation_unit_t;

#endif /* VERUM_STANDARD_FIPS_140_3_DEF */
