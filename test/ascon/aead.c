#include "unity.h"
#include "aead.h"        
#include "verum/ascon/aead.h" 
#include <stdint.h>

void setUp(void)
{
}

void tearDown(void)
{
}

static void test_VERUM_ASCON_AEAD128_encrypt(void)
{
    const uint32_t key[4U] =
    {
        0xb1c9e631U,
        0xb35c0138U,
        0x03e6188fU,
        0xaa0f0aafU
    };
    const uint32_t nonce[4U] =
    {
        0xa06a309cU,
        0x0b0dab74U,
        0x385257e5U,
        0x672c1867U
    };
    uint8_t plaintext[64U] =
    {
        0x90U, 0xcdU, 0xc6U, 0xcaU, 0xb9U, 0x16U, 0x62U, 0xf5U,
        0x45U, 0x2eU, 0xa0U, 0xf6U, 0x29U, 0xf1U, 0x85U, 0xf4U,
        0xe0U, 0xb8U, 0xb9U, 0x1bU, 0xddU, 0xf9U, 0x4bU, 0x1eU,
        0xc0U, 0x25U, 0x4dU, 0xb4U, 0xdcU, 0x53U, 0xddU, 0xd7U,
        0x44U, 0x4eU, 0xc1U, 0xcfU, 0x07U, 0x41U, 0x67U, 0xf3U,
        0xf8U, 0x57U, 0x19U, 0xeaU, 0x6bU, 0x79U, 0xa8U, 0xf0U,
        0x04U, 0x32U, 0x9dU, 0x44U, 0x18U, 0x83U, 0xdaU, 0x87U,
        0x3eU, 0xc1U, 0xecU, 0xb1U, 0xd5U, 0x92U, 0xdfU, 0x72U
    };
    const uint8_t expected_ciphertext[64U] =
    {
        0x80U, 0x94U, 0xa7U, 0x2eU, 0x01U, 0xb2U, 0x64U, 0xd9U,
        0x89U, 0xb6U, 0xd7U, 0x5eU, 0x09U, 0x01U, 0xd2U, 0xeeU,
        0x93U, 0x26U, 0x02U, 0xafU, 0xaaU, 0xbaU, 0x51U, 0x16U,
        0x15U, 0x4dU, 0x5eU, 0xa2U, 0x78U, 0xf6U, 0xf3U, 0x22U,
        0xa7U, 0x76U, 0xa8U, 0x81U, 0x5bU, 0xe7U, 0xafU, 0xdeU,
        0x77U, 0x51U, 0x9aU, 0xc7U, 0x81U, 0x2cU, 0xd7U, 0x1eU,
        0xfbU, 0xabU, 0x23U, 0x83U, 0x19U, 0x18U, 0xb4U, 0x0cU,
        0x22U, 0x3bU, 0xe5U, 0x47U, 0x93U, 0xb6U, 0xfdU, 0xe2U
    };
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[32U] =
    {
        0x0aU, 0xf5U, 0xa7U, 0xf7U, 0x93U, 0x3fU, 0xa2U, 0x57U,
        0xd3U, 0x05U, 0x19U, 0x4aU, 0x81U, 0x46U, 0x6bU, 0xe6U,
        0x4dU, 0xdeU, 0xebU, 0x35U, 0x26U, 0x2dU, 0x59U, 0xa6U,
        0x7bU, 0x76U, 0xfdU, 0xd3U, 0x85U, 0x74U, 0x5eU, 0xb0U
    };
#endif
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};

    VERUM_ASCON_AEAD128_encrypt(key,
                                nonce,
                                state,
                                plaintext,
                                64U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                32U,
#endif
                                authentication_tag);

    printf("\nCiphertext:\n");
    for(uint32_t i = 0U; i < 64U; i++)
    {
        printf("%02X ", plaintext[i]);
        if(((i + 1U) % 16U) == 0U)
        {
            printf("\n");
        }
    }
    printf("\nExpected:\n");
    for(uint32_t i = 0U; i < 64U; i++)
    {
        printf("%02X ", expected_ciphertext[i]);
        if(((i + 1U) % 16U) == 0U)
        {
            printf("\n");
        }
    }
    printf("\n");

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext,
                                 plaintext,
                                 64U);
}

/*
 * Test vector: zero-length plaintext, zero-length associated data.
 * Source: vecs_aead_t testcase with key/nonce = 0x00..0x0F.
 *
 * Key   : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
 * Nonce : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
 * PT len: 0
 * AD len: 0
 * Tag   : E3 55 15 9F 29 29 11 F7 94 CB 14 32 A0 10 3A 8A
 */
static void test_VERUM_ASCON_AEAD128_tag_empty_msg(void)
{
    /* 16-byte key packed as big-endian uint32_t words:
     * 00010203 | 04050607 | 08090A0B | 0C0D0E0F */
    const uint32_t key[4U] =
    {
        0x00010203U,
        0x04050607U,
        0x08090A0BU,
        0x0C0D0E0FU
    };

    /* Identical layout for the nonce */
    const uint32_t nonce[4U] =
    {
        0x00010203U,
        0x04050607U,
        0x08090A0BU,
        0x0C0D0E0FU
    };

    /* Expected tag: E355159F 292911F7 94CB1432 A0103A8A */
    const uint32_t expected_tag[4U] =
    {
        0xE355159FU,
        0x292911F7U,
        0x94CB1432U,
        0xA0103A8AU
    };

    uint32_t state[10U]            = {0U};
    uint32_t authentication_tag[4U] = {0U};

    /* Empty plaintext and no associated data — only the tag is produced. */
    VERUM_ASCON_AEAD128_encrypt(key,
                                nonce,
                                state,
                                NULL,   /* plaintext  */
                                0U,     /* plaintext_len */
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                NULL,   /* associated_data */
                                0U,     /* assoc_data_len  */
#endif
                                authentication_tag);

    printf("\nTag (computed):\n");
    for(uint32_t i = 0U; i < 4U; i++)
    {
        printf("%08X ", authentication_tag[i]);
    }
    printf("\nTag (expected):\n");
    for(uint32_t i = 0U; i < 4U; i++)
    {
        printf("%08X ", expected_tag[i]);
    }
    printf("\n");

    /* Compare all 16 tag bytes (4 words × 4 bytes). */
    TEST_ASSERT_EQUAL_HEX32_ARRAY(expected_tag,
                                  authentication_tag,
                                  4U);
}

int run_aead_tests(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt);
    RUN_TEST(test_VERUM_ASCON_AEAD128_tag_empty_msg);
    return UNITY_END();
}