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


const uint8_t key[16U] =
{
    0x78U,0xb3U,0x8eU,0x1eU,
    0xf3U,0x60U,0xe7U,0xa2U,
    0xd6U,0x04U,0xa8U,0xa2U,
    0x98U,0x35U,0xf8U,0x40U
};

const uint8_t nonce[16U] =
{
    0x73,0x26,0x1b,0x4f,0x3b,0x26,0x29,0x0e,0xcf,0x23,0x73,0xae,0x9d,0xaf,0xba,0x43
    
};
    uint8_t plaintext[64U] =
    {
        0x61,
        0x73,
        0x63,
        0x6f,
        0x6e
    };
    const uint8_t expected_ciphertext[64U] =
    {
        0x94, 0x31, 0xb8, 0x36, 0xd4

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

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                plaintext,
                                5U,
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
 const uint32_t key[4U] =
{
    0xa2e760f3U,
    0x1e8eb378U,
    0x40f83598U,
    0xa2a804d6U,
};

const uint32_t nonce[4U] =
{
    0x0e29263bU,
    0x4f1b2673U,
    0x43baaf9dU,
    0xae7323cfU,
    
};
    uint8_t plaintext[64U] =
    {
        0x61,
        0x73,
        0x63,
        0x6f,
        0x6e
    };
    const uint8_t expected_ciphertext[64U] =
    {
        0x94, 0x31, 0xb8, 0x36, 0xd4

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
                                5U,
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

    printf("\nTag (computed):\n");
    for(uint32_t i = 0U; i < 4U; i++)
    {
        printf("%08X ", authentication_tag[i]);
    }

    uint32_t expected_tag[4U] =
    {
        0x2a6297dcU,
        0x3bac1d88U,
        0x0355e503U,
        0x31d6cebeU
    };
    printf("\nTag (expected):\n");
    for(uint32_t i = 0U; i < 4U; i++)
    {
        printf("%08X ", expected_tag[i]);
    }
    printf("\n");

    /* Compare all 16 tag bytes (4 words × 4 bytes). */
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag,
                                  authentication_tag,
                                  16U);
}

static void test_kat(void)
{
 const uint8_t key[16U] =
{
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
};

 const uint8_t nonce[16U] =
{
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B,
    0x0C, 0x0D, 0x0E, 0x0F
};
    uint8_t plaintext[16U];
    const uint8_t expected_ciphertext[16U] =
    {
        0x44, 0x27, 0xD6, 0x4B, 0x8E, 0x1E, 0x14, 0x51,
        0xFC, 0x44, 0x59, 0x60, 0xF0, 0x83, 0x9B, 0xB0
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

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*const)key,
                                (const uint32_t* const)nonce,
                                state,
                                plaintext,
                                16U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                32U,
#endif
                                authentication_tag);

    printf("\nCiphertext:\n");
    for(uint32_t i = 0U; i < 16U; i++)
    {
        printf("%02X ", plaintext[i]);
        if(((i + 1U) % 16U) == 0U)
        {
            printf("\n");
        }
    }
    printf("\nExpected:\n");
    for(uint32_t i = 0U; i < 16U; i++)
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
                                 16U);

    
}

int run_aead_tests(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt);
    RUN_TEST(test_VERUM_ASCON_AEAD128_tag_empty_msg);
    RUN_TEST(test_kat);
    return UNITY_END();
}