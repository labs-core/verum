#include "unity.h"
#include "aead.h"
#include "verum/ascon/aead.h"
#include <stdint.h>
#include <stdio.h>

void setUp(void) {}
void tearDown(void) {}

static void print_hex(const char *label, const uint8_t *data, uint32_t len)
{
    printf("%s\n", label);
    for (uint32_t i = 0U; i < len; i++)
    {
        printf("%02X ", data[i]);
        if (((i + 1U) % 16U) == 0U)
        {
            printf("\n");
        }
    }
    printf("\n");
}

#ifndef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
static void test_VERUM_ASCON_AEAD128_base_encrypt(void)
{
    const uint8_t key[16U] =
    {
        0x78U, 0xB3U, 0x8EU, 0x1EU,
        0xF3U, 0x60U, 0xE7U, 0xA2U,
        0xD6U, 0x04U, 0xA8U, 0xA2U,
        0x98U, 0x35U, 0xF8U, 0x40U
    };
    const uint8_t nonce[16U] =
    {
        0x73U, 0x26U, 0x1BU, 0x4FU,
        0x3BU, 0x26U, 0x29U, 0x0EU,
        0xCFU, 0x23U, 0x73U, 0xAEU,
        0x9DU, 0xAFU, 0xBAU, 0x43U
    };
    uint8_t plaintext[5U] =
    {
        0x61U, 0x73U, 0x63U, 0x6FU, 0x6EU
    };
    const uint8_t expected_ciphertext[5U] =
    {
        0x94U, 0x31U, 0xB8U, 0x36U, 0xD4U
    };
    const uint8_t expected_tag[16U] =
    {
        0x88U, 0x1DU, 0xACU, 0x3BU,
        0xDCU, 0x97U, 0x62U, 0x2AU,
        0xBEU, 0xCEU, 0xD6U, 0x31U,
        0x03U, 0xE5U, 0x55U, 0x03U
    };
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[32U] =
    {
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U,
        0x00U, 0x00U, 0x00U, 0x00U
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

    print_hex("Ciphertext got:", plaintext, 5U);
    print_hex("Ciphertext expected:", expected_ciphertext, 5U);
    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, 5U);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}

static void test_VERUM_ASCON_AEAD128_encrypt_empty_pt_empty_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t expected_tag[16U] =
    {
        0x44U, 0x27U, 0xD6U, 0x4BU,
        0x8EU, 0x1EU, 0x14U, 0x51U,
        0xFCU, 0x44U, 0x59U, 0x60U,
        0xF0U, 0x83U, 0x9BU, 0xB0U
    };
    uint8_t dummy[1U] = {0U};
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[1U] = {0U};
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                dummy,
                                0U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                0U,
#endif
                                authentication_tag);

    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}

static void test_VERUM_ASCON_AEAD128_encrypt_one_byte_pt_empty_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    uint8_t plaintext[1U] = {0x00U};
    const uint8_t expected_ciphertext[1U] = {0xE7U};
    const uint8_t expected_tag[16U] =
    {
        0x9FU, 0x58U, 0xF1U, 0xF5U,
        0x41U, 0xFCU, 0x51U, 0xB5U,
        0xD4U, 0x38U, 0xF8U, 0xE1U,
        0xDDU, 0x03U, 0xF1U, 0x47U
    };
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[1U] = {0U};
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                plaintext,
                                1U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                0U,
#endif
                                authentication_tag);

    print_hex("Ciphertext got:", plaintext, 1U);
    print_hex("Ciphertext expected:", expected_ciphertext, 1U);
    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, 1U);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}



static void test_VERUM_ASCON_AEAD128_encrypt_two_byte_pt_empty_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    uint8_t plaintext[2U] = {0x00U, 0x01U};
    const uint8_t expected_ciphertext[2U] = {0xE7U, 0x70U};
    const uint8_t expected_tag[16U] =
    {
        0x02U, 0x4EU, 0xF7U, 0x89U,
        0x5CU, 0x32U, 0x5CU, 0xBEU,
        0x02U, 0xEBU, 0x5FU, 0xBEU,
        0x6FU, 0x9DU, 0x7EU, 0x8DU
    };
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[1U] = {0U};
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                plaintext,
                                2U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                0U,
#endif
                                authentication_tag);

    print_hex("Ciphertext got:", plaintext, 2U);
    print_hex("Ciphertext expected:", expected_ciphertext, 2U);
    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, 2U);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}

static void test_VERUM_ASCON_AEAD128_encrypt_sixteen_byte_pt_empty_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    uint8_t plaintext[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t expected_ciphertext[16U] =
    {
        0xE7U, 0x70U, 0xD2U, 0x89U,
        0xD2U, 0xA4U, 0x4AU, 0xEEU,
        0x7CU, 0xD0U, 0xA4U, 0x8EU,
        0xCEU, 0x52U, 0x74U, 0xE3U
    };
    const uint8_t expected_tag[16U] =
    {
        0xEAU, 0x72U, 0x1FU, 0x9AU,
        0x8FU, 0xC4U, 0xE5U, 0x56U,
        0xF2U, 0x74U, 0x59U, 0x72U,
        0xF5U, 0xA7U, 0x84U, 0x11U
    };
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[1U] = {0U};
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                plaintext,
                                16U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                0U,
#endif
                                authentication_tag);

    print_hex("Ciphertext got:", plaintext, 16U);
    print_hex("Ciphertext expected:", expected_ciphertext, 16U);
    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, 16U);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}


static void test_VERUM_ASCON_AEAD128_encrypt_thirtytwo_byte_pt_empty_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    uint8_t plaintext[32U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU,
        0x10U, 0x11U, 0x12U, 0x13U,
        0x14U, 0x15U, 0x16U, 0x17U,
        0x18U, 0x19U, 0x1AU, 0x1BU,
        0x1CU, 0x1DU, 0x1EU, 0x1FU
    };
    const uint8_t expected_ciphertext[32U] =
    {
        0xE7U, 0x70U, 0xD2U, 0x89U,
        0xD2U, 0xA4U, 0x4AU, 0xEEU,
        0x7CU, 0xD0U, 0xA4U, 0x8EU,
        0xCEU, 0x52U, 0x74U, 0xE3U,
        0x81U, 0xBAU, 0xD7U, 0xE1U,
        0x63U, 0xDCU, 0xC4U, 0x97U,
        0x0FU, 0x78U, 0x73U, 0x61U,
        0x0DU, 0xEBU, 0xBEU, 0xB1U
    };
    const uint8_t expected_tag[16U] =
    {
        0xA2U, 0x86U, 0x57U, 0xF6U,
        0xE8U, 0x2FU, 0xE5U, 0x3DU,
        0x08U, 0xB0U, 0x9EU, 0xFFU,
        0x93U, 0x30U, 0xBDU, 0x2BU
    };
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[1U] = {0U};
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                plaintext,
                                32U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                0U,
#endif
                                authentication_tag);

    print_hex("Ciphertext got:", plaintext, 32U);
    print_hex("Ciphertext expected:", expected_ciphertext, 32U);
    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, 32U);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}




static void test_VERUM_ASCON_AEAD128_encrypt_seventeen_byte_pt_empty_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    uint8_t plaintext[17U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU,
        0x10U
    };
    const uint8_t expected_ciphertext[17U] =
    {
        0xE7U, 0x70U, 0xD2U, 0x89U,
        0xD2U, 0xA4U, 0x4AU, 0xEEU,
        0x7CU, 0xD0U, 0xA4U, 0x8EU,
        0xCEU, 0x52U, 0x74U, 0xE3U,
        0x81U
    };
    const uint8_t expected_tag[16U] =
    {
        0xA6U, 0x13U, 0x2EU, 0x1DU,
        0x1BU, 0x07U, 0x2BU, 0x1FU,
        0x10U, 0x38U, 0x17U, 0xB2U,
        0xD4U, 0x54U, 0x70U, 0x0DU
    };
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[1U] = {0U};
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                plaintext,
                                17U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                0U,
#endif
                                authentication_tag);

    print_hex("Ciphertext got:", plaintext, 17U);
    print_hex("Ciphertext expected:", expected_ciphertext, 17U);
    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, 17U);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}



#else
static void test_VERUM_ASCON_AEAD128_encrypt_empty_pt_sixteen_byte_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t expected_tag[16U] =
    {
        0xB7U, 0x47U, 0xD3U, 0x23U,
        0x5EU, 0x97U, 0x1CU, 0x20U,
        0xD0U, 0x0DU, 0xCFU, 0x87U,
        0x40U, 0x69U, 0x38U, 0xFDU
    };
    uint8_t dummy[1U] = {0U};
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                dummy,
                                0U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                16U,
#endif
                                authentication_tag);

    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}

static void test_VERUM_ASCON_AEAD128_encrypt_one_byte_pt_one_byte_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    uint8_t plaintext[1U] = {0x00U};
    const uint8_t expected_ciphertext[1U] = {0x25U};
    const uint8_t expected_tag[16U] =
    {
        0xEBU, 0x4BU, 0x70U, 0x0EU,
        0xD4U, 0xACU, 0x85U, 0x17U,
        0xDCU, 0xBAU, 0x20U, 0xF6U,
        0x73U, 0x29U, 0x22U, 0x30U
    };
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[1U] = {0x00U};
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                plaintext,
                                1U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                1U,
#endif
                                authentication_tag);

    print_hex("Ciphertext got:", plaintext, 1U);
    print_hex("Ciphertext expected:", expected_ciphertext, 1U);
    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, 1U);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}

static void test_VERUM_ASCON_AEAD128_encrypt_one_byte_pt_ten_byte_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    uint8_t plaintext[1U] = {0x00U};
    const uint8_t expected_ciphertext[1U] = {0xF2U};
    const uint8_t expected_tag[16U] =
    {
        0xCEU, 0xE4U, 0xC2U, 0x1CU,
        0x5EU, 0x8BU, 0xE4U, 0x7CU,
        0x62U, 0x80U, 0x1CU, 0xF8U,
        0xF9U, 0x9CU, 0x0FU, 0x68U
    };
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[10U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U
    };
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                plaintext,
                                1U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                10U,
#endif
                                authentication_tag);

    print_hex("Ciphertext got:", plaintext, 1U);
    print_hex("Ciphertext expected:", expected_ciphertext, 1U);
    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, 1U);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}

static void test_VERUM_ASCON_AEAD128_encrypt_sixteen_byte_pt_sixteen_byte_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    uint8_t plaintext[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t expected_ciphertext[16U] =
    {
        0x6AU, 0x28U, 0x21U, 0x5EU,
        0x4AU, 0x60U, 0x23U, 0xFAU,
        0xE4U, 0x20U, 0x95U, 0x31U,
        0x8BU, 0x18U, 0x7FU, 0x99U
    };
    const uint8_t expected_tag[16U] =
    {
        0xE0U, 0xC4U, 0x79U, 0x77U,
        0x1AU, 0x09U, 0xB5U, 0xD2U,
        0x9AU, 0xFDU, 0x05U, 0x82U,
        0x5BU, 0x01U, 0x3DU, 0x0DU
    };
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                plaintext,
                                16U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                16U,
#endif
                                authentication_tag);

    print_hex("Ciphertext got:", plaintext, 16U);
    print_hex("Ciphertext expected:", expected_ciphertext, 16U);
    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, 16U);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}

static void test_VERUM_ASCON_AEAD128_encrypt_thirtytwo_byte_pt_thirtytwo_byte_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    uint8_t plaintext[32U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU,
        0x10U, 0x11U, 0x12U, 0x13U,
        0x14U, 0x15U, 0x16U, 0x17U,
        0x18U, 0x19U, 0x1AU, 0x1BU,
        0x1CU, 0x1DU, 0x1EU, 0x1FU
    };
    const uint8_t expected_ciphertext[32U] =
    {
        0x4CU, 0x08U, 0x6DU, 0x27U,
        0xA3U, 0xB5U, 0x1AU, 0x23U,
        0x33U, 0xCFU, 0xC7U, 0xF2U,
        0x21U, 0x72U, 0xA9U, 0xBCU,
        0xADU, 0x88U, 0xB8U, 0xD4U,
        0xD7U, 0x7EU, 0x50U, 0x62U,
        0x2DU, 0x78U, 0x83U, 0x45U,
        0xFAU, 0x7BU, 0xEEU, 0x44U
    };
    const uint8_t expected_tag[16U] =
    {
        0x68U, 0x91U, 0x5DU, 0x3FU,
        0x94U, 0x22U, 0x28U, 0x9FU,
        0x23U, 0x49U, 0xD6U, 0xA3U,
        0xB4U, 0x16U, 0x03U, 0x97U
    };
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[32U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU,
        0x10U, 0x11U, 0x12U, 0x13U,
        0x14U, 0x15U, 0x16U, 0x17U,
        0x18U, 0x19U, 0x1AU, 0x1BU,
        0x1CU, 0x1DU, 0x1EU, 0x1FU
    };
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                plaintext,
                                32U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                32U,
#endif
                                authentication_tag);

    print_hex("Ciphertext got:", plaintext, 32U);
    print_hex("Ciphertext expected:", expected_ciphertext, 32U);
    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, 32U);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}

static void test_VERUM_ASCON_AEAD128_encrypt_five_byte_pt_five_byte_ad(void)
{
    const uint8_t key[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    const uint8_t nonce[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U,
        0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU,
        0x0CU, 0x0DU, 0x0EU, 0x0FU
    };
    uint8_t plaintext[5U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U
    };
    const uint8_t expected_ciphertext[5U] =
    {
        0x1FU, 0x82U, 0x02U, 0x73U, 0xC6U
    };
    const uint8_t expected_tag[16U] =
    {
        0x1BU, 0x8BU, 0x77U, 0xD3U,
        0x67U, 0xC0U, 0xD8U, 0x6EU,
        0x0CU, 0x55U, 0x7AU, 0x43U,
        0x30U, 0x39U, 0xA0U, 0xA5U
    };
    uint32_t state[10U] = {0U};
    uint32_t authentication_tag[4U] = {0U};
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    const uint8_t associated_data[5U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U
    };
#endif

    VERUM_ASCON_AEAD128_encrypt((const uint32_t*)key,
                                (const uint32_t*)nonce,
                                state,
                                plaintext,
                                5U,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                associated_data,
                                5U,
#endif
                                authentication_tag);

    print_hex("Ciphertext got:", plaintext, 5U);
    print_hex("Ciphertext expected:", expected_ciphertext, 5U);
    print_hex("Tag got:", (uint8_t*)authentication_tag, 16U);
    print_hex("Tag expected:", expected_tag, 16U);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_ciphertext, plaintext, 5U);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_tag, (uint8_t*)authentication_tag, 16U);
}
#endif




int run_aead_tests(void)
{
    UNITY_BEGIN();
    #ifndef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
        RUN_TEST(test_VERUM_ASCON_AEAD128_base_encrypt);
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_empty_pt_empty_ad);
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_one_byte_pt_empty_ad);
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_two_byte_pt_empty_ad);
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_sixteen_byte_pt_empty_ad);
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_thirtytwo_byte_pt_empty_ad);
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_seventeen_byte_pt_empty_ad);
    #else
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_empty_pt_sixteen_byte_ad);
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_one_byte_pt_one_byte_ad);
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_one_byte_pt_ten_byte_ad);
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_sixteen_byte_pt_sixteen_byte_ad);
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_thirtytwo_byte_pt_thirtytwo_byte_ad);
        RUN_TEST(test_VERUM_ASCON_AEAD128_encrypt_five_byte_pt_five_byte_ad);
    #endif
    
    return UNITY_END();
}