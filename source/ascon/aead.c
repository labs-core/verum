/**
 * @file       aead.h
 * @brief      NIST SP 800-232 ASCON AEAD-128A.
 * @details    Authenticated Encryption with Associated Data (AEAD) is a form of
 *             encryption that simultaneously guarantees confidentiality of the
 *             plaintext and authenticity of both the plaintext and the associated
 *             data. Associated data is authenticated but not encrypted,tamper-evident.
 *             ASCON-AEAD128 realises this construction through a
 *             duplex sponge operating over a 320-bit permutation state, binding a
 *             128-bit key and a 128-bit nonce to produce a ciphertext equal in
 *             length to the plaintext and a 128-bit authentication tag, as
 *             standardised in NIST SP 800-232.
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
 */
#include "verum/ascon/aead.h"
#include "standard/types.h"
#include <cstdint>

/**
 * @ref NIST SP 800-232 Appendix B
 * @see https://doi.org/10.6028/NIST.SP.800-232
 */
static const uint32_t VERUM_ASCON_AEAD128_initialization_vector[2U] = {0x00001000UL, 0x808C0001UL};



/**
 * @ref NIST SP 800-232 Section 3.2 Table 5
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @details C[𝑖] = Const[16−𝑟𝑛𝑑+𝑖]
 */
static const uint32_t VERUM_ASCON_AEAD128_round_constants[12U] = {
    0x000000F0UL, 0x000000E1UL, 0x000000D2UL, 0x000000C3UL,
    0x000000B4UL, 0x000000A5UL, 0x00000096UL, 0x00000087UL,
    0x00000078UL, 0x00000069UL, 0x0000005AUL, 0x0000004BUL
};


/**
 * @ref NIST SP 800-232 Section 4.1.1
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief Nonce-based AEAD encryption scheme, offering 128-bit security strength in the single-key setting.
 *
 *
 * @param[in] key 128-bit secret key, represented as an array of four 32-bit unsigned integers.
 * @param[in] nonce 128-bit public nonce, represented as an array of four 32-bit unsigned integers. Must be unique for each encryption operation with the same key to ensure security.
 * @param[in] state ASCON state, represented as a union of a structured format and a raw buffer.
 * @param[inout] data Pointer to the plaintext data to be encrypted and associated data. The plaintext data will be encrypted in-place, meaning that the ciphertext will overwrite the plaintext in memory. The associated data is authenticated but not encrypted, and it is processed separately from the plaintext.
 * @param[in] plaintext_size Size of the plaintext data in bytes. The encryption process will handle the plaintext in blocks, and any remaining bytes will be processed according to the ASCON specification for padding.
 * @param[in] associated_size Size of the associated data in bytes. The associated data is authenticated but not encrypted, and it is processed in blocks of 64 bits (8 bytes) during the authentication process. Any remaining bytes will be processed according to the ASCON specification for padding.
 * @param[out] authentication_tag 128-bit authentication tag, represented as an array of four 32-bit unsigned integers. This tag is generated during the encryption process and is used to verify the integrity and authenticity of both the plaintext and the associated data during decryption. The tag should be stored or transmitted alongside the ciphertext for later verification.
 */
void VERUM_ASCON_AEAD128_encrypt(const uint32_t        key[4U],
                                 const uint32_t        nonce[4U],
                                 uint32_t const   state[10U],
                                 const uint8_t * const data,
                                 const uint32_t plaintext_size,
                                 const uint32_t associated_size,
                                 uint32_t const authentication_tag[4U] )
{
    /**
     * @ref NIST SP 800-232 Section 3.2.1
     * @see https://doi.org/10.6028/NIST.SP.800-232
     */
    state[0U] = VERUM_ASCON_AEAD128_initialization_vector[0U];
    state[1U] = VERUM_ASCON_AEAD128_initialization_vector[1U];

    state[2U] = key[0U];
    state[3U] = key[1U];
    state[4U] = key[2U];
    /**
     * @ref NIST SP 800-232 Section 3.2
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝑝𝐶 Constant-Addition Layer
     */
    state[5U] = key[3U]^VERUM_ASCON_AEAD128_round_constants[0U];

    state[6U] = nonce[0U];
    state[7U] = nonce[1U];
    state[8U] = nonce[2U];
    state[9U] = nonce[3U];


    /**
     * @ref NIST SP 800-232 Section 3.3
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝑝𝑆 Substitution Layer
     */
    state[0U] = state[0U] ^ state[8U];
    state[1U] = state[1U] ^ state[9U];

    state[4U] = state[4U] ^ state[2U];
    state[5U] = state[5U] ^ state[3U];

    state[8U] = state[8U] ^ state[6U];
    state[9U] = state[9U] ^ state[7U];

    /**
     * @optimization
     * - Less holder variables : 4 instead of 10 : Reduces the amount of stores needed to fill holder buffers and also reduces footprint on stack memory.
     */
    uint32_t state_holder[4U];

    state_holder[0U] = state[0U];
    state_holder[1U] = state[1U];

    state_holder[2U] = state[2U];
    state_holder[3U] = state[3U];

    state[0U] = state[0U] ^ ((state[2U] ^ 0xFFFFFFFFUL) & state[4U]);
    state[1U] = state[1U] ^ ((state[3U] ^ 0xFFFFFFFFUL) & state[5U]);

    state[2U] = state[2U] ^ ((state[4U] ^ 0xFFFFFFFFUL) & state[6U]);
    state[3U] = state[3U] ^ ((state[5U] ^ 0xFFFFFFFFUL) & state[7U]);

    state[4U] = state[4U] ^ ((state[6U] ^ 0xFFFFFFFFUL) & state[8U]);
    state[5U] = state[5U] ^ ((state[7U] ^ 0xFFFFFFFFUL) & state[9U]);

    state[6U] = state[6U] ^ ((state[8U] ^ 0xFFFFFFFFUL) & state_holder[0U]);
    state[7U] = state[7U] ^ ((state[9U] ^ 0xFFFFFFFFUL) & state_holder[1U]);

    state[8U] = state[8U] ^ ((state_holder[0U] ^ 0xFFFFFFFFUL) & state_holder[2U]);
    state[9U] = state[9U] ^ ((state_holder[1U] ^ 0xFFFFFFFFUL) & state_holder[3U]);


    state[6U] = state[6U] ^ state[4U];
    state[7U] = state[7U] ^ state[5U];

    state[4U] = state[4U] ^ 0xFFFFFFFFUL;
    state[5U] = state[5U] ^ 0xFFFFFFFFUL;

    state[2U] = state[2U] ^ state[0U];
    state[3U] = state[3U] ^ state[1U];

    state[0U] = state[0U] ^ state[8U];
    state[1U] = state[1U] ^ state[9U];







    
}
