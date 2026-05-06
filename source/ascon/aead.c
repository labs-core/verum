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

/**
 * @ref NIST SP 800-232 Appendix B
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @
 */
static const uint32_t VERUM_ASCON_AEAD128_initialization_vector[2U] = {
    0x00001000UL,
    0x808C0001UL
};

/**
 * @ref NIST SP 800-232 Section 3.2 Table 5
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief C[𝑖] = Const[16−𝑟𝑛𝑑+𝑖]
 */
static const uint32_t VERUM_ASCON_AEAD128_round_constants[12U] = {
    0x000000F0UL, 0x000000E1UL, 0x000000D2UL, 0x000000C3UL,
    0x000000B4UL, 0x000000A5UL, 0x00000096UL, 0x00000087UL,
    0x00000078UL, 0x00000069UL, 0x0000005AUL, 0x0000004BUL
};

/**
 * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief S ← 𝐼𝑉 ∥ 𝐾 ∥ 𝑁
 */
static inline void VERUM_ASCON_AEAD128_initialize_state(uint32_t state[10U],
                                                        const uint32_t key[4U],
                                                        const uint32_t nonce[4U])
{
    state[0U] = VERUM_ASCON_AEAD128_initialization_vector[0U];
    state[1U] = VERUM_ASCON_AEAD128_initialization_vector[1U];

    state[2U] = key[0U];
    state[3U] = key[1U];
    state[4U] = key[2U];
    /**
     * @ref NIST SP 800-232 Section 3.2
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝑝𝐶 Constant-Addition Layer
     * @optimization The constant addition layer is merged with the initialization of the state, reducing the number of load operations needed to set up the initial state for encryption.
     */
    state[5U] = key[3U] ^ VERUM_ASCON_AEAD128_round_constants[0U];

    state[6U] = nonce[0U];
    state[7U] = nonce[1U];
    state[8U] = nonce[2U];
    state[9U] = nonce[3U];
}

/**
 * @ref NIST SP 800-232 Section 3.2
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief 𝑝𝐶 Constant-Addition Layer
 */
static inline void VERUM_ASCON_AEAD128_permute_constant_addition(uint32_t state[10U],
                                                                 const uint32_t round_constant)
{
    state[5U] = state[5U] ^ round_constant;
}

/**
 * @ref NIST SP 800-232 Section 3.3
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief 𝑝𝑆 Substitution Layer
 * @optimization Uses 4 temporaries instead of 10, reducing memory traffic (fewer loads/stores), lowering stack usage, and easing register pressure for better overall efficiency.
 */
static inline void VERUM_ASCON_AEAD128_permute_substitution_layer(uint32_t state[10U],
                                                                  uint32_t *const state_holder)
{
    state[0U] = state[0U] ^ state[8U];
    state[1U] = state[1U] ^ state[9U];
    state[4U] = state[4U] ^ state[2U];
    state[5U] = state[5U] ^ state[3U];
    state[8U] = state[8U] ^ state[6U];
    state[9U] = state[9U] ^ state[7U];

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

/**
 * @ref NIST SP 800-232 Section 3.4
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief 𝑝𝐿 Linear Diffusion Layer
 */
static inline void VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(uint32_t state[10U],
                                                                      uint32_t * const state_holder)
{
    *state_holder = state[0U];
    state[0U] = state[0U] ^ ((state[0U]>>19U) | (state[1U]<<13U)) ^ ((state[0U]>>28U) | (state[1U]<<4U));
    state[1U] = state[1U] ^ ((state[1U]>>19U) | (*state_holder<<13U)) ^ ((state[1U]>>28U) | (*state_holder<<4U));

    *state_holder = state[2U];
    state[2U] = state[2U] ^ ((state[2U]<<3U) | (state[3U]>>29U)) ^ ((state[2U]<<25U) | (state[3U]>>7U));
    state[3U] = state[3U] ^ ((state[3U]<<3U) | (*state_holder>>29U)) ^ ((state[3U]<<25U) | (*state_holder>>7U));

    *state_holder = state[4U];
    state[4U] = state[4U] ^ ((state[4U] >>  1U) | (state[5U] << 31U)) ^ ((state[4U] >>  6U) | (state[5U] << 26U));
    state[5U] = state[5U] ^ ((state[5U] >>  1U) | (*state_holder << 31U)) ^ ((state[5U] >>  6U) | (*state_holder << 26U));

    *state_holder = state[6U];
    state[6U] = state[6U] ^ ((state[6U] >> 10U) | (state[7U] << 22U)) ^ ((state[6U] >> 17U) | (state[7U] << 15U));
    state[7U] = state[7U] ^ ((state[7U] >> 10U) | (*state_holder<< 22U)) ^ ((state[7U] >> 17U) | (*state_holder<< 15U));

    *state_holder = state[8U];
    state[8U] = state[8U] ^ ((state[8U] >>  7U) | (state[9U] << 25U)) ^ ((state[9U] >>  9U) | (state[8U] << 23U));
    state[9U] = state[9U] ^ ((state[9U] >>  7U) | (*state_holder<< 25U)) ^ ((*state_holder<<  9U) | (state[9U] << 23U));
}

#ifdef VERUM_ASCON_AEAD128_MEMORY_OPTIMIZED_DEF
/**
 * @brief Permutes the ASCON state starting from a specified round.
 * @param[inout] state The ASCON state to be permuted.
 * @param[out] state_holder A buffer to hold intermediate state values.
 * @param[in] round_index The index of the current round.
 * @optimization This function allows for a more compact implementation of the permutation rounds by reducing code duplication and improving instruction cache utilization.
 */
__attribute__((noinline))
static void VERUM_ASCON_AEAD128_permute(uint32_t state[10U],
                                        uint32_t * const state_holder,
                                        const uint32_t round_index)
{
    do
    {
        VERUM_ASCON_AEAD128_permute_constant_addition(state, round_constants[round_index]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);
        ++round_index;
    }
    while (round_index < 12U);
}

#endif // VERUM_ASCON_AEAD128_MEMORY_OPTIMIZED_DEF



/**
 * @ref NIST SP 800-232 Section 4.1.1
 * @see                           https://doi.org/10.6028/NIST.SP.800-232
 * @brief Nonce-based AEAD encryption scheme, offering 128-bit security strength in the single-key setting.
 *
 *
 * @param[in]  key                128-bit secret key, represented as an array of four 32-bit unsigned integers.
 * @param[in]  nonce              128-bit public nonce, represented as an array of four 32-bit unsigned integers. Must be unique for each encryption operation with the same key to ensure security.
 * @param[in]  state              ASCON state, represented as a union of a structured format and a raw buffer.
 * @param[inout] plaintext        Pointer to the plaintext data to be encrypted and associated data. The plaintext data will be encrypted in-place, meaning that the ciphertext will overwrite the plaintext in memory. The associated data is authenticated but not encrypted, and it is processed separately from the plaintext.
 * @param[in]  plaintext_size     Size of the plaintext data in bytes. The encryption process will handle the plaintext in blocks, and any remaining bytes will be processed according to the ASCON specification for padding.
 * @param[in]  associated_data    VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF : Pointer to the associated data to be authenticated but not encrypted. The associated data can be of arbitrary length and is processed separately from the plaintext.
 * @param[in]  associated_size    VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF : Size of the associated data in bytes. The associated data is authenticated but not encrypted, and it is processed in blocks of 64 bits (8 bytes) during the authentication process. Any remaining bytes will be processed according to the ASCON specification for padding.
 * @param[out] authentication_tag 128-bit authentication tag, represented as an array of four 32-bit unsigned integers. This tag is generated during the encryption process and is used to verify the integrity and authenticity of both the plaintext and the associated data during decryption. The tag should be stored or transmitted alongside the ciphertext for later verification.
 */
void VERUM_ASCON_AEAD128_encrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
                                 uint32_t state[10U],
                                 uint8_t *plaintext,
                                 const uint32_t plaintext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                 const uint8_t * const associated_data,
                                 const uint32_t associated_size,
#endif
                                 uint32_t authentication_tag[4U])
{

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝐼𝑉 ← 0x00001000808c0001; S ← 𝐼𝑉 ‖ 𝐾 ‖ 𝑁; S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
    VERUM_ASCON_AEAD128_initialize_state(state, key, nonce);

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
    uint32_t state_holder[4U] = { 0U, 0U, 0U, 0U };
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

#ifdef VERUM_ASCON_AEAD128_MEMORY_OPTIMIZED_DEF
    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
    VERUM_ASCON_AEAD128_permute(state, state_holder, 1U);
#else
    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[1U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[2U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[3U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[4U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[5U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[6U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[7U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[8U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[9U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[9U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[10U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[11U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

#endif

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← S ⊕ (0^[192] ‖ 𝐾)
     */
    state[6U] = state[6U] ^ key[0U];
    state[7U] = state[7U] ^ key[1U];
    state[8U] = state[8U] ^ key[2U];
    state[9U] = state[9U] ^ key[3U];



    uint8_t last_block[16U] = { 0U };
    uint32_t block_counter = 0U;
    uint32_t last_block_byte_index = 0U;

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝐴𝑚 ←pad(̃𝐴𝑚, 128)
     */
    block_counter = associated_size >> 4U;
    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief S[0∶127] ⊕ 𝐴𝑖
         */
        state[0U] = state[0U] ^ ((const uint32_t *) associated_data)[0U];
        state[1U] = state[1U] ^ ((const uint32_t *) associated_data)[1U];
        state[2U] = state[2U] ^ ((const uint32_t *) associated_data)[2U];
        state[3U] = state[3U] ^ ((const uint32_t *) associated_data)[3U];
        associated_data += 16U;

        /**
         * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑖) ‖ S[128∶319])
         */
#ifdef VERUM_ASCON_AEAD128_MEMORY_OPTIMIZED_DEF
        VERUM_ASCON_AEAD128_permute(state, state_holder, 4U);
#else
        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[4U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[5U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[6U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[7U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[8U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[9U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[10U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[11U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);
#endif // VERUM_ASCON_AEAD128_MEMORY_OPTIMIZED_DEF
    }

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief pad(̃𝐴𝑚, 128)
     */
    last_block_byte_index = associated_size & 0xFU;
    last_block[last_block_byte_index] = 0x80U;

    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block[last_block_byte_index] = associated_data[last_block_byte_index];
    }

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S[0∶127] ⊕ 𝐴𝑖
     */
    state[0U] = state[0U] ^ ((const uint32_t *) last_block)[0U];
    state[1U] = state[1U] ^ ((const uint32_t *) last_block)[1U];
    state[2U] = state[2U] ^ ((const uint32_t *) last_block)[2U];
    state[3U] = state[3U] ^ ((const uint32_t *) last_block)[3U];

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑖) ‖ S[128∶319])
     */
#ifdef VERUM_ASCON_AEAD128_MEMORY_OPTIMIZED_DEF
    VERUM_ASCON_AEAD128_permute(state, state_holder, 4U);
#else
    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[4U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[5U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[6U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[7U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[8U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[9U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[10U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[11U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);
#endif // VERUM_ASCON_AEAD128_MEMORY_OPTIMIZED_DEF

#endif // VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← S ⊕ (0[319] ‖ 1)
     */
    state[9U] = state[9U] ^ 0x00000001UL;

    block_counter = plaintext_size >> 4U;

    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief S[0∶127] ← S[0∶127] ⊕ 𝑃𝑖
         */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
        state[0U] = state[0U] ^ ((const uint32_t *) plaintext)[0U];
        state[1U] = state[1U] ^ ((const uint32_t *) plaintext)[1U];
        state[2U] = state[2U] ^ ((const uint32_t *) plaintext)[2U];
        state[3U] = state[3U] ^ ((const uint32_t *) plaintext)[3U];
        /**
         * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief 𝐶𝑖 ← S[0∶127]
         */
        ((uint32_t *) plaintext)[0U] = state[0U];
        ((uint32_t *) plaintext)[1U] = state[1U];
        ((uint32_t *) plaintext)[2U] = state[2U];
        ((uint32_t *) plaintext)[3U] = state[3U];
#pragma clang diagnostic pop
        plaintext += 16U;



        /**
         * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8](S)
         */
#ifdef VERUM_ASCON_AEAD128_MEMORY_OPTIMIZED_DEF
        VERUM_ASCON_AEAD128_permute(state, state_holder, 4U);
#else
        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[4U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[5U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[6U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[7U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[8U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[9U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[10U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

        VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[11U]);
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);
#endif // VERUM_ASCON_AEAD128_MEMORY_OPTIMIZED_DEF
    }

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief pad(̃𝑃𝑛, 128)
     */
    last_block_byte_index = plaintext_size & 0xFU;
    uint32_t last_block_byte_index_holder = last_block_byte_index;
    last_block[last_block_byte_index] = 0x80U;

    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block[last_block_byte_index] = plaintext[last_block_byte_index];
    }

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S[0∶127] ← S[0∶127] ⊕ pad(̃𝑃𝑛, 128)
     */
    state[0U] = state[0U] ^ ((const uint32_t *) last_block)[0U];
    state[1U] = state[1U] ^ ((const uint32_t *) last_block)[1U];
    state[2U] = state[2U] ^ ((const uint32_t *) last_block)[2U];
    state[3U] = state[3U] ^ ((const uint32_t *) last_block)[3U];

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝐶𝑛 ← S[0∶ℓ−1].
     */
    const uint8_t * const state_bytes = (const uint8_t *) state;
    while (0U < last_block_byte_index_holder)
    {
        --last_block_byte_index_holder;
        plaintext[last_block_byte_index_holder] = state_bytes[last_block_byte_index_holder];
    }

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← S ⊕ (0^[128] ∥ 𝐾 ∥ 0^[64])
     */
    state[4U] = state[4U] ^ key[0U];
    state[5U] = state[5U] ^ key[1U];
    state[6U] = state[6U] ^ key[2U];
    state[7U] = state[7U] ^ key[3U];

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
#ifdef VERUM_ASCON_AEAD128_MEMORY_OPTIMIZED_DEF
    VERUM_ASCON_AEAD128_permute(state, state_holder, 0U);
#else
    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[0U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[1U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[2U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[3U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);


    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[4U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[5U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[6U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[7U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[8U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[9U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[10U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);

    VERUM_ASCON_AEAD128_permute_constant_addition(state, VERUM_ASCON_AEAD128_round_constants[11U]);
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, state_holder);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, state_holder);
#endif // VERUM_ASCON_AEAD128_MEMORY_OPTIMIZED_DEF

    /**
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝑇 ← S[192∶319] ⊕ 𝐾
     */
    authentication_tag[0U] = state[6U]^key[0U];
    authentication_tag[1U] = state[7U]^key[1U];
    authentication_tag[2U] = state[8U]^key[2U];
    authentication_tag[3U] = state[9U]^key[3U];

}
