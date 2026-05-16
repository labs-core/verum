/**
 * @file       aead.c
 * @brief      NIST SP 800-232 ASCON AEAD-128.
 * @details    Authenticated Encryption with Associated Data (AEAD) implementation,
 *             configurable for memory efficiency xor performance. Uses atomic 32-bit
 *             operations while maintaining explicit state machines that operate on
 *             64-bit state for compilation targets in 32-bit microprocessors. The
 *             compiler is not responsible to implement the state machine.
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
#include "define.h"
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
#include "auxiliary/memory.h"
#endif // VERUM_OPTIMIZATION_MEMORY_DEF

/**
 * @internal
 * @ref NIST SP 800-232 Appendix B
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @ 𝐼𝑉 ← 0x00001000808c0001
 */
static const uint32_t VERUM_ASCON_AEAD128_initialization_vector[2U] = {
    0x00001000UL,
    0x808C0001UL
};

/**
 * @internal
 * @ref NIST SP 800-232 Section 3.2 Table 5
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief C[𝑖] = Const[16−𝑟𝑛𝑑+𝑖]
 * @details Each of these are little endian; The XOR will be bounded to the most significant bit of the 5th word of the state.
 */
static const uint32_t VERUM_ASCON_AEAD128_round_constants[12U] = {
    0x000000F0UL, 0x000000E1UL, 0x000000D2UL, 0x000000C3UL,
    0x000000B4UL, 0x000000A5UL, 0x00000096UL, 0x00000087UL,
    0x00000078UL, 0x00000069UL, 0x0000005AUL, 0x0000004BUL
};




/**
 * @internal
 * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief S ← 𝐼𝑉 ∥ 𝐾 ∥ 𝑁
 */
VERUM_ATTR_INLINE
static inline void VERUM_ASCON_AEAD128_initialize_state(uint32_t state[10U],
                                                        const uint32_t key[4U],
                                                        const uint32_t nonce[4U])
{
    state[0U] = VERUM_ASCON_AEAD128_initialization_vector[1U];
    state[1U] = VERUM_ASCON_AEAD128_initialization_vector[0U];

    state[2U] = key[0U];
    state[3U] = key[1U];
    /**
     * @internal
     * @ref NIST SP 800-232 Section 3.2
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝑝𝐶 Constant-Addition Layer
     * @optimization The constant addition layer is merged with the initialization of the state, reducing the number of load operations needed to set up the initial state for encryption.
     */
    state[4U] = key[2U];
    state[5U] = key[3U];

#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_AUX_MEMORY_copy128(&state[6U], nonce);
#else
    state[6U] = nonce[0U];
    state[7U] = nonce[1U];
    state[8U] = nonce[2U];
    state[9U] = nonce[3U];
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
}

/**
 * @internal
 * @ref NIST SP 800-232 Section 3.3
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief 𝑝𝑆 Substitution Layer
 * @optimization Uses 4 temporaries instead of 10, reducing memory traffic (fewer loads/stores), lowering stack usage, and easing register pressure for better overall efficiency.
 */
VERUM_ATTR_INLINE
static inline void VERUM_ASCON_AEAD128_permute_substitution_layer(uint32_t state[10U],
                                                                  uint32_t holder[10U],
                                                                  const uint32_t round_constant)
{
    state[0U] = state[0U] ^ state[8U];
    state[1U] = state[1U] ^ state[9U];
    /**
     * @internal
     * @ref NIST SP 800-232 Section 3.2
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝑝𝐶 Constant-Addition Layer
     */
    state[4U] = state[4U] ^ state[2U] ^ round_constant;
    state[5U] = state[5U] ^ state[3U];

    state[8U] = state[8U] ^ state[6U];
    state[9U] = state[9U] ^ state[7U];

    holder[0U] = state[0U] ^ ((state[2U] ^ 0xFFFFFFFFUL) & state[4U]);
    holder[1U] = state[1U] ^ ((state[3U] ^ 0xFFFFFFFFUL) & state[5U]);
    holder[2U] = state[2U] ^ ((state[4U] ^ 0xFFFFFFFFUL) & state[6U]) ^ holder[0U];
    holder[3U] = state[3U] ^ ((state[5U] ^ 0xFFFFFFFFUL) & state[7U]) ^ holder[1U];
    holder[4U] = state[4U] ^ ((state[6U] ^ 0xFFFFFFFFUL) & state[8U]);
    holder[5U] = state[5U] ^ ((state[7U] ^ 0xFFFFFFFFUL) & state[9U]);
    holder[6U] = state[6U] ^ ((state[8U] ^ 0xFFFFFFFFUL) & state[0U]) ^ holder[4U];
    holder[7U] = state[7U] ^ ((state[9U] ^ 0xFFFFFFFFUL) & state[1U]) ^ holder[5U];
    holder[8U] = state[8U] ^ ((state[0U] ^ 0xFFFFFFFFUL) & state[2U]);
    holder[9U] = state[9U] ^ ((state[1U] ^ 0xFFFFFFFFUL) & state[3U]);


    holder[0U] = holder[0U] ^ holder[8U];
    holder[1U] = holder[1U] ^ holder[9U];
    holder[4U] = holder[4U] ^ 0xFFFFFFFFUL;
    holder[5U] = holder[5U] ^ 0xFFFFFFFFUL;
}

/**
 * @internal
 * @ref NIST SP 800-232 Section 3.4
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief 𝑝𝐿 Linear Diffusion Layer
 */
VERUM_ATTR_INLINE
static inline void VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(uint32_t state[10U],
                                                                      uint32_t holder[10U])
{
    state[0U] = holder[0U] ^ ((holder[0U] >> 19U) | (holder[1U] << 13U)) ^ ((holder[0U] >> 28U) | (holder[1U] << 4U));
    state[1U] = holder[1U] ^ ((holder[1U] >> 19U) | (holder[0U] << 13U)) ^ ((holder[1U] >> 28U) | (holder[0U] << 4U));

    state[2U] = holder[2U] ^ ((holder[2U] << 3U) | (holder[3U] >> 29U)) ^ ((holder[2U] << 25U) | (holder[3U] >> 7U));
    state[3U] = holder[3U] ^ ((holder[3U] << 3U) | (holder[2U] >> 29U)) ^ ((holder[3U] << 25U) | (holder[2U] >> 7U));

    state[4U] = holder[4U] ^ ((holder[4U] >>  1U) | (holder[5U] << 31U)) ^ ((holder[4U] >>  6U) | (holder[5U] << 26U));
    state[5U] = holder[5U] ^ ((holder[5U] >>  1U) | (holder[4U] << 31U)) ^ ((holder[5U] >>  6U) | (holder[4U] << 26U));

    state[6U] = holder[6U] ^ ((holder[6U] >> 10U) | (holder[7U] << 22U)) ^ ((holder[6U] >> 17U) | (holder[7U] << 15U));
    state[7U] = holder[7U] ^ ((holder[7U] >> 10U) | (holder[6U] << 22U)) ^ ((holder[7U] >> 17U) | (holder[6U]<< 15U));

    state[8U] = holder[8U] ^ ((holder[8U] >>  7U) | (holder[9U] << 25U)) ^ ((holder[8U] <<  23U) | (holder[9U] >> 9U));
    state[9U] = holder[9U] ^ ((holder[9U] >>  7U) | (holder[8U] << 25U)) ^ ((holder[9U] <<  23U) | (holder[8U] >> 9U));
}

#ifndef VERUM_OPTIMIZATION_MEMORY_DEF
/**
 * @internal
 * @ref NIST SP 800-232 Section 3.4
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief 𝑝𝐿 Linear Diffusion Layer; 𝑝𝑆 Substitution Layer; 𝑝𝐶 Constant-Addition Layer
 * @optimization The linear diffusion layer is merged with the next round's initial permutation step, reducing the number of intermediate state stores and loads, which can improve performance by minimizing memory access overhead.
 */
VERUM_ATTR_INLINE
static inline void VERUM_ASCON_AEAD128_permute_merged(uint32_t state[10U],
                                                      uint32_t holder[10U],
                                                      const uint32_t round_constant)
{
    state[8U] = holder[8U] ^ ((holder[8U] >>  7U) | (holder[9U] << 25U)) ^ ((holder[8U] <<  23U) | (holder[9U] >> 9U));
    state[9U] = holder[9U] ^ ((holder[9U] >>  7U) | (holder[8U] << 25U)) ^ ((holder[9U] <<  23U) | (holder[8U] >> 9U));

    state[0U] = (holder[0U] ^ ((holder[0U] >> 19U) | (holder[1U] << 13U)) ^ ((holder[0U] >> 28U) | (holder[1U] << 4U))) ^ state[8U];
    state[1U] = (holder[1U] ^ ((holder[1U] >> 19U) | (holder[0U] << 13U)) ^ ((holder[1U] >> 28U) | (holder[0U] << 4U))) ^ state[9U];

    state[2U] = holder[2U] ^ ((holder[2U] << 3U) | (holder[3U] >> 29U)) ^ ((holder[2U] << 25U) | (holder[3U] >> 7U));
    state[3U] = holder[3U] ^ ((holder[3U] << 3U) | (holder[2U] >> 29U)) ^ ((holder[3U] << 25U) | (holder[2U] >> 7U));

    state[4U] = (holder[4U] ^ ((holder[4U] >>  1U) | (holder[5U] << 31U)) ^ ((holder[4U] >>  6U) | (holder[5U] << 26U))) ^ (state[2U] ^ round_constant);
    state[5U] = (holder[5U] ^ ((holder[5U] >>  1U) | (holder[4U] << 31U)) ^ ((holder[5U] >>  6U) | (holder[4U] << 26U))) ^ state[3U];

    state[6U] = holder[6U] ^ ((holder[6U] >> 10U) | (holder[7U] << 22U)) ^ ((holder[6U] >> 17U) | (holder[7U] << 15U));
    state[7U] = holder[7U] ^ ((holder[7U] >> 10U) | (holder[6U] << 22U)) ^ ((holder[7U] >> 17U) | (holder[6U]<< 15U));


    state[8U] = state[8U] ^ state[6U];
    state[9U] = state[9U] ^ state[7U];

    holder[0U] = state[0U] ^ ((state[2U] ^ 0xFFFFFFFFUL) & state[4U]);
    holder[1U] = state[1U] ^ ((state[3U] ^ 0xFFFFFFFFUL) & state[5U]);
    holder[2U] = state[2U] ^ ((state[4U] ^ 0xFFFFFFFFUL) & state[6U]) ^ holder[0U];
    holder[3U] = state[3U] ^ ((state[5U] ^ 0xFFFFFFFFUL) & state[7U]) ^ holder[1U];
    holder[4U] = state[4U] ^ ((state[6U] ^ 0xFFFFFFFFUL) & state[8U]);
    holder[5U] = state[5U] ^ ((state[7U] ^ 0xFFFFFFFFUL) & state[9U]);
    holder[6U] = state[6U] ^ ((state[8U] ^ 0xFFFFFFFFUL) & state[0U]) ^ holder[4U];
    holder[7U] = state[7U] ^ ((state[9U] ^ 0xFFFFFFFFUL) & state[1U]) ^ holder[5U];
    holder[8U] = state[8U] ^ ((state[0U] ^ 0xFFFFFFFFUL) & state[2U]);
    holder[9U] = state[9U] ^ ((state[1U] ^ 0xFFFFFFFFUL) & state[3U]);


    holder[0U] = holder[0U] ^ holder[8U];
    holder[1U] = holder[1U] ^ holder[9U];
    holder[4U] = holder[4U] ^ 0xFFFFFFFFUL;
    holder[5U] = holder[5U] ^ 0xFFFFFFFFUL;
}
#endif // !VERUM_OPTIMIZATION_MEMORY_DEF

#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
/**
 * @internal
 * @brief Permutes the ASCON state starting from a specified round.
 * @param[inout] state The ASCON state to be permuted.
 * @param[out] holder A buffer to hold intermediate state values.
 * @param[in] round_index The index of the current round.
 * @optimization This function allows for a more compact implementation of the permutation rounds by reducing code duplication and improving instruction cache utilization.
 */
VERUM_ATTR_NOINLINE
static void VERUM_ASCON_AEAD128_permute(uint32_t state[10U],
                                        uint32_t * const holder,
                                        uint32_t round_index)
{
    do
    {
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[round_index]);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);
        ++round_index;
    }
    while (round_index < 12U);
}

#endif // VERUM_OPTIMIZATION_MEMORY_DEF

/**
 * @internal
 * @ref NIST SP 800-232 Section 4.1.1
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
 *
 * @warning  Nonce reuse under the same key breaks confidentiality and leaks
 *           key material. Uniqueness is the caller's responsibility.
 * @warning  The tag must be verified in constant time before any plaintext
 *           is released. This function produces the @p authentication_tag.
 * @warning  @p key should be sent as LE words
 *
 * @param[in]     key                128-bit secret key as four 32-bit words.
 * @param[in]     nonce              128-bit nonce as four 32-bit words. Must be unique per (key, plaintext).
 * @param[in,out] state              320-bit Ascon permutation state as ten 32-bit words. Overwritten on entry.
 * @param[in,out] plaintext          Plaintext buffer. Overwritten in place with ciphertext.
 * @param[in]     plaintext_size     Byte length of @p plaintext. Zero is valid.
 * @param[in]     associated_data    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Associated data buffer. Authenticated but not encrypted.
 * @param[in]     associated_size    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Byte length of @p associated_data. Zero is valid.
 * @param[out]    authentication_tag 128-bit authentication tag as four 32-bit words. Store and transmit alongside the ciphertext.
 */
void VERUM_ASCON_AEAD128_encrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
                                 uint32_t state[10U],
                                 uint8_t *plaintext,
                                 const uint32_t plaintext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                 const uint8_t *associated_data,
                                 const uint32_t associated_size,
#endif
                                 uint32_t authentication_tag[4U])
{

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝐼𝑉 ← 0x00001000808c0001; S ← 𝐼𝑉 ‖ 𝐾 ‖ 𝑁; S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     * @details Given a 128-bit 𝐾 and 128-bit 𝑁, the 320-bit internal state is initialized as the concatenation of 𝐼𝑉, 𝐾, and 𝑁
     */
    VERUM_ASCON_AEAD128_initialize_state(state, key, nonce);


    uint32_t holder[10U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_AEAD128_permute(state, holder, 0U);
#else
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[0U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[1U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[2U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[3U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[4U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[5U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[6U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[7U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[8U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[9U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[10U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[11U]);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);

#endif

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← S ⊕ (0^[192] ‖ 𝐾)
     */
    state[6U] = state[6U] ^ key[0U];
    state[7U] = state[7U] ^ key[1U];
    state[8U] = state[8U] ^ key[2U];
    state[9U] = state[9U] ^ key[3U];

    uint32_t block_counter = 0U;
    uint32_t last_block_byte_index = 0U;
    uint8_t last_block_plaintext[16U] = { 0U };

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    uint8_t last_block_associated_data[16U] = { 0U };
    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝐴𝑚 ←pad(̃𝐴𝑚, 128)
     */
    block_counter = associated_size >> 4U;
    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief S[0∶127] ⊕ 𝐴𝑖
         */
        state[0U] = state[0U] ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, _Alignof(uint32_t)))[0U];
        state[1U] = state[1U] ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, _Alignof(uint32_t)))[1U];
        state[2U] = state[2U] ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, _Alignof(uint32_t)))[2U];
        state[3U] = state[3U] ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, _Alignof(uint32_t)))[3U];
        associated_data += 16U;

        /**
         * @internal
         * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑖) ‖ S[128∶319])
         */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        VERUM_ASCON_AEAD128_permute(state, holder, 4U);
#else
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[4U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[5U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[6U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[7U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[8U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[9U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[10U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[11U]);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
    }

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief pad(̃𝐴𝑚, 128)
     */
    last_block_byte_index = associated_size & 0xFU;
    last_block_associated_data[last_block_byte_index] = 0x01U;

    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_associated_data[last_block_byte_index] = associated_data[last_block_byte_index];
    }

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S[0∶127] ⊕ 𝐴𝑖
     */
    state[0U] = state[0U] ^ ((const uint32_t *) last_block_associated_data)[0U];
    state[1U] = state[1U] ^ ((const uint32_t *) last_block_associated_data)[1U];
    state[2U] = state[2U] ^ ((const uint32_t *) last_block_associated_data)[2U];
    state[3U] = state[3U] ^ ((const uint32_t *) last_block_associated_data)[3U];

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑖) ‖ S[128∶319])
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_AEAD128_permute(state, holder, 4U);
#else
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[4U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[5U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[6U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[7U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[8U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[9U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[10U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[11U]);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF

#endif // VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← S ⊕ (0[319] ‖ 1)
     */
    state[9U] = state[9U] ^ 0x80000000UL;

    block_counter = plaintext_size >> 4U;

    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief S[0∶127] ← S[0∶127] ⊕ 𝑃𝑖
         */
        state[0U] = state[0U] ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, _Alignof(uint32_t)))[0U];
        state[1U] = state[1U] ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, _Alignof(uint32_t)))[1U];
        state[2U] = state[2U] ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, _Alignof(uint32_t)))[2U];
        state[3U] = state[3U] ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, _Alignof(uint32_t)))[3U];
        /**
         * @internal
         * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief 𝐶𝑖 ← S[0∶127]
         */
        ((uint32_t *) __builtin_assume_aligned(plaintext, _Alignof(uint32_t)))[0U] = state[0U];
        ((uint32_t *) __builtin_assume_aligned(plaintext, _Alignof(uint32_t)))[1U] = state[1U];
        ((uint32_t *) __builtin_assume_aligned(plaintext, _Alignof(uint32_t)))[2U] = state[2U];
        ((uint32_t *) __builtin_assume_aligned(plaintext, _Alignof(uint32_t)))[3U] = state[3U];
        plaintext += 16U;



        /**
         * @internal
         * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8](S)
         */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        VERUM_ASCON_AEAD128_permute(state, holder, 4U);
#else
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[4U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[5U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[6U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[7U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[8U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[9U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[10U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[11U]);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
    }

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief pad(̃𝑃𝑛, 128)
     */
    last_block_byte_index = plaintext_size & 0xFU;
    uint32_t last_block_byte_index_holder = last_block_byte_index;
    last_block_plaintext[last_block_byte_index] = 0x01U;
    // TR: opt 32_bit cpy if possible
    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_plaintext[last_block_byte_index] = plaintext[last_block_byte_index];
    }

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S[0∶127] ← S[0∶127] ⊕ pad(̃𝑃𝑛, 128)
     */
    state[0U] = state[0U] ^ ((const uint32_t *) last_block_plaintext)[0U];
    state[1U] = state[1U] ^ ((const uint32_t *) last_block_plaintext)[1U];
    state[2U] = state[2U] ^ ((const uint32_t *) last_block_plaintext)[2U];
    state[3U] = state[3U] ^ ((const uint32_t *) last_block_plaintext)[3U];

    /**
     * @internal
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
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← S ⊕ (0^[128] ∥ 𝐾 ∥ 0^[64])
     */
    state[4U] = state[4U] ^ key[0U];
    state[5U] = state[5U] ^ key[1U];
    state[6U] = state[6U] ^ key[2U];
    state[7U] = state[7U] ^ key[3U];

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_AEAD128_permute(state, holder, 0U);
#else
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[0U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[1U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[2U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[3U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[4U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[5U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[6U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[7U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[8U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[9U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[10U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[11U]);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝑇 ← S[192∶319] ⊕ 𝐾
     */
    authentication_tag[0U] = state[6U]^key[0U];
    authentication_tag[1U] = state[7U]^key[1U];
    authentication_tag[2U] = state[8U]^key[2U];
    authentication_tag[3U] = state[9U]^key[3U];

#ifdef VERUM_STANDARD_FIPS_140_3_DEF
    /**
     * @internal
     * @ref ISO/IEC 19790:2012 Section 7.9.7 Zeroization
     * @ref FIPS 140-3 IG
     * @see https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
     * @see https://doi.org/10.6028/NIST.FIPS.140-3
     * @brief Zeroize permutation state to destroy residual key-dependent material
     */
    state[0U] = 0U;
    state[1U] = 0U;
    state[2U] = 0U;
    state[3U] = 0U;
    state[4U] = 0U;
    state[5U] = 0U;
    state[6U] = 0U;
    state[7U] = 0U;
    state[8U] = 0U;
    state[9U] = 0U;

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, _Alignof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, _Alignof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, _Alignof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, _Alignof(uint32_t)))[3U] = 0U;
#endif // VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, _Alignof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, _Alignof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, _Alignof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, _Alignof(uint32_t)))[3U] = 0U;

    holder[0U] = 0U;
    holder[1U] = 0U;
    holder[2U] = 0U;
    holder[3U] = 0U;

#endif // VERUM_STANDARD_FIPS_140_3_DEF

}


/**
 * @internal
 * @ref NIST SP 800-232 Section 4.1.2
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
 *
 * @warning  The tag must be verified before any plaintext
 *           is released. This function verifies the @p authentication_tag.
 * @warning  @p key should be sent as LE words
 *
 * @param[in]     key                128-bit secret key as four 32-bit words.
 * @param[in]     nonce              128-bit nonce as four 32-bit words. Must be unique per (key, plaintext).
 * @param[in,out] state              320-bit Ascon permutation state as ten 32-bit words. Overwritten on entry.
 * @param[in,out] ciphertext         Ciphertext buffer. Overwritten in place with plaintext.
 * @param[in]     ciphertext_size    Byte length of @p ciphertext. Zero is valid.
 * @param[in]     associated_data    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Associated data buffer. Authenticated but not encrypted.
 * @param[in]     associated_size    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Byte length of @p associated_data. Zero is valid.
 * @param[out]    authentication_tag 128-bit authentication tag as four 32-bit words. Store and transmit alongside the ciphertext.
 */
void VERUM_ASCON_AEAD128_decrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
                                 uint32_t state[10U],
                                 uint8_t *ciphertext,
                                 const uint32_t ciphertext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                 const uint8_t *associated_data,
                                 const uint32_t associated_size,
#endif
                                 uint32_t authentication_tag[4U])
{

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝐼𝑉 ← 0x00001000808c0001; S ← 𝐼𝑉 ‖ 𝐾 ‖ 𝑁; S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     * @details Given a 128-bit 𝐾 and 128-bit 𝑁, the 320-bit internal state is initialized as the concatenation of 𝐼𝑉, 𝐾, and 𝑁
     */
    VERUM_ASCON_AEAD128_initialize_state(state, key, nonce);

    uint32_t holder[10U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_AEAD128_permute(state, holder, 0U);
#else
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[0U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[1U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[2U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[3U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[4U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[5U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[6U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[7U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[8U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[9U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[10U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[11U]);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);
#endif

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← S ⊕ (0^[192] ‖ 𝐾)
     */
    state[6U] = state[6U] ^ key[0U];
    state[7U] = state[7U] ^ key[1U];
    state[8U] = state[8U] ^ key[2U];
    state[9U] = state[9U] ^ key[3U];

    uint32_t block_counter = 0U;
    uint32_t last_block_byte_index = 0U;
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    uint8_t last_block_associated_data[16U] = { 0U };
    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝐴𝑚 ←pad(̃𝐴𝑚, 128)
     */
    block_counter = associated_size >> 4U;
    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief S[0∶127] ⊕ 𝐴𝑖
         */
        state[0U] = state[0U] ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, _Alignof(uint32_t)))[0U];
        state[1U] = state[1U] ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, _Alignof(uint32_t)))[1U];
        state[2U] = state[2U] ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, _Alignof(uint32_t)))[2U];
        state[3U] = state[3U] ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, _Alignof(uint32_t)))[3U];
        associated_data += 16U;

        /**
         * @internal
         * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑖) ‖ S[128∶319])
         */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        VERUM_ASCON_AEAD128_permute(state, holder, 4U);
#else
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[4U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[5U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[6U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[7U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[8U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[9U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[10U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[11U]);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
    }

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief pad(̃𝐴𝑚, 128)
     */
    last_block_byte_index = associated_size & 0xFU;
    last_block_associated_data[last_block_byte_index] = 0x01U;

    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_associated_data[last_block_byte_index] = associated_data[last_block_byte_index];
    }

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S[0∶127] ⊕ 𝐴𝑖
     */
    state[0U] = state[0U] ^ ((const uint32_t *) last_block_associated_data)[0U];
    state[1U] = state[1U] ^ ((const uint32_t *) last_block_associated_data)[1U];
    state[2U] = state[2U] ^ ((const uint32_t *) last_block_associated_data)[2U];
    state[3U] = state[3U] ^ ((const uint32_t *) last_block_associated_data)[3U];

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑖) ‖ S[128∶319])
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_AEAD128_permute(state, holder, 4U);
#else
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[4U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[5U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[6U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[7U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[8U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[9U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[10U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[11U]);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF

#endif // VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← S ⊕ (0[319] ‖ 1)
     */
    state[9U] = state[9U] ^ 0x80000000UL;

    block_counter = ciphertext_size >> 4U;

    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief 𝑃𝑖 ← S[0∶127] ⊕ 𝐶𝑖; S[0∶127] ← 𝐶𝑖
         * @feature allows for in-place decryption, but requires temporary state storage to avoid overwriting the ciphertext before it is used in the decryption calculation
         */
        holder[0U] = ((uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[0U];
        ((uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[0U] = state[0U] ^ ((const uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[0U];
        state[0U] = holder[0U];

        holder[0U] = ((uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[1U];
        ((uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[1U] = state[1U] ^ ((const uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[1U];
        state[1U] = holder[0U];

        holder[0U] = ((uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[2U];
        ((uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[2U] = state[2U] ^ ((const uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[2U];
        state[2U] = holder[0U];

        holder[0U] = ((uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[3U];
        ((uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[3U] = state[3U] ^ ((const uint32_t *) __builtin_assume_aligned(ciphertext, _Alignof(uint32_t)))[3U];
        state[3U] = holder[0U];

        ciphertext += 16U;


        //@opt use cipher as state holder for next round chainit
        /**
         * @internal
         * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
         * @see https://doi.org/10.6028/NIST.SP.800-232
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8](S)
         */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        VERUM_ASCON_AEAD128_permute(state, holder, 4U);
#else
        VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[4U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[5U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[6U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[7U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[8U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[9U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[10U]);
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[11U]);
        VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
    }


    last_block_byte_index = ciphertext_size & 0xFU;
    uint32_t last_block_byte_index_holder = last_block_byte_index;

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝑃𝑛 ← S[0∶ℓ−1] ⊕̃ 𝐶𝑛
     */
    uint8_t * const state_bytes = (uint8_t *) state;
    while (0U < last_block_byte_index_holder)
    {
        --last_block_byte_index_holder;
        ciphertext[last_block_byte_index_holder] = state_bytes[last_block_byte_index_holder]^ciphertext[last_block_byte_index_holder];
    }

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S[ℓ∶127] ← S[ℓ∶127] ⊕ (1||0^[127−ℓ])
     */
    uint8_t last_block_ciphertext[16U] = { 0U };
    last_block_ciphertext[last_block_byte_index] = 0x01U;
    // TR: opt 32_bit cpy if possible
    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_ciphertext[last_block_byte_index] = ciphertext[last_block_byte_index];
    }
    state[0U] = state[0U] ^ ((const uint32_t *) last_block_ciphertext)[0U];
    state[1U] = state[1U] ^ ((const uint32_t *) last_block_ciphertext)[1U];
    state[2U] = state[2U] ^ ((const uint32_t *) last_block_ciphertext)[2U];
    state[3U] = state[3U] ^ ((const uint32_t *) last_block_ciphertext)[3U];

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← S ⊕ (0^[128] ∥ 𝐾 ∥ 0^[64])
     */
    state[4U] = state[4U] ^ key[0U];
    state[5U] = state[5U] ^ key[1U];
    state[6U] = state[6U] ^ key[2U];
    state[7U] = state[7U] ^ key[3U];

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_AEAD128_permute(state, holder, 0U);
#else
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[0U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[1U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[2U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[3U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[4U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[5U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[6U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[7U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[8U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[9U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[10U]);
    VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[11U]);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF

    /**
     * @internal
     * @ref NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝑇 ← S[192∶319] ⊕ 𝐾
     */
    authentication_tag[0U] = state[6U]^key[0U];
    authentication_tag[1U] = state[7U]^key[1U];
    authentication_tag[2U] = state[8U]^key[2U];
    authentication_tag[3U] = state[9U]^key[3U];

#ifdef VERUM_STANDARD_FIPS_140_3_DEF
    /**
     * @internal
     * @ref ISO/IEC 19790:2012 Section 7.9.7 Zeroization
     * @ref FIPS 140-3 IG
     * @see https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
     * @see https://doi.org/10.6028/NIST.FIPS.140-3
     * @brief Zeroize permutation state to destroy residual key-dependent material
     */
    state[0U] = 0U;
    state[1U] = 0U;
    state[2U] = 0U;
    state[3U] = 0U;
    state[4U] = 0U;
    state[5U] = 0U;
    state[6U] = 0U;
    state[7U] = 0U;
    state[8U] = 0U;
    state[9U] = 0U;

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, _Alignof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, _Alignof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, _Alignof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, _Alignof(uint32_t)))[3U] = 0U;
#endif // VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, _Alignof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, _Alignof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, _Alignof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, _Alignof(uint32_t)))[3U] = 0U;

    holder[0U] = 0U;
    holder[1U] = 0U;
    holder[2U] = 0U;
    holder[3U] = 0U;

#endif // VERUM_STANDARD_FIPS_140_3_DEF
}
