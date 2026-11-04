/**
 * @file       aead.c
 * @brief      NIST SP 800-232 ASCON AEAD-128.
 * @details    Authenticated Encryption with Associated Data (AEAD) implementation,
 *             configurable for memory efficiency xor performance via explicit 32-bit
 *             operations over the 320-bit (five 64-bit word) bit-interleaved state
 *             machine [OPT-A_0] on 32-bit targets without compiler-synthesized 64-bit
 *             arithmetic.
 *
 * @see        https://doi.org/10.6028/NIST.SP.800-232
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */
#include "verum/ascon/aead.h"
#include "ascon.h"
#include "define.h"

/**
 * @internal
 * @ref          NIST SP 800-232 Appendix B
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        𝐼𝑉 ← 0x00001000808c0001
 * @details      Stored as π(𝐼𝑉) = { E, O } of (𝐿 = 0x808C0001, 𝐻 = 0x00001000).
 * @optimization [OPT-A_0] Pre-interleaved at compile time; no runtime π on the IV.
 */
static const uint32_t VERUM_ASCON_AEAD128_initialization_vector[2U] = {
    0x00400201UL,
    0x00008A00UL
};


/**
 * @internal
 * @ref           NIST SP 800-232 Section 4.1.1 Algorithm 3
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
 *
 * @warning       Nonce reuse under the same key breaks confidentiality and leaks key
 *                material; uniqueness is the caller's responsibility.
 * @warning       The produced @p authentication_tag must be verified in constant time
 *                before any plaintext is released.
 * @warning       @p plaintext, @p associated_data, and @p authentication_tag must be
 *                aligned to @c uint32_t boundaries; @p key, @p nonce, and
 *                @p authentication_tag must be little-endian 32-bit words.
 *
 * @param[in]     key                128-bit secret key (four 32-bit LE words).
 * @param[in]     nonce              128-bit nonce (four 32-bit LE words, unique per (key, plaintext)).
 * @param[in,out] plaintext          Plaintext buffer, overwritten in place with ciphertext.
 * @param[in]     plaintext_size     Byte length of @p plaintext (0 is valid).
 * @param[in]     associated_data    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Authenticated unencrypted AD buffer.
 * @param[in]     associated_size    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Byte length of @p associated_data.
 * @param[out]    authentication_tag 128-bit authentication tag (four 32-bit LE words).
 */
// cppcheck-suppress unusedFunction ; DEV-006: Public library API is called by downstream applications; no in-repository caller is required.
// cppcheck-suppress misra-c2012-8.7 ; DEV-007: External linkage is required so downstream applications can link this public API.
void VERUM_ASCON_AEAD128_encrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
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
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        𝐼𝑉 ← 0x00001000808c0001; S ← 𝐼𝑉 ‖ 𝐾 ‖ 𝑁
     * @details      Initializes the 320-bit state as the concatenation of 64-bit 𝐼𝑉, 128-bit 𝐾, and 128-bit 𝑁.
     *               Bit-interleaved state [OPT-A_0]: state[2w] = E_w (even bits of S_w),
     *               state[2w+1] = O_w (odd bits of S_w).
     * @optimization [OPT-A_12] π applied in place on the state words holding 𝐾 and 𝑁.
     */
    uint32_t state[10U] = { VERUM_ASCON_AEAD128_initialization_vector[0U],
                            VERUM_ASCON_AEAD128_initialization_vector[1U],
                            key[0U], key[1U], key[2U], key[3U],
                            nonce[0U], nonce[1U], nonce[2U], nonce[3U] };
    uint32_t holder[10U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };
    VERUM_ASCON_interleave(&state[2U]);
    VERUM_ASCON_interleave(&state[4U]);
    VERUM_ASCON_interleave(&state[6U]);
    VERUM_ASCON_interleave(&state[8U]);

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     * @optimization [OPT-A_7] Selects compact loop call (VERUM_OPTIMIZATION_MEMORY_DEF) or
     *               12 unrolled fused inline rounds (p_S + 11x p_merged + p_L).
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_permute(state, holder, 0U);
#else
    VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[0U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[1U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[2U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[3U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[4U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
    VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#endif

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        S ← S ⊕ (0^[192] ‖ π(𝐾))
     * @optimization [OPT-A_12] holder (dead between permutations) stages π(𝐾); no
     *               persistent interleaved key copy (no extra SSP to zeroize).
     */
    holder[0U] = key[0U];
    holder[1U] = key[1U];
    holder[2U] = key[2U];
    holder[3U] = key[3U];
    VERUM_ASCON_interleave(&holder[0U]);
    VERUM_ASCON_interleave(&holder[2U]);
    state[6U] = state[6U] ^ holder[0U];
    state[7U] = state[7U] ^ holder[1U];
    state[8U] = state[8U] ^ holder[2U];
    state[9U] = state[9U] ^ holder[3U];

    uint32_t block_counter = 0U;
    uint32_t last_block_byte_index = 0U;
    // cppcheck-suppress misra-c2012-1.4 ; DEV-004: C11 defines _Alignas behavior; explicit alignment is needed for these fixed-size staging buffers.
    _Alignas(uint32_t) uint8_t last_block_plaintext[16U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    // cppcheck-suppress misra-c2012-1.4 ; DEV-004: C11 defines _Alignas behavior; explicit alignment is needed for these fixed-size staging buffers.
    _Alignas(uint32_t) uint8_t last_block_associated_data[16U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };
    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief 𝐴1 ... 𝐴𝑚−1 full 128-bit associated-data block count.
     */
    block_counter = associated_size >> 4U;
    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @brief        S[0∶127] ← S[0∶127] ⊕ π(𝐴𝑖)
         * @optimization [OPT-A_12] holder stages π(𝐴𝑖); no extra stack.
         */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        holder[0U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[0U];
        holder[1U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[1U];
        holder[2U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[2U];
        holder[3U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[3U];
        // cppcheck-suppress-end misra-c2012-11.3
        VERUM_ASCON_interleave(&holder[0U]);
        VERUM_ASCON_interleave(&holder[2U]);
        state[0U] = state[0U] ^ holder[0U];
        state[1U] = state[1U] ^ holder[1U];
        state[2U] = state[2U] ^ holder[2U];
        state[3U] = state[3U] ^ holder[3U];
        associated_data += 16U;

        /**
         * @internal
         * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑖) ‖ S[128∶319])
         */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        VERUM_ASCON_permute(state, holder, 4U);
#else
        VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[4U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
        VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
    }

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief 𝐴𝑚 ← pad(̃𝐴𝑚, 128)
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
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        S[0∶127] ← S[0∶127] ⊕ π(𝐴𝑚)
     * @optimization [OPT-A_12] π applied in place on the aligned staging buffer.
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[2U]);
    state[0U] = state[0U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[0U];
    state[1U] = state[1U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[1U];
    state[2U] = state[2U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[2U];
    state[3U] = state[3U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑚) ‖ S[128∶319])
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_permute(state, holder, 4U);
#else
    VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[4U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
    VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF

#endif // VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    /**
     * @internal
     * @ref     NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief   S ← S ⊕ (0^[319] ‖ 1)
     * @details Bit 63 of S4 is odd (2·31 + 1), so it maps to bit 31 of O_4 (state[9U]).
     */
    state[9U] = state[9U] ^ 0x80000000UL;

    block_counter = plaintext_size >> 4U;

    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @brief        S[0∶127] ← S[0∶127] ⊕ π(𝑃𝑖); 𝐶𝑖 ← π⁻¹(S[0∶127])
         * @optimization [OPT-A_12] holder stages π(𝑃𝑖) and π⁻¹(S[0∶127]); no extra stack.
         */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        holder[0U] = ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[0U];
        holder[1U] = ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[1U];
        holder[2U] = ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[2U];
        holder[3U] = ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[3U];
        VERUM_ASCON_interleave(&holder[0U]);
        VERUM_ASCON_interleave(&holder[2U]);
        state[0U] = state[0U] ^ holder[0U];
        state[1U] = state[1U] ^ holder[1U];
        state[2U] = state[2U] ^ holder[2U];
        state[3U] = state[3U] ^ holder[3U];

        holder[0U] = state[0U];
        holder[1U] = state[1U];
        holder[2U] = state[2U];
        holder[3U] = state[3U];
        VERUM_ASCON_deinterleave(&holder[0U]);
        VERUM_ASCON_deinterleave(&holder[2U]);
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[0U] = holder[0U];
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[1U] = holder[1U];
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[2U] = holder[2U];
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[3U] = holder[3U];
        // cppcheck-suppress-end misra-c2012-11.3
        plaintext += 16U;



        /**
         * @internal
         * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8](S)
         */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        VERUM_ASCON_permute(state, holder, 4U);
#else
        VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[4U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
        VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
    }

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
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
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        S[0∶127] ← S[0∶127] ⊕ π(pad(̃𝑃𝑛, 128))
     * @optimization [OPT-A_12] π applied in place on the aligned staging buffer.
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U]);
    state[0U] = state[0U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U];
    state[1U] = state[1U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U];
    state[2U] = state[2U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U];
    state[3U] = state[3U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        𝐶𝑛 ← π⁻¹(S[0∶127])[0∶ℓ−1]
     * @optimization [OPT-A_12] holder stages π⁻¹(S[0∶127]); no extra stack.
     */
    holder[0U] = state[0U];
    holder[1U] = state[1U];
    holder[2U] = state[2U];
    holder[3U] = state[3U];
    VERUM_ASCON_deinterleave(&holder[0U]);
    VERUM_ASCON_deinterleave(&holder[2U]);
    const uint8_t * const holder_bytes = (const uint8_t *) holder;
    while (0U < last_block_byte_index_holder)
    {
        --last_block_byte_index_holder;
        plaintext[last_block_byte_index_holder] = holder_bytes[last_block_byte_index_holder];
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        S ← S ⊕ (0^[128] ∥ π(𝐾) ∥ 0^[64])
     * @optimization [OPT-A_12] holder stages π(𝐾); no persistent interleaved key copy.
     */
    holder[0U] = key[0U];
    holder[1U] = key[1U];
    holder[2U] = key[2U];
    holder[3U] = key[3U];
    VERUM_ASCON_interleave(&holder[0U]);
    VERUM_ASCON_interleave(&holder[2U]);
    state[4U] = state[4U] ^ holder[0U];
    state[5U] = state[5U] ^ holder[1U];
    state[6U] = state[6U] ^ holder[2U];
    state[7U] = state[7U] ^ holder[3U];

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_permute(state, holder, 0U);
#else
    VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[0U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[1U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[2U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[3U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[4U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
    VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        𝑇 ← π⁻¹(S[192∶319]) ⊕ 𝐾
     * @optimization [OPT-A_12] π⁻¹ applied in place on the tag words; no staging copy.
     */
    authentication_tag[0U] = state[6U];
    authentication_tag[1U] = state[7U];
    authentication_tag[2U] = state[8U];
    authentication_tag[3U] = state[9U];
    VERUM_ASCON_deinterleave(&authentication_tag[0U]);
    VERUM_ASCON_deinterleave(&authentication_tag[2U]);
    authentication_tag[0U] = authentication_tag[0U] ^ key[0U];
    authentication_tag[1U] = authentication_tag[1U] ^ key[1U];
    authentication_tag[2U] = authentication_tag[2U] ^ key[2U];
    authentication_tag[3U] = authentication_tag[3U] ^ key[3U];

#ifdef VERUM_STANDARD_FIPS_140_3_DEF
    /**
     * @internal
     * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
     * @ref   FIPS 140-3 IG
     * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
     * @see   https://doi.org/10.6028/NIST.FIPS.140-3
     * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
     */
    // cppcheck-suppress-begin unreadVariable ; DEV-001: intentional SSP zeroization (ISO/IEC 19790 7.9.7)
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
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[3U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
#endif // VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3

    holder[0U] = 0U;
    holder[1U] = 0U;
    holder[2U] = 0U;
    holder[3U] = 0U;
    // cppcheck-suppress-end unreadVariable

#endif // VERUM_STANDARD_FIPS_140_3_DEF

}


/**
 * @internal
 * @ref           NIST SP 800-232 Section 4.1.2 Algorithm 4
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
 *
 * @warning       Outputs the recomputed candidate @p authentication_tag; the caller must
 *                verify @p authentication_tag in constant time before any plaintext is
 *                released.
 * @warning       @p ciphertext, @p associated_data, and @p authentication_tag must be
 *                aligned to @c uint32_t boundaries; @p key, @p nonce, and
 *                @p authentication_tag must be little-endian 32-bit words.
 *
 * @param[in]     key                128-bit secret key (four 32-bit LE words).
 * @param[in]     nonce              128-bit nonce matching encryption (four 32-bit LE words).
 * @param[in,out] ciphertext         Ciphertext buffer, overwritten in place with plaintext.
 * @param[in]     ciphertext_size    Byte length of @p ciphertext (0 is valid).
 * @param[in]     associated_data    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Authenticated unencrypted AD buffer.
 * @param[in]     associated_size    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Byte length of @p associated_data.
 * @param[out]    authentication_tag Recomputed 128-bit candidate tag (four 32-bit LE words).
 */
// cppcheck-suppress unusedFunction ; DEV-006: Public library API is called by downstream applications; no in-repository caller is required.
// cppcheck-suppress misra-c2012-8.7 ; DEV-007: External linkage is required so downstream applications can link this public API.
void VERUM_ASCON_AEAD128_decrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
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
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        𝐼𝑉 ← 0x00001000808c0001; S ← 𝐼𝑉 ‖ 𝐾 ‖ 𝑁
     * @details      Initializes the 320-bit state as the concatenation of 64-bit 𝐼𝑉, 128-bit 𝐾, and 128-bit 𝑁.
     *               Bit-interleaved state [OPT-A_0]: state[2w] = E_w (even bits of S_w),
     *               state[2w+1] = O_w (odd bits of S_w).
     * @optimization [OPT-A_12] π applied in place on the state words holding 𝐾 and 𝑁.
     */
    uint32_t state[10U] = { VERUM_ASCON_AEAD128_initialization_vector[0U],
                            VERUM_ASCON_AEAD128_initialization_vector[1U],
                            key[0U], key[1U], key[2U], key[3U],
                            nonce[0U], nonce[1U], nonce[2U], nonce[3U] };

    uint32_t holder[10U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };
    VERUM_ASCON_interleave(&state[2U]);
    VERUM_ASCON_interleave(&state[4U]);
    VERUM_ASCON_interleave(&state[6U]);
    VERUM_ASCON_interleave(&state[8U]);

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     * @optimization [OPT-A_7] Selects compact loop call (VERUM_OPTIMIZATION_MEMORY_DEF) or
     *               12 unrolled fused inline rounds (p_S + 11x p_merged + p_L).
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_permute(state, holder, 0U);
#else
    VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[0U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[1U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[2U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[3U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[4U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
    VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#endif

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        S ← S ⊕ (0^[192] ‖ π(𝐾))
     * @optimization [OPT-A_12] holder (dead between permutations) stages π(𝐾); no
     *               persistent interleaved key copy (no extra SSP to zeroize).
     */
    holder[0U] = key[0U];
    holder[1U] = key[1U];
    holder[2U] = key[2U];
    holder[3U] = key[3U];
    VERUM_ASCON_interleave(&holder[0U]);
    VERUM_ASCON_interleave(&holder[2U]);
    state[6U] = state[6U] ^ holder[0U];
    state[7U] = state[7U] ^ holder[1U];
    state[8U] = state[8U] ^ holder[2U];
    state[9U] = state[9U] ^ holder[3U];

    uint32_t block_counter = 0U;
    uint32_t last_block_byte_index = 0U;
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    // cppcheck-suppress misra-c2012-1.4 ; DEV-004: C11 defines _Alignas behavior; explicit alignment is needed for these fixed-size staging buffers.
    _Alignas(uint32_t) uint8_t last_block_associated_data[16U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };
    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief 𝐴1 ... 𝐴𝑚−1 full 128-bit associated-data block count.
     */
    block_counter = associated_size >> 4U;
    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
         * @brief        S[0∶127] ← S[0∶127] ⊕ π(𝐴𝑖)
         * @optimization [OPT-A_12] holder stages π(𝐴𝑖); no extra stack.
         */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        holder[0U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[0U];
        holder[1U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[1U];
        holder[2U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[2U];
        holder[3U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[3U];
        // cppcheck-suppress-end misra-c2012-11.3
        VERUM_ASCON_interleave(&holder[0U]);
        VERUM_ASCON_interleave(&holder[2U]);
        state[0U] = state[0U] ^ holder[0U];
        state[1U] = state[1U] ^ holder[1U];
        state[2U] = state[2U] ^ holder[2U];
        state[3U] = state[3U] ^ holder[3U];
        associated_data += 16U;

        /**
         * @internal
         * @ref   NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑖) ‖ S[128∶319])
         */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        VERUM_ASCON_permute(state, holder, 4U);
#else
        VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[4U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
        VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
    }

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief 𝐴𝑚 ← pad(̃𝐴𝑚, 128)
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
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        S[0∶127] ← S[0∶127] ⊕ π(𝐴𝑚)
     * @optimization [OPT-A_12] π applied in place on the aligned staging buffer.
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[2U]);
    state[0U] = state[0U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[0U];
    state[1U] = state[1U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[1U];
    state[2U] = state[2U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[2U];
    state[3U] = state[3U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑚) ‖ S[128∶319])
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_permute(state, holder, 4U);
#else
    VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[4U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
    VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF

#endif // VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    /**
     * @internal
     * @ref     NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief   S ← S ⊕ (0^[319] ‖ 1)
     * @details Bit 63 of S4 is odd (2·31 + 1), so it maps to bit 31 of O_4 (state[9U]).
     */
    state[9U] = state[9U] ^ 0x80000000UL;

    block_counter = ciphertext_size >> 4U;

    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
         * @brief        𝑃𝑖 ← π⁻¹(S[0∶127]) ⊕ 𝐶𝑖; S[0∶127] ← π(𝐶𝑖)
         * @feature      In-place decryption preserving 𝐶𝑖 for sponge state replacement.
         * @optimization [OPT-A_12] holder[0U..3U] stages π⁻¹(S[0∶127]) and holder[4U..7U]
         *               preserves 𝐶𝑖 for π, avoiding extra stack allocation.
         */
        holder[0U] = state[0U];
        holder[1U] = state[1U];
        holder[2U] = state[2U];
        holder[3U] = state[3U];
        VERUM_ASCON_deinterleave(&holder[0U]);
        VERUM_ASCON_deinterleave(&holder[2U]);

        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        holder[4U] = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[0U];
        holder[5U] = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[1U];
        holder[6U] = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[2U];
        holder[7U] = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[3U];
        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[0U] = holder[0U] ^ holder[4U];
        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[1U] = holder[1U] ^ holder[5U];
        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[2U] = holder[2U] ^ holder[6U];
        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[3U] = holder[3U] ^ holder[7U];
        // cppcheck-suppress-end misra-c2012-11.3

        VERUM_ASCON_interleave(&holder[4U]);
        VERUM_ASCON_interleave(&holder[6U]);
        state[0U] = holder[4U];
        state[1U] = holder[5U];
        state[2U] = holder[6U];
        state[3U] = holder[7U];

        ciphertext += 16U;


        //@opt use cipher as state holder for next round chainit
        /**
         * @internal
         * @ref   NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8](S)
         */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
        VERUM_ASCON_permute(state, holder, 4U);
#else
        VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[4U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
        VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
    }


    last_block_byte_index = ciphertext_size & 0xFU;
    uint32_t last_block_byte_index_holder = last_block_byte_index;

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        𝑃𝑛 ← π⁻¹(S[0∶127])[0∶ℓ−1] ⊕ ̃𝐶𝑛
     * @optimization [OPT-A_12] holder stages π⁻¹(S[0∶127]); no extra stack.
     */
    holder[0U] = state[0U];
    holder[1U] = state[1U];
    holder[2U] = state[2U];
    holder[3U] = state[3U];
    VERUM_ASCON_deinterleave(&holder[0U]);
    VERUM_ASCON_deinterleave(&holder[2U]);
    const uint8_t * const holder_bytes = (const uint8_t *) holder;
    while (0U < last_block_byte_index_holder)
    {
        --last_block_byte_index_holder;
        ciphertext[last_block_byte_index_holder] = holder_bytes[last_block_byte_index_holder]^ciphertext[last_block_byte_index_holder];
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        S[0∶127] ← π(̃𝐶𝑛 ‖ (π⁻¹(S)[ℓ∶127] ⊕ (1 ‖ 0^[127−ℓ])))
     * @optimization [OPT-A_13] Stages the decrypted tail 𝑃𝑛 with the 0x01 padding byte in a
     *               4-byte-aligned buffer so S ⊕ π(pad(𝑃𝑛)) yields the result in a single
     *               word-XOR pass (π is ⊕-linear).
     *               [OPT-A_12] π applied in place on the aligned staging buffer.
     */
    // cppcheck-suppress misra-c2012-1.4 ; DEV-004: C11 defines _Alignas behavior; explicit alignment is needed for these fixed-size staging buffers.
    _Alignas(uint32_t) uint8_t last_block_ciphertext[16U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };
    last_block_ciphertext[last_block_byte_index] = 0x01U;
    // TR: opt 32_bit cpy if possible
    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_ciphertext[last_block_byte_index] = ciphertext[last_block_byte_index];
    }
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U]);
    state[0U] = state[0U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U];
    state[1U] = state[1U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U];
    state[2U] = state[2U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U];
    state[3U] = state[3U] ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        S ← S ⊕ (0^[128] ∥ π(𝐾) ∥ 0^[64])
     * @optimization [OPT-A_12] holder stages π(𝐾); no persistent interleaved key copy.
     */
    holder[0U] = key[0U];
    holder[1U] = key[1U];
    holder[2U] = key[2U];
    holder[3U] = key[3U];
    VERUM_ASCON_interleave(&holder[0U]);
    VERUM_ASCON_interleave(&holder[2U]);
    state[4U] = state[4U] ^ holder[0U];
    state[5U] = state[5U] ^ holder[1U];
    state[6U] = state[6U] ^ holder[2U];
    state[7U] = state[7U] ^ holder[3U];

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    VERUM_ASCON_permute(state, holder, 0U);
#else
    VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[0U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[1U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[2U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[3U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[4U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[5U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[6U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[7U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[8U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[9U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[10U]);
    VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[11U]);
    VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
#endif // VERUM_OPTIMIZATION_MEMORY_DEF

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        𝑇 ← π⁻¹(S[192∶319]) ⊕ 𝐾
     * @optimization [OPT-A_12] π⁻¹ applied in place on the tag words; no staging copy.
     */
    authentication_tag[0U] = state[6U];
    authentication_tag[1U] = state[7U];
    authentication_tag[2U] = state[8U];
    authentication_tag[3U] = state[9U];
    VERUM_ASCON_deinterleave(&authentication_tag[0U]);
    VERUM_ASCON_deinterleave(&authentication_tag[2U]);
    authentication_tag[0U] = authentication_tag[0U] ^ key[0U];
    authentication_tag[1U] = authentication_tag[1U] ^ key[1U];
    authentication_tag[2U] = authentication_tag[2U] ^ key[2U];
    authentication_tag[3U] = authentication_tag[3U] ^ key[3U];

#ifdef VERUM_STANDARD_FIPS_140_3_DEF
    /**
     * @internal
     * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
     * @ref   FIPS 140-3 IG
     * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
     * @see   https://doi.org/10.6028/NIST.FIPS.140-3
     * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
     */
    // cppcheck-suppress-begin unreadVariable ; DEV-001: intentional SSP zeroization (ISO/IEC 19790 7.9.7)
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
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_associated_data, sizeof(uint32_t)))[3U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
#endif // VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3

    holder[0U] = 0U;
    holder[1U] = 0U;
    holder[2U] = 0U;
    holder[3U] = 0U;
    // cppcheck-suppress-end unreadVariable

#endif // VERUM_STANDARD_FIPS_140_3_DEF
}
