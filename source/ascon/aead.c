/**
 * @file       aead.c
 * @brief      NIST SP 800-232 ASCON AEAD-128.
 * @details    Authenticated Encryption with Associated Data (AEAD) implementation,
 *             configurable for memory efficiency xor performance via explicit 32-bit
 *             operations over the 320-bit (five 64-bit word) state machine [OPT-A_0]
 *             on 32-bit targets without compiler-synthesized 64-bit arithmetic.
 *             Supports both bit-interleaved and direct-halves representations, as well as
 *             runtime vs. pre-interleaved keys and unrolled vs. compact permutation execution.
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
#include "macro.h"

/**
 * @internal
 * @ref          NIST SP 800-232 Appendix B
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        𝐼𝑉 ← 0x00001000808c0001
 * @details      Stored as π(𝐼𝑉) = { E, O } or little-endian (L, H) pair.
 * @optimization [OPT-A_0] Pre-interleaved at compile time; no runtime π on the IV.
 */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
static const uint32_t VERUM_ASCON_AEAD128_initialization_vector[2U] = {
    0x00400201UL,
    0x00008A00UL
};
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
static const uint32_t VERUM_ASCON_AEAD128_initialization_vector[2U] = {
    0x00001000UL,
    0x808C0001UL
};
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */



/**
 * @internal
 * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
 * @brief        Ascon-AEAD128 encryption processing core.
 * @details      Executes the pure mathematical cipher: bit-interleaved state initialization,
 *               associated data absorption, ciphertext generation, and authentication tag
 *               computation. Separated as a leaf processing engine to eliminate recursive
 *               call graph cycles (MISRA C:2012 Rule 17.2) between public API entry points
 *               and FIPS 140-3 pre-operational / conditional self-tests.
 *
 * @warning      @p key, @p nonce, @p plaintext, and @p authentication_tag must not be NULL.
 * @warning      @p plaintext, @p associated_data, and @p authentication_tag must be 4-byte aligned.
 *
 * @param[in]     key                128-bit secret key (four 32-bit LE words).
 * @param[in]     nonce              128-bit public nonce (four 32-bit LE words).
 * @param[in,out] plaintext          Entry: plaintext; Return: ciphertext in place.
 * @param[in]     plaintext_size     Byte length of @p plaintext.
 * @param[in]     associated_data    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Associated data buffer.
 * @param[in]     associated_size    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Byte length of @p associated_data.
 * @param[out]    authentication_tag 128-bit authentication tag output buffer.
 */
#ifdef VERUM_STANDARD_FIPS_140_3_DEF
VERUM_ATTR_NOINLINE static void VERUM_ASCON_AEAD128_encrypt_process(const uint32_t key[4U],
                                                                    const uint32_t nonce[4U],
                                                                    uint8_t *plaintext,
                                                                    const uint32_t plaintext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                                                    const uint8_t *associated_data,
                                                                    const uint32_t associated_size,
#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */
                                                                    uint32_t authentication_tag[4U])
#else
VERUM_ATTR_INLINE static void VERUM_ASCON_AEAD128_encrypt_process(const uint32_t key[4U],
                                                                  const uint32_t nonce[4U],
                                                                  uint8_t *plaintext,
                                                                  const uint32_t plaintext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                                                  const uint8_t *associated_data,
                                                                  const uint32_t associated_size,
#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */
                                                                  uint32_t authentication_tag[4U])
#endif
{
    // cppcheck-suppress misra-c2012-1.4 ; DEV-004: C11 defines _Alignas behavior; explicit alignment is needed for these fixed-size staging buffers.
    _Alignas(uint32_t) uint8_t last_block_plaintext[16U];

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        𝐼𝑉 ← 0x00001000808c0001; S ← 𝐼𝑉 ‖ 𝐾 ‖ 𝑁
     * @details      Initializes the 320-bit state as the concatenation of 64-bit 𝐼𝑉, 128-bit 𝐾, and 128-bit 𝑁.
     *               Bit-interleaved state [OPT-A_0]: state_2w = E_w (even bits of S_w),
     *               state_{2w+1} = O_w (odd bits of S_w).
     * @optimization [OPT-A_12] π applied in place on the shared aligned staging buffer (skipped if pre-interleaved),
     *               ordering nonce before key so π(𝐾) remains staged across Ascon-p[12] for the post-initialization
     *               key XOR without recomputing π(𝐾).
     *               [OPT-A_13] 320-bit state and 320-bit S-box scratch storage pinned to twenty
     *               32-bit register variables (state_0..state_9, holder_0..holder_9).
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    register uint32_t state_0 = VERUM_ASCON_AEAD128_initialization_vector[0U];
    register uint32_t state_1 = VERUM_ASCON_AEAD128_initialization_vector[1U];
    #ifdef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    register uint32_t state_2 = key[0U];
    register uint32_t state_3 = key[1U];
    register uint32_t state_4 = key[2U];
    register uint32_t state_5 = key[3U];
    register uint32_t state_6 = nonce[0U];
    register uint32_t state_7 = nonce[1U];
    register uint32_t state_8 = nonce[2U];
    register uint32_t state_9 = nonce[3U];
    #else /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U] = nonce[0U];
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U] = nonce[1U];
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U] = nonce[2U];
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U] = nonce[3U];
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U]);
    register uint32_t state_6 = ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U];
    register uint32_t state_7 = ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U];
    register uint32_t state_8 = ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U];
    register uint32_t state_9 = ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U];

    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U] = key[0U];
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U] = key[1U];
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U] = key[2U];
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U] = key[3U];
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U]);
    register uint32_t state_2 = ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U];
    register uint32_t state_3 = ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U];
    register uint32_t state_4 = ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U];
    register uint32_t state_5 = ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3
    #endif /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    register uint32_t state_0 = VERUM_ASCON_AEAD128_initialization_vector[1U];
    register uint32_t state_1 = VERUM_ASCON_AEAD128_initialization_vector[0U];
    register uint32_t state_2 = key[0U];
    register uint32_t state_3 = key[1U];
    register uint32_t state_4 = key[2U];
    register uint32_t state_5 = key[3U];
    register uint32_t state_6 = nonce[0U];
    register uint32_t state_7 = nonce[1U];
    register uint32_t state_8 = nonce[2U];
    register uint32_t state_9 = nonce[3U];
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

#ifdef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
    register uint32_t holder_0;
    register uint32_t holder_1;
    register uint32_t holder_2;
    register uint32_t holder_3;
    register uint32_t holder_4;
    register uint32_t holder_5;
    register uint32_t holder_6;
    register uint32_t holder_7;
    register uint32_t holder_8;
    register uint32_t holder_9;
#else /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
    uint32_t state[10U];
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     * @optimization [OPT-A_7] Selects compact loop call (VERUM_OPTIMIZATION_MEMORY_DEF) or
     *               12 unrolled fused inline rounds (p_S + 11x p_merged + p_L).
     */
    VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                            state_5, state_6, state_7, state_8, state_9,
                            holder_0, holder_1, holder_2, holder_3, holder_4,
                            holder_5, holder_6, holder_7, holder_8, holder_9);

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        S ← S ⊕ (0^[192] ‖ π(𝐾))
     * @optimization [OPT-A_12] Reuses π(𝐾) already staged in last_block_plaintext from state
     *               initialization, avoiding duplicate key interleaving and extra stack.
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    #ifdef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    state_6 = state_6 ^ key[0U];
    state_7 = state_7 ^ key[1U];
    state_8 = state_8 ^ key[2U];
    state_9 = state_9 ^ key[3U];
    #else /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    state_6 = state_6 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U];
    state_7 = state_7 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U];
    state_8 = state_8 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U];
    state_9 = state_9 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3
    #endif /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    state_6 = state_6 ^ key[0U];
    state_7 = state_7 ^ key[1U];
    state_8 = state_8 ^ key[2U];
    state_9 = state_9 ^ key[3U];
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

    uint32_t block_counter;
    uint32_t last_block_byte_index;

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

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
         * @optimization [OPT-A_12] Shared aligned staging buffer stages π(𝐴𝑖); no extra stack.
         */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[0U];
        ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[1U];
        ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[2U];
        ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[3U];
        VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U]);
        VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U]);
        state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U];
        state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U];
        state_2 = state_2 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U];
        state_3 = state_3 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U];
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[0U];
        state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[1U];
        state_2 = state_2 ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[2U];
        state_3 = state_3 ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[3U];
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        // cppcheck-suppress-end misra-c2012-11.3
        associated_data += 16U;

        /**
         * @internal
         * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑖) ‖ S[128∶319])
         */
        VERUM_ASCON_PERMUTE_P8(state_0, state_1, state_2, state_3, state_4,
                               state_5, state_6, state_7, state_8, state_9,
                               holder_0, holder_1, holder_2, holder_3, holder_4,
                               holder_5, holder_6, holder_7, holder_8, holder_9);
    }

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief 𝐴𝑚 ← pad(̃𝐴𝑚, 128)
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
    last_block_byte_index = associated_size & 0xFU;
    last_block_plaintext[last_block_byte_index] = 0x01U;

    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_plaintext[last_block_byte_index] = associated_data[last_block_byte_index];
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        S[0∶127] ← S[0∶127] ⊕ π(𝐴𝑚)
     * @optimization [OPT-A_12] π applied in place on the aligned staging buffer.
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U]);
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U];
    state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U];
    state_2 = state_2 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U];
    state_3 = state_3 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑚) ‖ S[128∶319])
     */
    VERUM_ASCON_PERMUTE_P8(state_0, state_1, state_2, state_3, state_4,
                           state_5, state_6, state_7, state_8, state_9,
                           holder_0, holder_1, holder_2, holder_3, holder_4,
                           holder_5, holder_6, holder_7, holder_8, holder_9);

#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */

    /**
     * @internal
     * @ref     NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief   S ← S ⊕ (0^[319] ‖ 1)
     * @details Bit 63 of S4 is odd (2·31 + 1), so it maps to bit 31 of O_4 (state[9U]).
     */
    state_9 = state_9 ^ 0x80000000UL;

    block_counter = plaintext_size >> 4U;

    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @brief        S[0∶127] ← S[0∶127] ⊕ π(𝑃𝑖); 𝐶𝑖 ← π⁻¹(S[0∶127])
         * @optimization [OPT-A_12] π(𝑃𝑖) and π⁻¹(S[0∶127]) applied in place on the aligned
         *               caller buffer; no extra stack or word copies.
         */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[0U]);
        VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[2U]);
        state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[0U];
        state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[1U];
        state_2 = state_2 ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[2U];
        state_3 = state_3 ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[3U];
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[0U] = state_0;
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[1U] = state_1;
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[2U] = state_2;
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[3U] = state_3;
        VERUM_ASCON_deinterleave(&((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[0U]);
        VERUM_ASCON_deinterleave(&((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[2U]);
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[0U];
        state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[1U];
        state_2 = state_2 ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[2U];
        state_3 = state_3 ^ ((const uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[3U];
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[0U] = state_0;
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[1U] = state_1;
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[2U] = state_2;
        ((uint32_t *) __builtin_assume_aligned(plaintext, sizeof(uint32_t)))[3U] = state_3;
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        // cppcheck-suppress-end misra-c2012-11.3
        plaintext += 16U;

        /**
         * @internal
         * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8](S)
         */
        VERUM_ASCON_PERMUTE_P8(state_0, state_1, state_2, state_3, state_4,
                               state_5, state_6, state_7, state_8, state_9,
                               holder_0, holder_1, holder_2, holder_3, holder_4,
                               holder_5, holder_6, holder_7, holder_8, holder_9);
    }

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief pad(̃𝑃𝑛, 128)
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
    last_block_byte_index = plaintext_size & 0xFU;
    uint32_t last_block_byte_index_holder = last_block_byte_index;
    last_block_plaintext[last_block_byte_index] = 0x01U;
    /* TR: opt 32_bit cpy if possible */
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
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U]);
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U];
    state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U];
    state_2 = state_2 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U];
    state_3 = state_3 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U];

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        𝐶𝑛 ← π⁻¹(S[0∶127])[0∶ℓ−1]
     * @optimization [OPT-A_12] Reuses last_block_plaintext to stage π⁻¹(S[0∶127]); no extra stack.
     */
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U] = state_0;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U] = state_1;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U] = state_2;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U] = state_3;
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    VERUM_ASCON_deinterleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_deinterleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U]);
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    // cppcheck-suppress-end misra-c2012-11.3
    while (0U < last_block_byte_index_holder)
    {
        --last_block_byte_index_holder;
        plaintext[last_block_byte_index_holder] = last_block_plaintext[last_block_byte_index_holder];
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        S ← S ⊕ (0^[128] ∥ π(𝐾) ∥ 0^[64])
     * @optimization [OPT-A_12] Reuses last_block_plaintext to stage π(𝐾); no persistent interleaved key copy.
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    #ifdef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    state_4 = state_4 ^ key[0U];
    state_5 = state_5 ^ key[1U];
    state_6 = state_6 ^ key[2U];
    state_7 = state_7 ^ key[3U];
    #else /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U] = key[0U];
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U] = key[1U];
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U] = key[2U];
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U] = key[3U];
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U]);
    state_4 = state_4 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U];
    state_5 = state_5 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U];
    state_6 = state_6 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U];
    state_7 = state_7 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3
    #endif /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    state_4 = state_4 ^ key[0U];
    state_5 = state_5 ^ key[1U];
    state_6 = state_6 ^ key[2U];
    state_7 = state_7 ^ key[3U];
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
    VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                            state_5, state_6, state_7, state_8, state_9,
                            holder_0, holder_1, holder_2, holder_3, holder_4,
                            holder_5, holder_6, holder_7, holder_8, holder_9);

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.1 Algorithm 3 Ascon-AEAD128.enc(𝐾,𝑁,𝐴,𝑃)
     * @brief        𝑇 ← π⁻¹(S[192∶319]) ⊕ 𝐾
     * @optimization [OPT-A_12] π⁻¹ applied in place on the tag words; no staging copy.
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    #ifdef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    authentication_tag[0U] = state_6 ^ key[0U];
    authentication_tag[1U] = state_7 ^ key[1U];
    authentication_tag[2U] = state_8 ^ key[2U];
    authentication_tag[3U] = state_9 ^ key[3U];
    VERUM_ASCON_deinterleave(&authentication_tag[0U]);
    VERUM_ASCON_deinterleave(&authentication_tag[2U]);
    #else /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
    authentication_tag[0U] = state_6;
    authentication_tag[1U] = state_7;
    authentication_tag[2U] = state_8;
    authentication_tag[3U] = state_9;
    VERUM_ASCON_deinterleave(&authentication_tag[0U]);
    VERUM_ASCON_deinterleave(&authentication_tag[2U]);
    authentication_tag[0U] = authentication_tag[0U] ^ key[0U];
    authentication_tag[1U] = authentication_tag[1U] ^ key[1U];
    authentication_tag[2U] = authentication_tag[2U] ^ key[2U];
    authentication_tag[3U] = authentication_tag[3U] ^ key[3U];
    #endif /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    authentication_tag[0U] = state_6 ^ key[0U];
    authentication_tag[1U] = state_7 ^ key[1U];
    authentication_tag[2U] = state_8 ^ key[2U];
    authentication_tag[3U] = state_9 ^ key[3U];
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

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
    state_0 = 0U;
    state_1 = 0U;
    state_2 = 0U;
    state_3 = 0U;
    state_4 = 0U;
    state_5 = 0U;
    state_6 = 0U;
    state_7 = 0U;
    state_8 = 0U;
    state_9 = 0U;

#ifdef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
    holder_0 = 0U;
    holder_1 = 0U;
    holder_2 = 0U;
    holder_3 = 0U;
    holder_4 = 0U;
    holder_5 = 0U;
    holder_6 = 0U;
    holder_7 = 0U;
    holder_8 = 0U;
    holder_9 = 0U;
#else /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
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
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */

    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_plaintext, sizeof(uint32_t)))[3U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
    // cppcheck-suppress-end unreadVariable
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */

}



/**
 * @internal
 * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
 * @brief        Ascon-AEAD128 decryption processing core.
 * @details      Executes the pure mathematical cipher: bit-interleaved state initialization,
 *               associated data absorption, plaintext extraction, and authentication tag
 *               recomputation. Separated as a leaf processing engine to eliminate recursive
 *               call graph cycles (MISRA C:2012 Rule 17.2) between public API entry points
 *               and FIPS 140-3 pre-operational / conditional self-tests.
 *
 * @warning      @p key, @p nonce, @p ciphertext, and @p authentication_tag must not be NULL.
 * @warning      @p ciphertext, @p associated_data, and @p authentication_tag must be 4-byte aligned.
 *
 * @param[in]     key                128-bit secret key (four 32-bit LE words).
 * @param[in]     nonce              128-bit public nonce matching encryption.
 * @param[in,out] ciphertext         Entry: ciphertext; Return: plaintext in place.
 * @param[in]     ciphertext_size    Byte length of @p ciphertext.
 * @param[in]     associated_data    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Associated data buffer.
 * @param[in]     associated_size    *(VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF)* Byte length of @p associated_data.
 * @param[out]    authentication_tag Recomputed 128-bit candidate tag.
 */
#ifdef VERUM_STANDARD_FIPS_140_3_DEF
VERUM_ATTR_NOINLINE static void VERUM_ASCON_AEAD128_decrypt_process(const uint32_t key[4U],
                                                                    const uint32_t nonce[4U],
                                                                    uint8_t *ciphertext,
                                                                    const uint32_t ciphertext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                                                    const uint8_t *associated_data,
                                                                    const uint32_t associated_size,
#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */
                                                                    uint32_t authentication_tag[4U])
#else
VERUM_ATTR_INLINE static void VERUM_ASCON_AEAD128_decrypt_process(const uint32_t key[4U],
                                                                  const uint32_t nonce[4U],
                                                                  uint8_t *ciphertext,
                                                                  const uint32_t ciphertext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                                                  const uint8_t *associated_data,
                                                                  const uint32_t associated_size,
#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */
                                                                  uint32_t authentication_tag[4U])
#endif
{
    // cppcheck-suppress misra-c2012-1.4 ; DEV-004: C11 defines _Alignas behavior; explicit alignment is needed for these fixed-size staging buffers.
    _Alignas(uint32_t) uint8_t last_block_ciphertext[16U];

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        𝐼𝑉 ← 0x00001000808c0001; S ← 𝐼𝑉 ‖ 𝐾 ‖ 𝑁
     * @details      Initializes the 320-bit state as the concatenation of 64-bit 𝐼𝑉, 128-bit 𝐾, and 128-bit 𝑁.
     *               Bit-interleaved state [OPT-A_0]: state_2w = E_w (even bits of S_w),
     *               state_{2w+1} = O_w (odd bits of S_w).
     * @optimization [OPT-A_12] π applied in place on the shared aligned staging buffer (skipped if pre-interleaved),
     *               ordering nonce before key so π(𝐾) remains staged across Ascon-p[12] for the post-initialization
     *               key XOR without recomputing π(𝐾).
     *               [OPT-A_13] 320-bit state and 320-bit S-box scratch storage pinned to twenty
     *               32-bit register variables (state_0..state_9, holder_0..holder_9).
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    register uint32_t state_0 = VERUM_ASCON_AEAD128_initialization_vector[0U];
    register uint32_t state_1 = VERUM_ASCON_AEAD128_initialization_vector[1U];
    #ifdef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    register uint32_t state_2 = key[0U];
    register uint32_t state_3 = key[1U];
    register uint32_t state_4 = key[2U];
    register uint32_t state_5 = key[3U];
    register uint32_t state_6 = nonce[0U];
    register uint32_t state_7 = nonce[1U];
    register uint32_t state_8 = nonce[2U];
    register uint32_t state_9 = nonce[3U];
    #else /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] = nonce[0U];
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] = nonce[1U];
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] = nonce[2U];
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] = nonce[3U];
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U]);
    register uint32_t state_6 = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U];
    register uint32_t state_7 = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U];
    register uint32_t state_8 = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U];
    register uint32_t state_9 = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U];

    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] = key[0U];
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] = key[1U];
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] = key[2U];
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] = key[3U];
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U]);
    register uint32_t state_2 = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U];
    register uint32_t state_3 = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U];
    register uint32_t state_4 = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U];
    register uint32_t state_5 = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3
    #endif /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    register uint32_t state_0 = VERUM_ASCON_AEAD128_initialization_vector[1U];
    register uint32_t state_1 = VERUM_ASCON_AEAD128_initialization_vector[0U];
    register uint32_t state_2 = key[0U];
    register uint32_t state_3 = key[1U];
    register uint32_t state_4 = key[2U];
    register uint32_t state_5 = key[3U];
    register uint32_t state_6 = nonce[0U];
    register uint32_t state_7 = nonce[1U];
    register uint32_t state_8 = nonce[2U];
    register uint32_t state_9 = nonce[3U];
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

#ifdef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
    register uint32_t holder_0;
    register uint32_t holder_1;
    register uint32_t holder_2;
    register uint32_t holder_3;
    register uint32_t holder_4;
    register uint32_t holder_5;
    register uint32_t holder_6;
    register uint32_t holder_7;
    register uint32_t holder_8;
    register uint32_t holder_9;
#else /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
    uint32_t state[10U];
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     * @optimization [OPT-A_7] Selects compact loop call (VERUM_OPTIMIZATION_MEMORY_DEF) or
     *               12 unrolled fused inline rounds (p_S + 11x p_merged + p_L).
     */
    VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                            state_5, state_6, state_7, state_8, state_9,
                            holder_0, holder_1, holder_2, holder_3, holder_4,
                            holder_5, holder_6, holder_7, holder_8, holder_9);

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        S ← S ⊕ (0^[192] ‖ π(𝐾))
     * @optimization [OPT-A_12] Reuses π(𝐾) already staged in last_block_ciphertext from state
     *               initialization, avoiding duplicate key interleaving and extra stack.
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    #ifdef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    state_6 = state_6 ^ key[0U];
    state_7 = state_7 ^ key[1U];
    state_8 = state_8 ^ key[2U];
    state_9 = state_9 ^ key[3U];
    #else /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    state_6 = state_6 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U];
    state_7 = state_7 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U];
    state_8 = state_8 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U];
    state_9 = state_9 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3
    #endif /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    state_6 = state_6 ^ key[0U];
    state_7 = state_7 ^ key[1U];
    state_8 = state_8 ^ key[2U];
    state_9 = state_9 ^ key[3U];
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

    uint32_t block_counter;
    uint32_t last_block_byte_index;
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF

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
         * @optimization [OPT-A_12] Shared aligned staging buffer stages π(𝐴𝑖); no extra stack.
         */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[0U];
        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[1U];
        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[2U];
        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] = ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[3U];
        VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U]);
        VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U]);
        state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U];
        state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U];
        state_2 = state_2 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U];
        state_3 = state_3 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U];
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[0U];
        state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[1U];
        state_2 = state_2 ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[2U];
        state_3 = state_3 ^ ((const uint32_t *) __builtin_assume_aligned(associated_data, sizeof(uint32_t)))[3U];
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        // cppcheck-suppress-end misra-c2012-11.3
        associated_data += 16U;

        /**
         * @internal
         * @ref   NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑖) ‖ S[128∶319])
         */
        VERUM_ASCON_PERMUTE_P8(state_0, state_1, state_2, state_3, state_4,
                               state_5, state_6, state_7, state_8, state_9,
                               holder_0, holder_1, holder_2, holder_3, holder_4,
                               holder_5, holder_6, holder_7, holder_8, holder_9);
    }

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief 𝐴𝑚 ← pad(̃𝐴𝑚, 128)
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
    last_block_byte_index = associated_size & 0xFU;
    last_block_ciphertext[last_block_byte_index] = 0x01U;

    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_ciphertext[last_block_byte_index] = associated_data[last_block_byte_index];
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        S[0∶127] ← S[0∶127] ⊕ π(𝐴𝑚)
     * @optimization [OPT-A_12] π applied in place on the aligned staging buffer.
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U]);
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U];
    state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U];
    state_2 = state_2 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U];
    state_3 = state_3 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8]((S[0∶127] ⊕ 𝐴𝑚) ‖ S[128∶319])
     */
    VERUM_ASCON_PERMUTE_P8(state_0, state_1, state_2, state_3, state_4,
                           state_5, state_6, state_7, state_8, state_9,
                           holder_0, holder_1, holder_2, holder_3, holder_4,
                           holder_5, holder_6, holder_7, holder_8, holder_9);

#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */

    /**
     * @internal
     * @ref     NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief   S ← S ⊕ (0^[319] ‖ 1)
     * @details Bit 63 of S4 is odd (2·31 + 1), so it maps to bit 31 of O_4 (state_9).
     */
    state_9 = state_9 ^ 0x80000000UL;

    block_counter = ciphertext_size >> 4U;

    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
         * @brief        𝑃𝑖 ← π⁻¹(S[0∶127]) ⊕ 𝐶𝑖; S[0∶127] ← π(𝐶𝑖)
         * @feature      In-place decryption preserving 𝐶𝑖 for sponge state replacement.
         * @optimization [OPT-A_12] Shared staging buffer stages π⁻¹(S[0∶127]) and dead register
         *               variables holder_0..holder_3 preserve 𝐶𝑖, avoiding extra stack allocation.
         */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[0U]);
        VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[2U]);

        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] = state_0;
        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] = state_1;
        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] = state_2;
        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] = state_3;

        state_0 = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[0U];
        state_1 = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[1U];
        state_2 = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[2U];
        state_3 = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[3U];

        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[0U] = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] ^ state_0;
        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[1U] = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] ^ state_1;
        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[2U] = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] ^ state_2;
        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[3U] = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] ^ state_3;

        VERUM_ASCON_deinterleave(&((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[0U]);
        VERUM_ASCON_deinterleave(&((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[2U]);
        // cppcheck-suppress-end misra-c2012-11.3
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] = state_0;
        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] = state_1;
        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] = state_2;
        ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] = state_3;

        state_0 = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[0U];
        state_1 = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[1U];
        state_2 = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[2U];
        state_3 = ((const uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[3U];

        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[0U] = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] ^ state_0;
        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[1U] = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] ^ state_1;
        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[2U] = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] ^ state_2;
        ((uint32_t *) __builtin_assume_aligned(ciphertext, sizeof(uint32_t)))[3U] = ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] ^ state_3;
        // cppcheck-suppress-end misra-c2012-11.3
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        ciphertext += 16U;

        /**
         * @internal
         * @ref   NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[8](S)
         */
        VERUM_ASCON_PERMUTE_P8(state_0, state_1, state_2, state_3, state_4,
                               state_5, state_6, state_7, state_8, state_9,
                               holder_0, holder_1, holder_2, holder_3, holder_4,
                               holder_5, holder_6, holder_7, holder_8, holder_9);
    }

    last_block_byte_index = ciphertext_size & 0xFU;
    uint32_t last_block_byte_index_holder = last_block_byte_index;

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        𝑃𝑛 ← π⁻¹(S[0∶127])[0∶ℓ−1] ⊕ ̃𝐶𝑛
     * @optimization [OPT-A_12] Shared staging buffer stages π⁻¹(S[0∶127]); no extra stack.
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] = state_0;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] = state_1;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] = state_2;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] = state_3;
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    VERUM_ASCON_deinterleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_deinterleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U]);
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    // cppcheck-suppress-end misra-c2012-11.3
    while (0U < last_block_byte_index_holder)
    {
        --last_block_byte_index_holder;
        ciphertext[last_block_byte_index_holder] = last_block_ciphertext[last_block_byte_index_holder] ^ ciphertext[last_block_byte_index_holder];
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
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
    last_block_ciphertext[last_block_byte_index] = 0x01U;
    /* TR: opt 32_bit cpy if possible */
    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_ciphertext[last_block_byte_index] = ciphertext[last_block_byte_index];
    }
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U]);
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U];
    state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U];
    state_2 = state_2 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U];
    state_3 = state_3 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        S ← S ⊕ (0^[128] ∥ π(𝐾) ∥ 0^[64])
     * @optimization [OPT-A_12] Shared staging buffer stages π(𝐾); no persistent interleaved key copy.
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    #ifdef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    state_4 = state_4 ^ key[0U];
    state_5 = state_5 ^ key[1U];
    state_6 = state_6 ^ key[2U];
    state_7 = state_7 ^ key[3U];
    #else /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] = key[0U];
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] = key[1U];
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] = key[2U];
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] = key[3U];
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U]);
    VERUM_ASCON_interleave(&((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U]);
    state_4 = state_4 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U];
    state_5 = state_5 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U];
    state_6 = state_6 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U];
    state_7 = state_7 ^ ((const uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U];
    // cppcheck-suppress-end misra-c2012-11.3
    #endif /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    state_4 = state_4 ^ key[0U];
    state_5 = state_5 ^ key[1U];
    state_6 = state_6 ^ key[2U];
    state_7 = state_7 ^ key[3U];
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
    VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                            state_5, state_6, state_7, state_8, state_9,
                            holder_0, holder_1, holder_2, holder_3, holder_4,
                            holder_5, holder_6, holder_7, holder_8, holder_9);

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 4.1.2 Algorithm 4 Ascon-AEAD128.dec(𝐾,𝑁,𝐴,C,T)
     * @brief        𝑇 ← π⁻¹(S[192∶319]) ⊕ 𝐾
     * @optimization [OPT-A_12] π⁻¹ applied in place on the tag words; no staging copy.
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    #ifdef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    authentication_tag[0U] = state_6 ^ key[0U];
    authentication_tag[1U] = state_7 ^ key[1U];
    authentication_tag[2U] = state_8 ^ key[2U];
    authentication_tag[3U] = state_9 ^ key[3U];
    VERUM_ASCON_deinterleave(&authentication_tag[0U]);
    VERUM_ASCON_deinterleave(&authentication_tag[2U]);
    #else /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
    authentication_tag[0U] = state_6;
    authentication_tag[1U] = state_7;
    authentication_tag[2U] = state_8;
    authentication_tag[3U] = state_9;
    VERUM_ASCON_deinterleave(&authentication_tag[0U]);
    VERUM_ASCON_deinterleave(&authentication_tag[2U]);
    authentication_tag[0U] = authentication_tag[0U] ^ key[0U];
    authentication_tag[1U] = authentication_tag[1U] ^ key[1U];
    authentication_tag[2U] = authentication_tag[2U] ^ key[2U];
    authentication_tag[3U] = authentication_tag[3U] ^ key[3U];
    #endif /* VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF */
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    authentication_tag[0U] = state_6 ^ key[0U];
    authentication_tag[1U] = state_7 ^ key[1U];
    authentication_tag[2U] = state_8 ^ key[2U];
    authentication_tag[3U] = state_9 ^ key[3U];
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

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
    state_0 = 0U;
    state_1 = 0U;
    state_2 = 0U;
    state_3 = 0U;
    state_4 = 0U;
    state_5 = 0U;
    state_6 = 0U;
    state_7 = 0U;
    state_8 = 0U;
    state_9 = 0U;

#ifdef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
    holder_0 = 0U;
    holder_1 = 0U;
    holder_2 = 0U;
    holder_3 = 0U;
    holder_4 = 0U;
    holder_5 = 0U;
    holder_6 = 0U;
    holder_7 = 0U;
    holder_8 = 0U;
    holder_9 = 0U;
#else /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
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
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */

    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[1U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[2U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_ciphertext, sizeof(uint32_t)))[3U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
    // cppcheck-suppress-end unreadVariable

#endif /* VERUM_STANDARD_FIPS_140_3_DEF */
}


#ifdef VERUM_STANDARD_FIPS_140_3_DEF
static VERUM_FIPS1403_state_t VERUM_FIPS1403_ASCON_AEAD128_operational_state = VERUM_FIPS1403_STATE_UNINITIALIZED;
static uint32_t VERUM_FIPS1403_ASCON_AEAD128_verified_key[4U] = { 0U, 0U, 0U, 0U };
static uint8_t VERUM_FIPS1403_ASCON_AEAD128_has_verified_key = 0U;

/**
 * @internal
 * @ref        ISO/IEC 19790:2012 Section 7.9.6 Conditional self-tests
 * @ref        FIPS 140-3 IG Section 9.6
 * @see        https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
 * @see        https://doi.org/10.6028/NIST.FIPS.140-3
 * @brief      Pair-wise consistency check on candidate key prior to first use.
 * @details    Encrypts and decrypts empty plaintext using the candidate key and an
 *             internal test nonce, verifying that the computed tags match.
 * @warning    @p key must not be NULL and must be 4-byte aligned.
 * @param[in]  key 128-bit candidate secret key buffer.
 * @return     0 on success (identical tags), non-zero on failure (accumulated bit difference).
 */
static uint32_t VERUM_FIPS1403_ASCON_AEAD128_conditional_key_test(const uint32_t key[4U])
{
    VERUM_FIPS1403_state_t previous_state = VERUM_FIPS1403_ASCON_AEAD128_operational_state;
    VERUM_FIPS1403_ASCON_AEAD128_operational_state = VERUM_FIPS1403_STATE_INITIALIZING;

    uint32_t authentication_tag_encrypted[4U] = { 0U, 0U, 0U, 0U };
    uint32_t authentication_tag_decrypted[4U] = { 0U, 0U, 0U, 0U };
    uint8_t dummy_buffer[1U] = { 0U };
#ifdef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
    static const uint32_t VERUM_FIPS1403_ASCON_AEAD128_conditional_test_nonce[4U] = { 0x32321010UL, 0x11001100UL, 0x32321010UL, 0x33223322UL };
#else
    static const uint32_t VERUM_FIPS1403_ASCON_AEAD128_conditional_test_nonce[4U] = { 0x03020100UL, 0x07060504UL, 0x0B0A0908UL, 0x0F0E0D0CUL };
#endif

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    static const uint8_t VERUM_FIPS1403_ASCON_AEAD128_conditional_test_associated_data[1U] = { 0x00U };
    VERUM_ASCON_AEAD128_encrypt_process(key,
                                        VERUM_FIPS1403_ASCON_AEAD128_conditional_test_nonce,
                                        dummy_buffer,
                                        0U,
                                        VERUM_FIPS1403_ASCON_AEAD128_conditional_test_associated_data,
                                        1U,
                                        authentication_tag_encrypted);
    VERUM_ASCON_AEAD128_decrypt_process(key,
                                        VERUM_FIPS1403_ASCON_AEAD128_conditional_test_nonce,
                                        dummy_buffer,
                                        0U,
                                        VERUM_FIPS1403_ASCON_AEAD128_conditional_test_associated_data,
                                        1U,
                                        authentication_tag_decrypted);
#else
    VERUM_ASCON_AEAD128_encrypt_process(key, VERUM_FIPS1403_ASCON_AEAD128_conditional_test_nonce, dummy_buffer, 0U, authentication_tag_encrypted);
    VERUM_ASCON_AEAD128_decrypt_process(key, VERUM_FIPS1403_ASCON_AEAD128_conditional_test_nonce, dummy_buffer, 0U, authentication_tag_decrypted);
#endif

    VERUM_FIPS1403_ASCON_AEAD128_operational_state = previous_state;

    uint32_t difference = 0U;
    uint32_t word_index = 0U;
    do
    {
        difference = difference | (authentication_tag_encrypted[word_index] ^ authentication_tag_decrypted[word_index]);
        ++word_index;
    }
    while (word_index < 4U);

    /**
     * @internal
     * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
     * @ref   FIPS 140-3 IG
     * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
     * @see   https://doi.org/10.6028/NIST.FIPS.140-3
     * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
     */
    VERUM_ATTR_VOLATILE uint32_t * const volatile_tag_encrypted = (VERUM_ATTR_VOLATILE uint32_t *) authentication_tag_encrypted;
    volatile_tag_encrypted[0U] = 0U;
    volatile_tag_encrypted[1U] = 0U;
    volatile_tag_encrypted[2U] = 0U;
    volatile_tag_encrypted[3U] = 0U;
    VERUM_ATTR_VOLATILE uint32_t * const volatile_tag_decrypted = (VERUM_ATTR_VOLATILE uint32_t *) authentication_tag_decrypted;
    volatile_tag_decrypted[0U] = 0U;
    volatile_tag_decrypted[1U] = 0U;
    volatile_tag_decrypted[2U] = 0U;
    volatile_tag_decrypted[3U] = 0U;

    return difference;
}

/**
 * @internal
 * @ref        ISO/IEC 19790:2012 Section 7.9.5 Pre-operational self-tests
 * @ref        FIPS 140-3 IG Section 9.5
 * @see        https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
 * @see        https://doi.org/10.6028/NIST.FIPS.140-3
 * @brief      Execute FIPS 140-3 Known-Answer Test (KAT) for Ascon-AEAD128.
 * @details    Validates encryption and decryption against reference NIST SP 800-232 vectors.
 *             Transitions state to OPERATIONAL on success, or ERROR and traps on failure.
 * @param      void This test takes no external inputs; standard KAT vectors are self-contained.
 * @return     0 on success (identical tags), non-zero on error (accumulated bit difference).
 */
// cppcheck-suppress staticFunction ; DEV-006: Public library API is called by downstream applications; no in-repository caller is required.
// cppcheck-suppress misra-c2012-8.7 ; DEV-007: External linkage is required so downstream applications can link this public API.
uint32_t VERUM_FIPS1403_ASCON_AEAD128_self_test(void)
{
    uint32_t difference = 0U;

    if (VERUM_FIPS1403_ASCON_AEAD128_operational_state == VERUM_FIPS1403_STATE_ERROR)
    {
        difference = 1U;
        VERUM_FAULT_HANDLER();
    }
    else if (VERUM_FIPS1403_ASCON_AEAD128_operational_state != VERUM_FIPS1403_STATE_OPERATIONAL)
    {
        VERUM_FIPS1403_ASCON_AEAD128_operational_state = VERUM_FIPS1403_STATE_INITIALIZING;

#ifdef VERUM_ASCON_AEAD128_PREINTERLEAVED_DEF
        static const uint32_t VERUM_FIPS1403_ASCON_AEAD128_expected_key[4U] = { 0x32321010UL, 0x11001100UL, 0x32321010UL, 0x33223322UL };
        static const uint32_t VERUM_FIPS1403_ASCON_AEAD128_test_nonce[4U] = { 0x32321010UL, 0x11001100UL, 0x32321010UL, 0x33223322UL };
#else
        static const uint32_t VERUM_FIPS1403_ASCON_AEAD128_expected_key[4U] = { 0x03020100UL, 0x07060504UL, 0x0B0A0908UL, 0x0F0E0D0CUL };
        static const uint32_t VERUM_FIPS1403_ASCON_AEAD128_test_nonce[4U] = { 0x03020100UL, 0x07060504UL, 0x0B0A0908UL, 0x0F0E0D0CUL };
#endif
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
        static const uint8_t VERUM_FIPS1403_ASCON_AEAD128_test_associated_data[1U] = { 0x00U };
        static const uint32_t VERUM_FIPS1403_ASCON_AEAD128_expected_authentication_tag[4U] = { 0x9DB73A10UL, 0x21033A91UL, 0xA9157728UL, 0x8585BB79UL };
#else
        static const uint32_t VERUM_FIPS1403_ASCON_AEAD128_expected_authentication_tag[4U] = { 0x4BD62744UL, 0x51141E8EUL, 0x605944FCUL, 0xB09B83F0UL };
#endif
        uint8_t dummy_buffer[1U] = { 0U };
        uint32_t test_authentication_tag[4U] = { 0U, 0U, 0U, 0U };
        uint32_t decrypted_authentication_tag[4U] = { 0U, 0U, 0U, 0U };

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
        VERUM_ASCON_AEAD128_encrypt_process(VERUM_FIPS1403_ASCON_AEAD128_expected_key,
                                            VERUM_FIPS1403_ASCON_AEAD128_test_nonce,
                                            dummy_buffer,
                                            0U,
                                            VERUM_FIPS1403_ASCON_AEAD128_test_associated_data,
                                            1U,
                                            test_authentication_tag);
        VERUM_ASCON_AEAD128_decrypt_process(VERUM_FIPS1403_ASCON_AEAD128_expected_key,
                                            VERUM_FIPS1403_ASCON_AEAD128_test_nonce,
                                            dummy_buffer,
                                            0U,
                                            VERUM_FIPS1403_ASCON_AEAD128_test_associated_data,
                                            1U,
                                            decrypted_authentication_tag);
#else
        VERUM_ASCON_AEAD128_encrypt_process(VERUM_FIPS1403_ASCON_AEAD128_expected_key, VERUM_FIPS1403_ASCON_AEAD128_test_nonce, dummy_buffer, 0U, test_authentication_tag);
        VERUM_ASCON_AEAD128_decrypt_process(VERUM_FIPS1403_ASCON_AEAD128_expected_key, VERUM_FIPS1403_ASCON_AEAD128_test_nonce, dummy_buffer, 0U, decrypted_authentication_tag);
#endif

        uint32_t word_index = 0U;
        do
        {
            difference = difference | (test_authentication_tag[word_index] ^ VERUM_FIPS1403_ASCON_AEAD128_expected_authentication_tag[word_index]);
            difference = difference | (test_authentication_tag[word_index] ^ decrypted_authentication_tag[word_index]);
            ++word_index;
        }
        while (word_index < 4U);

        /**
         * @internal
         * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
         * @ref   FIPS 140-3 IG
         * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
         * @see   https://doi.org/10.6028/NIST.FIPS.140-3
         * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
         */
        VERUM_ATTR_VOLATILE uint32_t * const volatile_test_tag = (VERUM_ATTR_VOLATILE uint32_t *) test_authentication_tag;
        volatile_test_tag[0U] = 0U;
        volatile_test_tag[1U] = 0U;
        volatile_test_tag[2U] = 0U;
        volatile_test_tag[3U] = 0U;
        VERUM_ATTR_VOLATILE uint32_t * const volatile_decrypted_tag = (VERUM_ATTR_VOLATILE uint32_t *) decrypted_authentication_tag;
        volatile_decrypted_tag[0U] = 0U;
        volatile_decrypted_tag[1U] = 0U;
        volatile_decrypted_tag[2U] = 0U;
        volatile_decrypted_tag[3U] = 0U;

        if (difference != 0U)
        {
            VERUM_FIPS1403_ASCON_AEAD128_operational_state = VERUM_FIPS1403_STATE_ERROR;
            VERUM_FAULT_HANDLER();
        }
        else
        {
            VERUM_FIPS1403_ASCON_AEAD128_operational_state = VERUM_FIPS1403_STATE_OPERATIONAL;
        }
    }
    else
    {
        /* Already in operational state; difference remains 0U */
    }

    return difference;
}
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */


// cppcheck-suppress unusedFunction ; DEV-006: Public library API is called by downstream applications; no in-repository caller is required.
// cppcheck-suppress misra-c2012-8.7 ; DEV-007: External linkage is required so downstream applications can link this public API.
void VERUM_ASCON_AEAD128_encrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
                                 uint8_t *plaintext,
                                 const uint32_t plaintext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                 const uint8_t *associated_data,
                                 const uint32_t associated_size,
#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */
                                 uint32_t authentication_tag[4U])
{
#ifdef VERUM_STANDARD_FIPS_140_3_DEF
    if (VERUM_FIPS1403_ASCON_AEAD128_operational_state == VERUM_FIPS1403_STATE_ERROR)
    {
        /**
         * @internal
         * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
         * @ref   FIPS 140-3 IG
         * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
         * @see   https://doi.org/10.6028/NIST.FIPS.140-3
         * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
         */
        VERUM_ATTR_VOLATILE uint32_t * const volatile_authentication_tag = (VERUM_ATTR_VOLATILE uint32_t *) authentication_tag;
        volatile_authentication_tag[0U] = 0U;
        volatile_authentication_tag[1U] = 0U;
        volatile_authentication_tag[2U] = 0U;
        volatile_authentication_tag[3U] = 0U;
        VERUM_FAULT_HANDLER();
    }
    if (VERUM_FIPS1403_ASCON_AEAD128_operational_state == VERUM_FIPS1403_STATE_UNINITIALIZED)
    {
        if (VERUM_FIPS1403_ASCON_AEAD128_self_test() != 0U)
        {
            /**
             * @internal
             * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
             * @ref   FIPS 140-3 IG
             * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
             * @see   https://doi.org/10.6028/NIST.FIPS.140-3
             * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
             */
            VERUM_ATTR_VOLATILE uint32_t * const volatile_authentication_tag = (VERUM_ATTR_VOLATILE uint32_t *) authentication_tag;
            volatile_authentication_tag[0U] = 0U;
            volatile_authentication_tag[1U] = 0U;
            volatile_authentication_tag[2U] = 0U;
            volatile_authentication_tag[3U] = 0U;
            VERUM_FAULT_HANDLER();
        }
    }
    /* Conditional self-test (Section 9.6): Pair-wise consistency check on key prior to first use */
    if (VERUM_FIPS1403_ASCON_AEAD128_operational_state != VERUM_FIPS1403_STATE_INITIALIZING)
    {
        if ((VERUM_FIPS1403_ASCON_AEAD128_has_verified_key == 0U) ||
            (key[0U] != VERUM_FIPS1403_ASCON_AEAD128_verified_key[0U]) ||
            (key[1U] != VERUM_FIPS1403_ASCON_AEAD128_verified_key[1U]) ||
            (key[2U] != VERUM_FIPS1403_ASCON_AEAD128_verified_key[2U]) ||
            (key[3U] != VERUM_FIPS1403_ASCON_AEAD128_verified_key[3U]))
        {
            if (VERUM_FIPS1403_ASCON_AEAD128_conditional_key_test(key) != 0U)
            {
                VERUM_FIPS1403_ASCON_AEAD128_operational_state = VERUM_FIPS1403_STATE_ERROR;
                /**
                 * @internal
                 * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
                 * @ref   FIPS 140-3 IG
                 * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
                 * @see   https://doi.org/10.6028/NIST.FIPS.140-3
                 * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
                 */
                VERUM_ATTR_VOLATILE uint32_t * const volatile_authentication_tag = (VERUM_ATTR_VOLATILE uint32_t *) authentication_tag;
                volatile_authentication_tag[0U] = 0U;
                volatile_authentication_tag[1U] = 0U;
                volatile_authentication_tag[2U] = 0U;
                volatile_authentication_tag[3U] = 0U;
                VERUM_FAULT_HANDLER();
            }
            VERUM_FIPS1403_ASCON_AEAD128_verified_key[0U] = key[0U];
            VERUM_FIPS1403_ASCON_AEAD128_verified_key[1U] = key[1U];
            VERUM_FIPS1403_ASCON_AEAD128_verified_key[2U] = key[2U];
            VERUM_FIPS1403_ASCON_AEAD128_verified_key[3U] = key[3U];
            VERUM_FIPS1403_ASCON_AEAD128_has_verified_key = 1U;
        }
    }
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    VERUM_ASCON_AEAD128_encrypt_process(key, nonce, plaintext, plaintext_size, associated_data, associated_size, authentication_tag);
#else
    VERUM_ASCON_AEAD128_encrypt_process(key, nonce, plaintext, plaintext_size, authentication_tag);
#endif
}



// cppcheck-suppress unusedFunction ; DEV-006: Public library API is called by downstream applications; no in-repository caller is required.
// cppcheck-suppress misra-c2012-8.7 ; DEV-007: External linkage is required so downstream applications can link this public API.
void VERUM_ASCON_AEAD128_decrypt(const uint32_t key[4U],
                                 const uint32_t nonce[4U],
                                 uint8_t *ciphertext,
                                 const uint32_t ciphertext_size,
#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
                                 const uint8_t *associated_data,
                                 const uint32_t associated_size,
#endif /* VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF */
                                 uint32_t authentication_tag[4U])
{
#ifdef VERUM_STANDARD_FIPS_140_3_DEF
    if (VERUM_FIPS1403_ASCON_AEAD128_operational_state == VERUM_FIPS1403_STATE_ERROR)
    {
        /**
         * @internal
         * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
         * @ref   FIPS 140-3 IG
         * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
         * @see   https://doi.org/10.6028/NIST.FIPS.140-3
         * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
         */
        VERUM_ATTR_VOLATILE uint32_t * const volatile_authentication_tag = (VERUM_ATTR_VOLATILE uint32_t *) authentication_tag;
        volatile_authentication_tag[0U] = 0U;
        volatile_authentication_tag[1U] = 0U;
        volatile_authentication_tag[2U] = 0U;
        volatile_authentication_tag[3U] = 0U;
        VERUM_FAULT_HANDLER();
    }
    if (VERUM_FIPS1403_ASCON_AEAD128_operational_state == VERUM_FIPS1403_STATE_UNINITIALIZED)
    {
        if (VERUM_FIPS1403_ASCON_AEAD128_self_test() != 0U)
        {
            /**
             * @internal
             * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
             * @ref   FIPS 140-3 IG
             * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
             * @see   https://doi.org/10.6028/NIST.FIPS.140-3
             * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
             */
            VERUM_ATTR_VOLATILE uint32_t * const volatile_authentication_tag = (VERUM_ATTR_VOLATILE uint32_t *) authentication_tag;
            volatile_authentication_tag[0U] = 0U;
            volatile_authentication_tag[1U] = 0U;
            volatile_authentication_tag[2U] = 0U;
            volatile_authentication_tag[3U] = 0U;
            VERUM_FAULT_HANDLER();
        }
    }
    /* Conditional self-test (Section 9.6): Pair-wise consistency check on key prior to first use */
    if (VERUM_FIPS1403_ASCON_AEAD128_operational_state != VERUM_FIPS1403_STATE_INITIALIZING)
    {
        if ((VERUM_FIPS1403_ASCON_AEAD128_has_verified_key == 0U) ||
            (key[0U] != VERUM_FIPS1403_ASCON_AEAD128_verified_key[0U]) ||
            (key[1U] != VERUM_FIPS1403_ASCON_AEAD128_verified_key[1U]) ||
            (key[2U] != VERUM_FIPS1403_ASCON_AEAD128_verified_key[2U]) ||
            (key[3U] != VERUM_FIPS1403_ASCON_AEAD128_verified_key[3U]))
        {
            if (VERUM_FIPS1403_ASCON_AEAD128_conditional_key_test(key) != 0U)
            {
                VERUM_FIPS1403_ASCON_AEAD128_operational_state = VERUM_FIPS1403_STATE_ERROR;
                /**
                 * @internal
                 * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
                 * @ref   FIPS 140-3 IG
                 * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
                 * @see   https://doi.org/10.6028/NIST.FIPS.140-3
                 * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
                 */
                VERUM_ATTR_VOLATILE uint32_t * const volatile_authentication_tag = (VERUM_ATTR_VOLATILE uint32_t *) authentication_tag;
                volatile_authentication_tag[0U] = 0U;
                volatile_authentication_tag[1U] = 0U;
                volatile_authentication_tag[2U] = 0U;
                volatile_authentication_tag[3U] = 0U;
                VERUM_FAULT_HANDLER();
            }
            VERUM_FIPS1403_ASCON_AEAD128_verified_key[0U] = key[0U];
            VERUM_FIPS1403_ASCON_AEAD128_verified_key[1U] = key[1U];
            VERUM_FIPS1403_ASCON_AEAD128_verified_key[2U] = key[2U];
            VERUM_FIPS1403_ASCON_AEAD128_verified_key[3U] = key[3U];
            VERUM_FIPS1403_ASCON_AEAD128_has_verified_key = 1U;
        }
    }
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */

#ifdef VERUM_ASCON_AEAD128_ASSOCIATED_DATA_DEF
    VERUM_ASCON_AEAD128_decrypt_process(key, nonce, ciphertext, ciphertext_size, associated_data, associated_size, authentication_tag);
#else
    VERUM_ASCON_AEAD128_decrypt_process(key, nonce, ciphertext, ciphertext_size, authentication_tag);
#endif
}
