/**
 * @file       cxof.c
 * @brief      NIST SP 800-232 ASCON CXOF.
 * @details    Customizable Extendable-Output Function (CXOF) implementation for ASCON,
 *             configurable for memory efficiency xor performance via explicit 32-bit
 *             operations over the 320-bit (five 64-bit word) state machine [OPT-A_0]
 *             on 32-bit targets without compiler-synthesized 64-bit arithmetic.
 *             Supports both bit-interleaved and direct-halves state representations,
 *             as well as unrolled vs. compact execution.
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

#include "verum/ascon/cxof.h"
#include "ascon.h"
#include "define.h"
#include "macro.h"

/**
 * @internal
 * @ref        NIST SP 800-232 Section 5.3 Algorithm 7
 * @see        https://doi.org/10.6028/NIST.SP.800-232
 * @brief      Ascon-CXOF128 cryptographic customizable extendable-output leaf processing engine.
 * @details    Executes the pure mathematical customizable extendable-output hash:
 *             bit-interleaved state initialization, customization string absorption,
 *             domain separation permutation, message absorption, padding, and
 *             incremental squeeze. Separated as a leaf processing engine to eliminate
 *             recursive call graph cycles (MISRA C:2012 Rule 17.2) between the public
 *             digest API and FIPS 140-3 pre-operational self-tests.
 *
 * @warning    @p digest must not be NULL.
 * @warning    @p message (when @p message_size >= 8), @p customization (when
 *             @p customization_size >= 8), and @p digest (when @p digest_size >= 8)
 *             must be aligned to @c uint32_t boundaries; full 64-bit blocks are
 *             written as little-endian 32-bit word pairs.
 * @warning    Customization string length must satisfy @p customization_size <= 256 bytes
 *             (|𝑍| <= 2048 bits) per NIST SP 800-232 Section 5.3.
 *
 * @param[in]  message            Input message buffer.
 * @param[in]  message_size       Byte length of @p message (0 is valid).
 * @param[in]  customization      Input customization string buffer.
 * @param[in]  customization_size Byte length of @p customization (0 <= customization_size <= 256).
 * @param[out] digest             Output buffer for the extendable-output digest.
 * @param[in]  digest_size        Byte length of output @p digest (> 0).
 */
#ifdef VERUM_STANDARD_FIPS_140_3_DEF
VERUM_ATTR_NOINLINE static void VERUM_ASCON_CXOF128_digest_process(const uint8_t *message,
                                                                   uint32_t message_size,
                                                                   const uint8_t *customization,
                                                                   uint32_t customization_size,
                                                                   uint8_t *digest,
                                                                   uint32_t digest_size)
#else
VERUM_ATTR_INLINE static void VERUM_ASCON_CXOF128_digest_process(const uint8_t *message,
                                                                 uint32_t message_size,
                                                                 const uint8_t *customization,
                                                                 uint32_t customization_size,
                                                                 uint8_t *digest,
                                                                 uint32_t digest_size)
#endif
{
    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.3 Algorithm 7 and Appendix B
     * @brief        𝐼𝑉 ← 0x0000080000cc0004; S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](𝐼𝑉 ‖ 0^[256])
     * @details      The initial state depends only on 𝐼𝑉 ‖ 0^[256] and is invariant across invocations.
     *               Bit-interleaved state [OPT-A_0]: state_2w = E_w (even bits of S_w),
     *               state_{2w+1} = O_w (odd bits of S_w).
     *               Little-endian (𝐿, 𝐻) source words: 0xa0e8de03, 0x675527c2, 0xc0377bbc,
     *               0x43d12d7d, 0x426e81b5, 0xe9901dec, 0x720780b6, 0x2ab14907, 0xd432bc46,
     *               0x8f3f1d02.
     * @optimization [OPT-A_8] Precomputes π(𝐴𝑠𝑐𝑜𝑛-𝑝[12](𝐼𝑉 ‖ 0^[256])) or direct halves
     *               initial state at compile time, eliminating the IV, 12 permutation rounds,
     *               and runtime conversions per call.
     *               [OPT-A_13] 320-bit state and 320-bit S-box scratch storage pinned to twenty
     *               32-bit register variables (state_0..state_9, holder_0..holder_9).
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    register uint32_t state_0 = 0xBF3808E1UL;
    register uint32_t state_1 = 0x5059CEB1UL;
    register uint32_t state_2 = 0x9D3F87D6UL;
    register uint32_t state_3 = 0x1866857EUL;
    register uint32_t state_4 = 0x947A8A17UL;
    register uint32_t state_5 = 0xE82E178CUL;
    register uint32_t state_6 = 0x0593C306UL;
    register uint32_t state_7 = 0x7C21518DUL;
    register uint32_t state_8 = 0x3770E46AUL;
    register uint32_t state_9 = 0xB72185E1UL;
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    register uint32_t state_0 = 0xa0e8de03U;
    register uint32_t state_1 = 0x675527c2U;
    register uint32_t state_2 = 0xc0377bbcU;
    register uint32_t state_3 = 0x43d12d7dU;
    register uint32_t state_4 = 0x426e81b5U;
    register uint32_t state_5 = 0xe9901decU;
    register uint32_t state_6 = 0x720780b6U;
    register uint32_t state_7 = 0x2ab14907U;
    register uint32_t state_8 = 0xd432bc46U;
    register uint32_t state_9 = 0x8f3f1d02U;
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

    // cppcheck-suppress misra-c2012-1.4 ; DEV-004: C11 defines _Alignas behavior; explicit alignment is needed for these fixed-size staging buffers.
    _Alignas(uint32_t) uint8_t last_block_message[8U];

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
     * @brief        𝑍₀ ← int₆₄(|𝑍|); S[0∶63] ← S[0∶63] ⊕ π(𝑍₀); S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     * @details      |𝑍| is bit length of customization string: customization_size << 3U.
     * @optimization [OPT-A_12] Shared 8-byte aligned staging buffer stages π(𝑍₀), π(𝑍𝑖),
     *               padded 𝑍𝑘, π(𝑀𝑖), padded 𝑀𝑠, and tail squeeze; no extra stack arrays.
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U] = customization_size << 3U;
    ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U] = 0U;
    VERUM_ASCON_interleave((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)));
    state_0 = state_0 ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U];
    state_1 = state_1 ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U];
    // cppcheck-suppress-end misra-c2012-11.3
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    state_0 = state_0 ^ (customization_size << 3U);
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

    VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                            state_5, state_6, state_7, state_8, state_9,
                            holder_0, holder_1, holder_2, holder_3, holder_4,
                            holder_5, holder_6, holder_7, holder_8, holder_9);

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
     * @brief        S[0∶63] ← S[0∶63] ⊕ π(𝑍𝑖); S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S) (𝑖 = 1..𝑘)
     * @optimization [OPT-A_12] Shared staging buffer stages π(𝑍𝑖); no extra stack.
     */
    uint32_t block_counter = customization_size >> 3U;
    for (; 0U < block_counter; --block_counter)
    {
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U] = ((const uint32_t *) __builtin_assume_aligned(customization, sizeof(uint32_t)))[0U];
        ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U] = ((const uint32_t *) __builtin_assume_aligned(customization, sizeof(uint32_t)))[1U];
        VERUM_ASCON_interleave((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)));
        state_0 = state_0 ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U];
        state_1 = state_1 ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U];
        // cppcheck-suppress-end misra-c2012-11.3
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(customization, sizeof(uint32_t)))[0U];
        state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(customization, sizeof(uint32_t)))[1U];
        // cppcheck-suppress-end misra-c2012-11.3
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        customization += 8U;

        /**
         * @internal
         * @ref   NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
         */
        VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                                state_5, state_6, state_7, state_8, state_9,
                                holder_0, holder_1, holder_2, holder_3, holder_4,
                                holder_5, holder_6, holder_7, holder_8, holder_9);
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
     * @brief        𝑍𝑘 ← pad(̃𝑍𝑘, 64); S[0∶63] ← S[0∶63] ⊕ π(𝑍𝑘); S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     * @optimization [OPT-A_12] π applied in place on aligned staging buffer.
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
    uint32_t last_block_byte_index = customization_size & 0x7U;
    last_block_message[last_block_byte_index] = 0x01U;

    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_message[last_block_byte_index] = customization[last_block_byte_index];
    }

    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    VERUM_ASCON_interleave((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)));
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    state_0 = state_0 ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U];
    state_1 = state_1 ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U];
    // cppcheck-suppress-end misra-c2012-11.3

    VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                            state_5, state_6, state_7, state_8, state_9,
                            holder_0, holder_1, holder_2, holder_3, holder_4,
                            holder_5, holder_6, holder_7, holder_8, holder_9);

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
     * @brief        S[0∶63] ← S[0∶63] ⊕ π(𝑀𝑖); S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S) (𝑖 = 1..𝑠)
     * @optimization [OPT-A_12] Shared staging buffer stages π(𝑀𝑖); no extra stack.
     */
    block_counter = message_size >> 3U;
    for (; 0U < block_counter; --block_counter)
    {
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U] = ((const uint32_t *) __builtin_assume_aligned(message, sizeof(uint32_t)))[0U];
        ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U] = ((const uint32_t *) __builtin_assume_aligned(message, sizeof(uint32_t)))[1U];
        VERUM_ASCON_interleave((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)));
        state_0 = state_0 ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U];
        state_1 = state_1 ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U];
        // cppcheck-suppress-end misra-c2012-11.3
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        state_0 = state_0 ^ ((const uint32_t *) __builtin_assume_aligned(message, sizeof(uint32_t)))[0U];
        state_1 = state_1 ^ ((const uint32_t *) __builtin_assume_aligned(message, sizeof(uint32_t)))[1U];
        // cppcheck-suppress-end misra-c2012-11.3
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        message += 8U;

        /**
         * @internal
         * @ref   NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
         */
        VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                                state_5, state_6, state_7, state_8, state_9,
                                holder_0, holder_1, holder_2, holder_3, holder_4,
                                holder_5, holder_6, holder_7, holder_8, holder_9);
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
     * @brief        𝑀𝑠 ← pad(̃𝑀𝑠, 64); S[0∶63] ← S[0∶63] ⊕ π(𝑀𝑠)
     * @optimization [OPT-A_12] π applied in place on aligned staging buffer.
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
    last_block_byte_index = message_size & 0x7U;
    last_block_message[last_block_byte_index] = 0x01U;

    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_message[last_block_byte_index] = message[last_block_byte_index];
    }

    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    VERUM_ASCON_interleave((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)));
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    state_0 = state_0 ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U];
    state_1 = state_1 ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U];
    // cppcheck-suppress-end misra-c2012-11.3

    /**
     * @internal
     * @ref           NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
     * @brief         ℎ ← ⌊𝐿/8⌋ full 64-bit output blocks.
     * @note          @p digest_size is specified in bytes rather than bits.
     * @nonconformity SP-800-232
     */
    block_counter = digest_size >> 3U;

    while (0U < block_counter)
    {
        /**
         * @internal
         * @ref   NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
         */
        VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                                state_5, state_6, state_7, state_8, state_9,
                                holder_0, holder_1, holder_2, holder_3, holder_4,
                                holder_5, holder_6, holder_7, holder_8, holder_9);

        /**
         * @internal
         * @ref          NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
         * @brief        𝐻𝑖 ← π⁻¹(S[0∶63])
         * @optimization [OPT-A_12] π⁻¹ applied in place on the aligned digest words.
         */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        ((uint32_t *) __builtin_assume_aligned(digest, sizeof(uint32_t)))[0U] = state_0;
        ((uint32_t *) __builtin_assume_aligned(digest, sizeof(uint32_t)))[1U] = state_1;
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        VERUM_ASCON_deinterleave((uint32_t *) __builtin_assume_aligned(digest, sizeof(uint32_t)));
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        // cppcheck-suppress-end misra-c2012-11.3
        digest += 8U;
        --block_counter;
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
     * @brief        𝐻ℎ ← π⁻¹(S[0∶63])[0∶ℓ−1]
     * @optimization [OPT-A_11] Skips the final Ascon-p[12] permutation when (digest_size & 0x7U) == 0U.
     *               [OPT-A_12] π⁻¹ applied in place on shared last_block_message staging buffer.
     */
    uint32_t digest_byte_index = digest_size & 0x7U;

    if (0U < digest_byte_index)
    {
        /**
         * @internal
         * @ref   NIST SP 800-232 Section 5.3 Algorithm 7 Ascon-CXOF128(𝑀, 𝐿, 𝑍)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
         */
        VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                                state_5, state_6, state_7, state_8, state_9,
                                holder_0, holder_1, holder_2, holder_3, holder_4,
                                holder_5, holder_6, holder_7, holder_8, holder_9);

        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
        ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U] = state_0;
        ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U] = state_1;
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        VERUM_ASCON_deinterleave((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)));
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        // cppcheck-suppress-end misra-c2012-11.3
        do
        {
            --digest_byte_index;
            digest[digest_byte_index] = last_block_message[digest_byte_index];
        }
        while (0U < digest_byte_index);
    }

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
    // cppcheck-suppress-end unreadVariable
#else /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
    // cppcheck-suppress-end unreadVariable
    VERUM_ATTR_VOLATILE uint32_t * const volatile_state = (VERUM_ATTR_VOLATILE uint32_t *) state;
    volatile_state[0U] = 0U;
    volatile_state[1U] = 0U;
    volatile_state[2U] = 0U;
    volatile_state[3U] = 0U;
    volatile_state[4U] = 0U;
    volatile_state[5U] = 0U;
    volatile_state[6U] = 0U;
    volatile_state[7U] = 0U;
    volatile_state[8U] = 0U;
    volatile_state[9U] = 0U;
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    VERUM_ATTR_VOLATILE uint32_t * const volatile_last_block = (VERUM_ATTR_VOLATILE uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t));
    volatile_last_block[0U] = 0U;
    volatile_last_block[1U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */
}

#ifdef VERUM_STANDARD_FIPS_140_3_DEF
static VERUM_FIPS1403_state_t VERUM_FIPS1403_ASCON_CXOF128_operational_state = VERUM_FIPS1403_STATE_UNINITIALIZED;

/**
 * @internal
 * @ref        ISO/IEC 19790:2012 Section 7.9.5 Pre-operational self-tests
 * @ref        FIPS 140-3 IG Section 9.5
 * @see        https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
 * @see        https://doi.org/10.6028/NIST.FIPS.140-3
 * @brief      Execute FIPS 140-3 Known-Answer Test (KAT) for Ascon-CXOF128.
 * @details    Squeezes 32 bytes with empty message and empty customization string,
 *             validating against NIST SP 800-232 reference vector.
 *             Transitions state to OPERATIONAL on pass, or ERROR and traps on failure.
 * @param      void This test takes no external inputs; standard KAT vectors are self-contained.
 * @return     0 on success (identical digest), non-zero on error (accumulated bit difference).
 */
// cppcheck-suppress staticFunction ; DEV-006: Public library API is called by downstream applications; no in-repository caller is required.
// cppcheck-suppress misra-c2012-8.7 ; DEV-007: External linkage is required so downstream applications can link this public API.
uint32_t VERUM_FIPS1403_ASCON_CXOF128_self_test(void)
{
    uint32_t difference = 0U;

    if (VERUM_FIPS1403_ASCON_CXOF128_operational_state == VERUM_FIPS1403_STATE_ERROR)
    {
        difference = 1U;
        VERUM_FAULT_HANDLER();
    }
    else if (VERUM_FIPS1403_ASCON_CXOF128_operational_state != VERUM_FIPS1403_STATE_OPERATIONAL)
    {
        VERUM_FIPS1403_ASCON_CXOF128_operational_state = VERUM_FIPS1403_STATE_INITIALIZING;

        // cppcheck-suppress misra-c2012-1.4 ; DEV-004: C11 defines _Alignas behavior; explicit alignment is needed for these fixed-size staging buffers.
        _Alignas(uint32_t) uint8_t test_digest[32U] = {
            0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
            0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
            0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
            0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U
        };
        static const uint8_t VERUM_FIPS1403_ASCON_CXOF128_expected_digest[32U] = {
            0x4FU, 0x50U, 0x15U, 0x9EU, 0xF7U, 0x0BU, 0xB3U, 0xDAU,
            0xD8U, 0x80U, 0x7EU, 0x03U, 0x4EU, 0xAEU, 0xBDU, 0x44U,
            0xC4U, 0xFAU, 0x2CU, 0xBBU, 0xC8U, 0xCFU, 0x1FU, 0x05U,
            0x51U, 0x1AU, 0xB6U, 0x6CU, 0xDCU, 0xC5U, 0x29U, 0x90U
        };

        VERUM_ASCON_CXOF128_digest_process(NULL, 0U, NULL, 0U, test_digest, 32U);

        uint32_t byte_index = 0U;
        do
        {
            difference = difference | (uint32_t) (test_digest[byte_index] ^ VERUM_FIPS1403_ASCON_CXOF128_expected_digest[byte_index]);
            ++byte_index;
        }
        while (byte_index < 32U);

        /**
         * @internal
         * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
         * @ref   FIPS 140-3 IG
         * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
         * @see   https://doi.org/10.6028/NIST.FIPS.140-3
         * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
         */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
        VERUM_ATTR_VOLATILE uint32_t * const volatile_test_digest = (VERUM_ATTR_VOLATILE uint32_t *) __builtin_assume_aligned(test_digest, sizeof(uint32_t));
        volatile_test_digest[0U] = 0U;
        volatile_test_digest[1U] = 0U;
        volatile_test_digest[2U] = 0U;
        volatile_test_digest[3U] = 0U;
        volatile_test_digest[4U] = 0U;
        volatile_test_digest[5U] = 0U;
        volatile_test_digest[6U] = 0U;
        volatile_test_digest[7U] = 0U;
        // cppcheck-suppress-end misra-c2012-11.3

        if (difference != 0U)
        {
            VERUM_FIPS1403_ASCON_CXOF128_operational_state = VERUM_FIPS1403_STATE_ERROR;
            VERUM_FAULT_HANDLER();
        }
        else
        {
            VERUM_FIPS1403_ASCON_CXOF128_operational_state = VERUM_FIPS1403_STATE_OPERATIONAL;
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
void VERUM_ASCON_CXOF128_digest(const uint8_t *message,
                                uint32_t message_size,
                                const uint8_t *customization,
                                uint32_t customization_size,
                                uint8_t *digest,
                                uint32_t digest_size)
{
#ifdef VERUM_STANDARD_FIPS_140_3_DEF
    if (VERUM_FIPS1403_ASCON_CXOF128_operational_state == VERUM_FIPS1403_STATE_ERROR)
    {
        /**
         * @internal
         * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
         * @ref   FIPS 140-3 IG
         * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
         * @see   https://doi.org/10.6028/NIST.FIPS.140-3
         * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
         */
        VERUM_ATTR_VOLATILE uint8_t * const volatile_digest = (VERUM_ATTR_VOLATILE uint8_t *) digest;
        for (uint32_t byte_index = 0U; byte_index < digest_size; ++byte_index)
        {
            volatile_digest[byte_index] = 0U;
        }
        VERUM_FAULT_HANDLER();
    }
    if (VERUM_FIPS1403_ASCON_CXOF128_operational_state == VERUM_FIPS1403_STATE_UNINITIALIZED)
    {
        if (VERUM_FIPS1403_ASCON_CXOF128_self_test() != 0U)
        {
            /**
             * @internal
             * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
             * @ref   FIPS 140-3 IG
             * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
             * @see   https://doi.org/10.6028/NIST.FIPS.140-3
             * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
             */
            VERUM_ATTR_VOLATILE uint8_t * const volatile_digest = (VERUM_ATTR_VOLATILE uint8_t *) digest;
            for (uint32_t byte_index = 0U; byte_index < digest_size; ++byte_index)
            {
                volatile_digest[byte_index] = 0U;
            }
            VERUM_FAULT_HANDLER();
        }
    }
#endif /* VERUM_STANDARD_FIPS_140_3_DEF */

    VERUM_ASCON_CXOF128_digest_process(message, message_size, customization, customization_size, digest, digest_size);
}
