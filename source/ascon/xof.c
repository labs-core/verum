/**
 * @file       xof.c
 * @brief      NIST SP 800-232 ASCON XOF.
 * @details    Extendable-Output Function (XOF) implementation for ASCON, configurable for
 *             memory efficiency xor performance via explicit 32-bit operations over the
 *             320-bit (five 64-bit word) state machine [OPT-A_0] on 32-bit targets without
 *             compiler-synthesized 64-bit arithmetic. Supports both bit-interleaved and
 *             direct-halves state representations, as well as unrolled vs. compact execution.
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

#include "verum/ascon/xof.h"
#include "ascon.h"
#include "define.h"
#include "macro.h"

/**
 * @internal
 * @ref        NIST SP 800-232 Section 5.2 Algorithm 6
 * @see        https://doi.org/10.6028/NIST.SP.800-232
 * @brief      Ascon-XOF128 cryptographic extendable-output leaf processing engine.
 * @details    Executes the pure mathematical extendable-output hash: bit-interleaved
 *             state initialization, message absorption, padding, and incremental
 *             squeeze. Separated as a leaf processing engine to eliminate recursive
 *             call graph cycles (MISRA C:2012 Rule 17.2) between the public
 *             digest API and FIPS 140-3 pre-operational self-tests.
 *
 * @warning    @p digest must not be NULL.
 * @warning    @p message (when @p message_size >= 8) and @p digest (when
 *             @p digest_size >= 8) must be aligned to @c uint32_t boundaries; full
 *             64-bit blocks are written as little-endian 32-bit word pairs.
 *
 * @param[in]  message      Input message buffer.
 * @param[in]  message_size Byte length of @p message (0 is valid).
 * @param[out] digest       Output buffer for the extendable-output digest.
 * @param[in]  digest_size  Byte length of output @p digest (> 0).
 */
#ifdef VERUM_STANDARD_FIPS_140_3_DEF
VERUM_ATTR_NOINLINE static void VERUM_ASCON_XOF128_digest_process(const uint8_t *message,
                                                                  uint32_t message_size,
                                                                  uint8_t *digest,
                                                                  uint32_t digest_size)
#else
VERUM_ATTR_INLINE static void VERUM_ASCON_XOF128_digest_process(const uint8_t *message,
                                                                uint32_t message_size,
                                                                uint8_t *digest,
                                                                uint32_t digest_size)
#endif
{
    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.2 Algorithm 6 and Appendix B
     * @brief        𝐼𝑉 ← 0x0000080000cc0003; S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](𝐼𝑉 ‖ 0^[256])
     * @details      The initial state depends only on 𝐼𝑉 ‖ 0^[256] and is invariant across invocations.
     *               Bit-interleaved state [OPT-A_0]: state_2w = E_w (even bits of S_w),
     *               state_{2w+1} = O_w (odd bits of S_w).
     *               Little-endian (𝐿, 𝐻) source words: 0x8d9447eb, 0xda82ce76, 0x5f1ef969,
     *               0xcc7ce6c7, 0x80085631, 0xe7508fd7, 0x416b58cc, 0x0ee0ea53, 0xdb6f0bde,
     *               0xe0547524.
     * @optimization [OPT-A_8] Precomputes π(𝐴𝑠𝑐𝑜𝑛-𝑝[12](𝐼𝑉 ‖ 0^[256])) or direct halves
     *               initial state at compile time, eliminating the IV, 12 permutation rounds,
     *               and runtime conversions per call.
     *               [OPT-A_13] 320-bit state and 320-bit S-box scratch storage pinned to twenty
     *               32-bit register variables (state_0..state_9, holder_0..holder_9).
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    register uint32_t state_0 = 0xC0AE36B9UL;
    register uint32_t state_1 = 0xB9B5A81FUL;
    register uint32_t state_2 = 0xAEABF6D9UL;
    register uint32_t state_3 = 0xA6D933E6UL;
    register uint32_t state_4 = 0xBC3F00E5UL;
    register uint32_t state_5 = 0xD0B98214UL;
    register uint32_t state_6 = 0x288D99CAUL;
    register uint32_t state_7 = 0x3CF1072AUL;
    register uint32_t state_8 = 0x8EF2DB1EUL;
    register uint32_t state_9 = 0xC044B73BUL;
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
    register uint32_t state_0 = 0x8d9447ebU;
    register uint32_t state_1 = 0xda82ce76U;
    register uint32_t state_2 = 0x5f1ef969U;
    register uint32_t state_3 = 0xcc7ce6c7U;
    register uint32_t state_4 = 0x80085631U;
    register uint32_t state_5 = 0xe7508fd7U;
    register uint32_t state_6 = 0x416b58ccU;
    register uint32_t state_7 = 0x0ee0ea53U;
    register uint32_t state_8 = 0xdb6f0bdeU;
    register uint32_t state_9 = 0xe0547524U;
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
     * @ref          NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
     * @brief        S[0∶63] ← S[0∶63] ⊕ π(𝑀𝑖)
     * @optimization [OPT-A_12] Shared 8-byte aligned staging buffer stages π(𝑀𝑖), padding, and tail squeeze; no extra stack.
     */
    uint32_t block_counter = message_size >> 3U;
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
         * @ref   NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
         */
        VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                                state_5, state_6, state_7, state_8, state_9,
                                holder_0, holder_1, holder_2, holder_3, holder_4,
                                holder_5, holder_6, holder_7, holder_8, holder_9);
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
     * @brief        𝑀𝑚 ← pad(̃𝑀𝑚, 64); S[0∶63] ← S[0∶63] ⊕ π(𝑀𝑚)
     * @optimization [OPT-A_12] π applied in place on the aligned staging buffer.
     */
    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U] = 0U;
    ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U] = 0U;
    // cppcheck-suppress-end misra-c2012-11.3
    uint32_t last_block_byte_index = message_size & 0x7U;
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
     * @ref          NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
     * @brief        S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S); 𝐻𝑖 ← π⁻¹(S[0∶63]) (𝑖 = 1..⌊𝐿/64⌋)
     * @optimization [OPT-A_12] π⁻¹ applied in place on word-aligned full blocks in digest.
     */
    block_counter = digest_size >> 3U;
    for (; 0U < block_counter; --block_counter)
    {
        VERUM_ASCON_PERMUTE_P12(state_0, state_1, state_2, state_3, state_4,
                                state_5, state_6, state_7, state_8, state_9,
                                holder_0, holder_1, holder_2, holder_3, holder_4,
                                holder_5, holder_6, holder_7, holder_8, holder_9);
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        ((uint32_t *) __builtin_assume_aligned(digest, sizeof(uint32_t)))[0U] = state_0;
        ((uint32_t *) __builtin_assume_aligned(digest, sizeof(uint32_t)))[1U] = state_1;
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        VERUM_ASCON_deinterleave((uint32_t *) __builtin_assume_aligned(digest, sizeof(uint32_t)));
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
        // cppcheck-suppress-end misra-c2012-11.3
        digest += 8U;
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
     * @brief        S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S); 𝐻𝑙 ← ⌊π⁻¹(S[0∶63])⌋_{𝐿 mod 64}
     * @optimization [OPT-A_12] π⁻¹ applied in place on shared last_block_message staging buffer;
     *               avoids unaligned writes to caller's digest buffer and extra stack arrays.
     */
    uint32_t digest_byte_index = digest_size & 0x7U;
    if (0U < digest_byte_index)
    {
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
static VERUM_FIPS1403_state_t VERUM_FIPS1403_ASCON_XOF128_operational_state = VERUM_FIPS1403_STATE_UNINITIALIZED;

/**
 * @internal
 * @ref        ISO/IEC 19790:2012 Section 7.9.5 Pre-operational self-tests
 * @ref        FIPS 140-3 IG Section 9.5
 * @see        https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
 * @see        https://doi.org/10.6028/NIST.FIPS.140-3
 * @brief      Execute FIPS 140-3 Known-Answer Test (KAT) for Ascon-XOF128.
 * @details    Squeezes 11 bytes from an empty message and validates against NIST SP 800-232 vector.
 *             Transitions state to OPERATIONAL on pass, or ERROR and traps on failure.
 * @param      void This test takes no external inputs; standard KAT vectors are self-contained.
 * @return     0 on success (identical digest), non-zero on error (accumulated bit difference).
 */
// cppcheck-suppress staticFunction ; DEV-006: Public library API is called by downstream applications; no in-repository caller is required.
// cppcheck-suppress misra-c2012-8.7 ; DEV-007: External linkage is required so downstream applications can link this public API.
uint32_t VERUM_FIPS1403_ASCON_XOF128_self_test(void)
{
    uint32_t difference = 0U;

    if (VERUM_FIPS1403_ASCON_XOF128_operational_state == VERUM_FIPS1403_STATE_ERROR)
    {
        difference = 1U;
        VERUM_FAULT_HANDLER();
    }
    else if (VERUM_FIPS1403_ASCON_XOF128_operational_state != VERUM_FIPS1403_STATE_OPERATIONAL)
    {
        VERUM_FIPS1403_ASCON_XOF128_operational_state = VERUM_FIPS1403_STATE_INITIALIZING;

        uint8_t test_digest[11U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };
        static const uint8_t VERUM_FIPS1403_ASCON_XOF128_expected_digest[11U] = {
            0x47U, 0x3DU, 0x5EU, 0x61U, 0x64U, 0xF5U, 0x8BU, 0x39U,
            0xDFU, 0xD8U, 0x4AU
        };

        VERUM_ASCON_XOF128_digest_process(NULL, 0U, test_digest, 11U);

        uint32_t byte_index = 0U;
        do
        {
            difference = difference | (uint32_t) (test_digest[byte_index] ^ VERUM_FIPS1403_ASCON_XOF128_expected_digest[byte_index]);
            ++byte_index;
        }
        while (byte_index < 11U);

        /**
         * @internal
         * @ref   ISO/IEC 19790:2012 Section 7.9.7 Zeroization
         * @ref   FIPS 140-3 IG
         * @see   https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf
         * @see   https://doi.org/10.6028/NIST.FIPS.140-3
         * @brief Zeroize permutation state and staging buffers to destroy residual SSP material.
         */
        VERUM_ATTR_VOLATILE uint8_t * const volatile_test_digest = (VERUM_ATTR_VOLATILE uint8_t *) test_digest;
        volatile_test_digest[0U] = 0U;
        volatile_test_digest[1U] = 0U;
        volatile_test_digest[2U] = 0U;
        volatile_test_digest[3U] = 0U;
        volatile_test_digest[4U] = 0U;
        volatile_test_digest[5U] = 0U;
        volatile_test_digest[6U] = 0U;
        volatile_test_digest[7U] = 0U;
        volatile_test_digest[8U] = 0U;
        volatile_test_digest[9U] = 0U;
        volatile_test_digest[10U] = 0U;

        if (difference != 0U)
        {
            VERUM_FIPS1403_ASCON_XOF128_operational_state = VERUM_FIPS1403_STATE_ERROR;
            VERUM_FAULT_HANDLER();
        }
        else
        {
            VERUM_FIPS1403_ASCON_XOF128_operational_state = VERUM_FIPS1403_STATE_OPERATIONAL;
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
void VERUM_ASCON_XOF128_digest(const uint8_t *message,
                               uint32_t message_size,
                               uint8_t *digest,
                               uint32_t digest_size)
{
#ifdef VERUM_STANDARD_FIPS_140_3_DEF
    if (VERUM_FIPS1403_ASCON_XOF128_operational_state == VERUM_FIPS1403_STATE_ERROR)
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
    if (VERUM_FIPS1403_ASCON_XOF128_operational_state == VERUM_FIPS1403_STATE_UNINITIALIZED)
    {
        if (VERUM_FIPS1403_ASCON_XOF128_self_test() != 0U)
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

    VERUM_ASCON_XOF128_digest_process(message, message_size, digest, digest_size);
}
