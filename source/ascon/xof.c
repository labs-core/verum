/**
 * @file       xof.c
 * @brief      NIST SP 800-232 ASCON XOF.
 * @details    Extendable-Output Function (XOF) implementation for ASCON, configurable for
 *             memory efficiency xor performance via explicit 32-bit operations over the
 *             320-bit (five 64-bit word) state machine on 32-bit targets without
 *             compiler-synthesized 64-bit arithmetic.
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


/**
 * @internal
 * @ref        NIST SP 800-232 Section 5.2 Algorithm 6
 * @see        https://doi.org/10.6028/NIST.SP.800-232
 * @brief      Ascon-XOF128(𝑀, 𝐿)
 *
 * @warning    @p message (when @p message_size >= 8) and @p digest (when
 *             @p digest_size >= 8) must be aligned to @c uint32_t boundaries; full
 *             64-bit blocks are written as little-endian 32-bit word pairs.
 *
 * @param[in]  message      Input message buffer.
 * @param[in]  message_size Byte length of @p message (0 is valid).
 * @param[out] digest       Output buffer for the extendable-output digest.
 * @param[in]  digest_size  Byte length of output @p digest (> 0).
 */
// cppcheck-suppress unusedFunction ; DEV-006: Public library API is called by downstream applications; no in-repository caller is required.
// cppcheck-suppress misra-c2012-8.7 ; DEV-007: External linkage is required so downstream applications can link this public API.
void VERUM_ASCON_XOF128_digest(const uint8_t *message,
                               uint32_t message_size,
                               uint8_t *digest,
                               uint32_t digest_size)
{
    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.2 Algorithm 6 and Appendix B
     * @brief        𝐼𝑉 ← 0x0000080000cc0003; S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](𝐼𝑉 ‖ 0^[256])
     * @details      The initial state depends only on 𝐼𝑉 ‖ 0^[256] and is invariant across invocations.
     * @optimization Precomputes 𝐴𝑠𝑐𝑜𝑛-𝑝[12](𝐼𝑉 ‖ 0^[256]) at compile time, eliminating the
     *               64-bit IV array and 12 permutation rounds per digest call.
     */
    uint32_t state[10] = { 0x8d9447ebU, 0xda82ce76U, 0x5f1ef969U, 0xcc7ce6c7U, 0x80085631U, 0xe7508fd7U, 0x416b58ccU, 0x0ee0ea53U,0xdb6f0bdeU, 0xe0547524U};
    uint32_t holder[10U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };

    uint32_t block_counter = message_size>>3U;
    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref   NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
         * @brief S[0∶63] ← S[0∶63] ⊕ 𝑀𝑖
         */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        state[0U] = state[0U] ^ ((const uint32_t *) __builtin_assume_aligned(message, sizeof(uint32_t)))[0U];
        state[1U] = state[1U] ^ ((const uint32_t *) __builtin_assume_aligned(message, sizeof(uint32_t)))[1U];
        // cppcheck-suppress-end misra-c2012-11.3
        message += 8U;

        /**
         * @internal
         * @ref   NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
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
    }

    /**
     * @internal
     * @ref   NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
     * @brief 𝑀𝑚 ← pad(̃𝑀𝑚, 64); S[0∶63] ← S[0∶63] ⊕ 𝑀𝑚
     */
    // cppcheck-suppress misra-c2012-1.4 ; DEV-004: C11 defines _Alignas behavior; explicit alignment is needed for these fixed-size staging buffers.
    _Alignas(uint32_t) uint8_t last_block_message[8U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };
    uint32_t last_block_byte_index = message_size & 0x7U;
    last_block_message[last_block_byte_index] = 0x01U;

    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_message[last_block_byte_index] = message[last_block_byte_index];
    }

    // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-003: local staging array is declared _Alignas(uint32_t) for word access.
    state[0U] = state[0U] ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[0U];
    state[1U] = state[1U] ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)))[1U];
    // cppcheck-suppress-end misra-c2012-11.3


    /**
     * @internal
     * @ref           NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
     * @brief         ℎ ← ⌊𝐿/8⌋ full 64-bit output blocks.
     * @note          @p digest_size is specified in bytes rather than bits.
     * @nonconformity SP-800-232
     */
    uint32_t digest_block_index = (digest_size >> 3U);
    block_counter = digest_block_index;

    while (0U < block_counter)
    {
        /**
         * @internal
         * @ref   NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
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
         * @ref   NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
         * @brief 𝐻𝑖 ← S[0∶63]
         */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        ((uint32_t *) __builtin_assume_aligned(digest, sizeof(uint32_t)))[0U] = state[0U];
        ((uint32_t *) __builtin_assume_aligned(digest, sizeof(uint32_t)))[1U] = state[1U];
        // cppcheck-suppress-end misra-c2012-11.3
        digest += 8U;
        --block_counter;
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
     * @brief        𝐻ℎ ← S[0∶ℓ−1]
     * @optimization Skips the final Ascon-p[12] permutation when (digest_size & 0x7U) == 0U.
     */
    uint32_t digest_byte_index = digest_size & 0x7U;

    if (0U < digest_byte_index)
    {
        /**
         * @internal
         * @ref   NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
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

        do
        {
            --digest_byte_index;
            digest[digest_byte_index] = ((const uint8_t *) state)[digest_byte_index];

        }
        while (0U < digest_byte_index);
    }

}
