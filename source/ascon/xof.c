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
     *               Bit-interleaved state [OPT-A_0]: state[2w] = E_w (even bits of S_w),
     *               state[2w+1] = O_w (odd bits of S_w).
     *               Little-endian (𝐿, 𝐻) source words: 0x8d9447eb, 0xda82ce76, 0x5f1ef969,
     *               0xcc7ce6c7, 0x80085631, 0xe7508fd7, 0x416b58cc, 0x0ee0ea53, 0xdb6f0bde,
     *               0xe0547524.
     * @optimization [OPT-A_8] Precomputes π(𝐴𝑠𝑐𝑜𝑛-𝑝[12](𝐼𝑉 ‖ 0^[256])) or direct halves
     *               initial state at compile time, eliminating the IV, 12 permutation rounds,
     *               and runtime conversions per call.
     */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    uint32_t state[10U] = { 0xC0AE36B9UL, 0xB9B5A81FUL, 0xAEABF6D9UL, 0xA6D933E6UL, 0xBC3F00E5UL, 0xD0B98214UL, 0x288D99CAUL, 0x3CF1072AUL, 0x8EF2DB1EUL, 0xC044B73BUL };
#else
    uint32_t state[10U] = { 0x8d9447ebU, 0xda82ce76U, 0x5f1ef969U, 0xcc7ce6c7U, 0x80085631U, 0xe7508fd7U, 0x416b58ccU, 0x0ee0ea53U, 0xdb6f0bdeU, 0xe0547524U };
#endif
    uint32_t holder[10U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };

    uint32_t block_counter = message_size >> 3U;
    for (; 0U < block_counter; --block_counter)
    {
        /**
         * @internal
         * @ref          NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
         * @brief        S[0∶63] ← S[0∶63] ⊕ π(𝑀𝑖)
         * @optimization [OPT-A_12] holder (dead between permutations) stages π(𝑀𝑖); no extra stack.
         */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        holder[0U] = ((const uint32_t *) __builtin_assume_aligned(message, sizeof(uint32_t)))[0U];
        holder[1U] = ((const uint32_t *) __builtin_assume_aligned(message, sizeof(uint32_t)))[1U];
        // cppcheck-suppress-end misra-c2012-11.3
        VERUM_ASCON_interleave(holder);
        state[0U] = state[0U] ^ holder[0U];
        state[1U] = state[1U] ^ holder[1U];
#else
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        state[0U] = state[0U] ^ ((const uint32_t *) __builtin_assume_aligned(message, sizeof(uint32_t)))[0U];
        state[1U] = state[1U] ^ ((const uint32_t *) __builtin_assume_aligned(message, sizeof(uint32_t)))[1U];
        // cppcheck-suppress-end misra-c2012-11.3
#endif
        message += 8U;

        /**
         * @internal
         * @ref   NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
         */
#ifdef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
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
#else
        VERUM_ASCON_permute(state, holder, 0U);
#endif
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
     * @brief        𝑀𝑚 ← pad(̃𝑀𝑚, 64); S[0∶63] ← S[0∶63] ⊕ π(𝑀𝑚)
     * @optimization [OPT-A_12] π applied in place on the aligned staging buffer.
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
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
    VERUM_ASCON_interleave((uint32_t *) __builtin_assume_aligned(last_block_message, sizeof(uint32_t)));
#endif
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
#ifdef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
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
#else
        VERUM_ASCON_permute(state, holder, 0U);
#endif

        /**
         * @internal
         * @ref          NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
         * @brief        𝐻𝑖 ← π⁻¹(S[0∶63])
         * @optimization [OPT-A_12] π⁻¹ applied in place on the aligned digest words.
         */
        // cppcheck-suppress-begin misra-c2012-11.3 ; DEV-002: API precondition requires caller buffers to be 4-byte aligned for word access.
        ((uint32_t *) __builtin_assume_aligned(digest, sizeof(uint32_t)))[0U] = state[0U];
        ((uint32_t *) __builtin_assume_aligned(digest, sizeof(uint32_t)))[1U] = state[1U];
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        VERUM_ASCON_deinterleave((uint32_t *) __builtin_assume_aligned(digest, sizeof(uint32_t)));
#endif
        // cppcheck-suppress-end misra-c2012-11.3
        digest += 8U;
        --block_counter;
    }

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
     * @brief        𝐻ℎ ← π⁻¹(S[0∶63])[0∶ℓ−1]
     * @optimization [OPT-A_11] Skips the final Ascon-p[12] permutation when (digest_size & 0x7U) == 0U.
     */
    uint32_t digest_byte_index = digest_size & 0x7U;

    if (0U < digest_byte_index)
    {
        /**
         * @internal
         * @ref   NIST SP 800-232 Section 5.2 Algorithm 6 Ascon-XOF128(𝑀, 𝐿)
         * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
         */
#ifdef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
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
#else
        VERUM_ASCON_permute(state, holder, 0U);
#endif

        /**
         * @internal
         * @optimization [OPT-A_12] π⁻¹ staged in the post-permutation dead holder[0U..1U].
         */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
        holder[0U] = state[0U];
        holder[1U] = state[1U];
        VERUM_ASCON_deinterleave(holder);
        const uint8_t * const state_bytes = (const uint8_t *) holder;
#else
        const uint8_t * const state_bytes = (const uint8_t *) state;
#endif
        do
        {
            --digest_byte_index;
            digest[digest_byte_index] = state_bytes[digest_byte_index];
        }
        while (0U < digest_byte_index);
    }

}
