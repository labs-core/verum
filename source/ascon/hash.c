/**
 * @file       hash.c
 * @brief      NIST SP 800-232 ASCON HASH256.
 * @details    Hash function implementation for ASCON.
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
 * SPDX-License-Identifier: Apache-2.0
 */

#include "verum/ascon/hash.h"
#include "ascon.h"
#include "define.h"
#include "standard/types.h"

/**
 * @internal
 * @ref NIST SP 800-232 Section 5.1
 * @see https://doi.org/10.6028/NIST.SP.800-232
 * @brief Ascon-Hash256(𝑀)
 *
 * @param[in]     message             Input message buffer.
 * @param[in]     message_size        Byte length of @p message .
 * @param[inout]  digest              256-bit message digest as eight 32-bit words.
 */
void VERUM_ASCON_HASH256_digest( uint8_t *message,
                                 const uint32_t message_size,
                                 uint32_t digest[8U])
{
    /**
     * @internal
     * @ref NIST SP 800-232 Section 5.1 Algorithm 5 Ascon-Hash256(𝑀)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief 𝐼𝑉 ← 0x00001000808c0001; S ← 𝐼𝑉 ‖ 0^[256]; S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     * @details Given a 128-bit 𝐾 and 128-bit 𝑁, the 320-bit internal state is initialized as the concatenation of 𝐼𝑉, 𝐾, and 𝑁
     */
    uint32_t state[10U] = { 0x00001000U, 0x808c0001U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };
    uint32_t holder[10U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };

    uint32_t block_counter = message_size>>3U;
    for (; 0U < block_counter; --block_counter)
    {
        state[0U] = state[0U] ^ ((const uint32_t *) __builtin_assume_aligned(message, _Alignof(uint32_t)))[0U];
        state[1U] = state[1U] ^ ((const uint32_t *) __builtin_assume_aligned(message, _Alignof(uint32_t)))[1U];
        message += 8U;

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
    }
    
    uint8_t last_block_message[8U] = { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U };
    uint32_t last_block_byte_index = message_size & 0x7U;
    last_block_message[last_block_byte_index] = 0x01U;

    while (0U < last_block_byte_index)
    {
        --last_block_byte_index;
        last_block_message[last_block_byte_index] = message[last_block_byte_index];
    }

    state[0U] = state[0U] ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, _Alignof(uint32_t)))[0U];
    state[1U] = state[1U] ^ ((uint32_t *) __builtin_assume_aligned(last_block_message, _Alignof(uint32_t)))[1U];


#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
    block_counter = 0U;
    do
    {
        VERUM_ASCON_AEAD128_permute(state, holder, 0U);
        digest[block_counter] = state[0U];
        digest[block_counter + 1U] = state[1U];
        block_counter = block_counter + 2U;
    }
    while ( block_counter <= 6U);


#else
    /**
     * @internal
     * @ref NIST SP 800-232 Section 5.1 Algorithm 5 Ascon-Hash256(𝑀)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
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

    digest[0U] = state[0U];
    digest[1U] = state[1U];

    /**
     * @internal
     * @ref NIST SP 800-232 Section 5.1 Algorithm 5 Ascon-Hash256(𝑀)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
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

    digest[2U] = state[0U];
    digest[3U] = state[1U];

    /**
     * @internal
     * @ref NIST SP 800-232 Section 5.1 Algorithm 5 Ascon-Hash256(𝑀)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
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

    digest[4U] = state[0U];
    digest[5U] = state[1U];

    /**
     * @internal
     * @ref NIST SP 800-232 Section 5.1 Algorithm 5 Ascon-Hash256(𝑀)
     * @see https://doi.org/10.6028/NIST.SP.800-232
     * @brief S ← 𝐴𝑠𝑐𝑜𝑛-𝑝[12](S)
     */
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

    digest[6U] = state[0U];
    digest[7U] = state[1U];
#endif // VERUM_OPTIMIZATION_MEMORY_DEF

}