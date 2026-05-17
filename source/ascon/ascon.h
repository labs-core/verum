/**
 * @file      ascon.h
 * @brief     Ascon shared primitives.
 * @details   This header defines shared constants, types, and internal helper functions for the Ascon family of authenticated encryption algorithms.
 *
 * @see       https://doi.org/10.6028/NIST.SP.800-232
 *
 * @copyright  (C) Core Labs
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @github     https://github.com/manoel-serafim
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef VERUM_ASCON_H_
#define VERUM_ASCON_H_

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
                                                                      const uint32_t holder[10U])
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
    VERUM_ASCON_AEAD128_permute_substitution_layer(state, holder, VERUM_ASCON_AEAD128_round_constants[round_index]);
    ++round_index;
    do
    {
        VERUM_ASCON_AEAD128_permute_merged(state, holder, VERUM_ASCON_AEAD128_round_constants[round_index]);
        ++round_index;
    }
    while (round_index < 12U);
    VERUM_ASCON_AEAD128_permute_linear_diffusion_layer(state, holder);
}

#endif // VERUM_OPTIMIZATION_MEMORY_DEF

#endif // VERUM_ASCON_H_