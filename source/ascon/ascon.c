/**
 * @file      ascon.c
 * @brief     Ascon shared permutation primitives.
 * @details   Implements shared round constants and 320-bit Ascon-p permutation layers
 *            using explicit 32-bit word-pair operations (NIST SP 800-232 Section 3).
 *
 * @see       https://doi.org/10.6028/NIST.SP.800-232
 *
 * @copyright (C) Core Labs
 *            All rights reserved.
 *
 * @author    Manoel Serafim
 * @email     manoel.serafim@proton.me
 * @github    https://github.com/manoel-serafim
 * SPDX-License-Identifier: GPL-3.0
 */

 #include "ascon.h"

/**
 * @internal
 * @ref          NIST SP 800-232 Section 3.2 Table 5
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        C[𝑖] = Const[16−𝑟𝑛𝑑+𝑖]
 * @details      Little-endian 32-bit round constants XORed into the lower word of S2 (state[4U]).
 * @optimization Stored as 32-bit words rather than 64-bit words because bits [8:63] of every
 *               round constant are zero, halving .rodata footprint (48 B vs. 96 B) and eliding
 *               upper-word XORs on state[5U].
 */
const uint32_t VERUM_ASCON_round_constants[12U] = {
    0x000000F0UL, 0x000000E1UL, 0x000000D2UL, 0x000000C3UL,
    0x000000B4UL, 0x000000A5UL, 0x00000096UL, 0x00000087UL,
    0x00000078UL, 0x00000069UL, 0x0000005AUL, 0x0000004BUL
};

/**
 * @internal
 * @ref           NIST SP 800-232 Sections 3.2 and 3.3
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         𝑝𝐶 Constant-Addition Layer; 𝑝𝑆 Substitution Layer
 * @param[in,out] state          320-bit state as ten 32-bit words.
 * @param[out]    holder         320-bit scratch buffer receiving post-S-box words.
 * @param[in]     round_constant Round constant C[i] for the initial round.
 * @optimization  Fuses p_C (state[4U] ^= round_constant) into the first S-box XOR and
 *                evaluates the 5-bit S-box in 32-bit bit-sliced form directly into
 *                holder[0U..9U] using bitwise NOT-AND (~x & y) and ~x without additional
 *                temporaries, reducing stack usage, register pressure, and memory traffic.
 */
VERUM_ATTR_INLINE
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
static
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
inline void VERUM_ASCON_permute_substitution_layer(uint32_t state[10U],
                                                                  uint32_t holder[10U],
                                                                  const uint32_t round_constant)
{
    state[0U] = state[0U] ^ state[8U];
    state[1U] = state[1U] ^ state[9U];
    /**
     * @internal
     * @ref          NIST SP 800-232 Section 3.2
     * @brief        𝑝𝐶 Constant-Addition Layer: S2 ← S2 ⊕ C[𝑖]
     * @optimization Merged into the S2 ^= S1 linear pre-mixing step to save a separate
     *               read-modify-write on state[4U].
     */
    state[4U] = state[4U] ^ state[2U] ^ round_constant;
    state[5U] = state[5U] ^ state[3U];

    state[8U] = state[8U] ^ state[6U];
    state[9U] = state[9U] ^ state[7U];

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 3.3
     * @brief        𝑝𝑆 Substitution Layer
     * @optimization Replaces (x ^ 0xFFFFFFFFUL) & y and x ^ 0xFFFFFFFFUL with (~x) & y
     *               and ~x, mapping directly to single-cycle bitwise NOT-AND (BIC/ANDN)
     *               and NOT instructions and eliminating 12 immediate-XOR operations per round.
     */
    holder[0U] = state[0U] ^ ((~state[2U]) & state[4U]);
    holder[1U] = state[1U] ^ ((~state[3U]) & state[5U]);
    holder[2U] = state[2U] ^ ((~state[4U]) & state[6U]) ^ holder[0U];
    holder[3U] = state[3U] ^ ((~state[5U]) & state[7U]) ^ holder[1U];
    holder[4U] = state[4U] ^ ((~state[6U]) & state[8U]);
    holder[5U] = state[5U] ^ ((~state[7U]) & state[9U]);
    holder[6U] = state[6U] ^ ((~state[8U]) & state[0U]) ^ holder[4U];
    holder[7U] = state[7U] ^ ((~state[9U]) & state[1U]) ^ holder[5U];
    holder[8U] = state[8U] ^ ((~state[0U]) & state[2U]);
    holder[9U] = state[9U] ^ ((~state[1U]) & state[3U]);


    holder[0U] = holder[0U] ^ holder[8U];
    holder[1U] = holder[1U] ^ holder[9U];
    holder[4U] = ~holder[4U];
    holder[5U] = ~holder[5U];
}

/**
 * @internal
 * @ref        NIST SP 800-232 Section 3.4
 * @see        https://doi.org/10.6028/NIST.SP.800-232
 * @brief      𝑝𝐿 Linear Diffusion Layer
 * @param[out] state  320-bit state receiving diffused words.
 * @param[in]  holder 320-bit scratch buffer holding post-substitution words.
 */
VERUM_ATTR_INLINE
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
static
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
inline void VERUM_ASCON_permute_linear_diffusion_layer(uint32_t state[10U],
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
 * @ref           NIST SP 800-232 Sections 3.2, 3.3, and 3.4
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         𝑝𝐿 Linear Diffusion Layer; 𝑝𝐶 Constant-Addition Layer; 𝑝𝑆 Substitution Layer
 * @param[out]    state          320-bit state buffer.
 * @param[in,out] holder         320-bit scratch buffer updated across merged rounds.
 * @param[in]     round_constant Round constant C[i] for the next round.
 * @optimization  Fuses p_L of round i-1 with p_C and p_S of round i, scheduling diffusion
 *                of S4 (state[8U..9U]) and S2 (state[4U..5U]) ahead of S0 and S3 so the
 *                initial S-box XORs (S0 ^= S4, S2 ^= S1 ^ C[i], S4 ^= S3) fold directly
 *                into diffusion stores, eliminating inter-round state loads and stores.
 */
VERUM_ATTR_INLINE
#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
static
#endif // VERUM_OPTIMIZATION_MEMORY_DEF
inline void VERUM_ASCON_permute_merged(uint32_t state[10U],
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

    /**
     * @internal
     * @ref          NIST SP 800-232 Section 3.3
     * @brief        𝑝𝑆 Substitution Layer
     * @optimization Replaces (x ^ 0xFFFFFFFFUL) & y and x ^ 0xFFFFFFFFUL with (~x) & y
     *               and ~x, mapping directly to single-cycle bitwise NOT-AND (BIC/ANDN)
     *               and NOT instructions and eliminating 12 immediate-XOR operations per round.
     */
    holder[0U] = state[0U] ^ ((~state[2U]) & state[4U]);
    holder[1U] = state[1U] ^ ((~state[3U]) & state[5U]);
    holder[2U] = state[2U] ^ ((~state[4U]) & state[6U]) ^ holder[0U];
    holder[3U] = state[3U] ^ ((~state[5U]) & state[7U]) ^ holder[1U];
    holder[4U] = state[4U] ^ ((~state[6U]) & state[8U]);
    holder[5U] = state[5U] ^ ((~state[7U]) & state[9U]);
    holder[6U] = state[6U] ^ ((~state[8U]) & state[0U]) ^ holder[4U];
    holder[7U] = state[7U] ^ ((~state[9U]) & state[1U]) ^ holder[5U];
    holder[8U] = state[8U] ^ ((~state[0U]) & state[2U]);
    holder[9U] = state[9U] ^ ((~state[1U]) & state[3U]);


    holder[0U] = holder[0U] ^ holder[8U];
    holder[1U] = holder[1U] ^ holder[9U];
    holder[4U] = ~holder[4U];
    holder[5U] = ~holder[5U];
}


#ifdef VERUM_OPTIMIZATION_MEMORY_DEF
/**
 * @internal
 * @ref           NIST SP 800-232 Section 3
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         Permutes the 320-bit ASCON state from @p round_index through round 11.
 * @param[in,out] state       320-bit state as ten 32-bit words.
 * @param[out]    holder      320-bit scratch buffer for intermediate post-S-box values.
 * @param[in]     round_index Starting round index (0 for Ascon-p[12], 4 for Ascon-p[8]).
 * @optimization  Marked noinline and shared across p[12] and p[8]; peels the initial
 *                substitution layer and final linear diffusion layer outside the loop so
 *                the body executes only fused p_L+p_C+p_S rounds, minimizing .text
 *                footprint and instruction-cache pressure.
 */
VERUM_ATTR_NOINLINE
void VERUM_ASCON_permute(uint32_t state[10U],
                                        uint32_t * const holder,
                                        uint32_t round_index)
{
    VERUM_ASCON_permute_substitution_layer(state, holder, VERUM_ASCON_round_constants[round_index]);
    ++round_index;
    do
    {
        VERUM_ASCON_permute_merged(state, holder, VERUM_ASCON_round_constants[round_index]);
        ++round_index;
    }
    while (round_index < 12U);
    VERUM_ASCON_permute_linear_diffusion_layer(state, holder);
}

#endif // VERUM_OPTIMIZATION_MEMORY_DEF
