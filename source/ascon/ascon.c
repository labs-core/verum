/**
 * @file      ascon.c
 * @brief     Ascon shared permutation primitives.
 * @details   Implements shared round constants, bit-interleaving conversions, and 320-bit
 *            Ascon-p permutation layers (NIST SP 800-232 Section 3). Supports both
 *            bit-interleaved [OPT-A_0] and direct-halves state representations, as well as
 *            both unrolled merged rounds and compact looped execution.
 *
 * @see       https://doi.org/10.6028/NIST.SP.800-232
 * @see       H. S. Warren Jr., Hacker's Delight, 2nd ed., Section 7-2 (2012).
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
 * @details      Round constants XORed into S2.
 * @optimization [OPT-A_2] Pre-computed round constants at compile time (no runtime conversion).
 *               Under bit interleaving: π(C[𝑖]) = { E, O } stored as uint8_t pairs: 24 B .rodata,
 *               loaded with zero-extending byte loads into state[4U] and state[5U].
 *               Under direct halves: little-endian 32-bit round constants (48 B .rodata) XORed
 *               into state[4U], eliding upper-word XORs on state[5U] since bits [8:63] are zero.
 */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
const uint8_t VERUM_ASCON_round_constants[12U][2U] = {
    { 0x0CU, 0x0CU }, { 0x09U, 0x0CU }, { 0x0CU, 0x09U }, { 0x09U, 0x09U },
    { 0x06U, 0x0CU }, { 0x03U, 0x0CU }, { 0x06U, 0x09U }, { 0x03U, 0x09U },
    { 0x0CU, 0x06U }, { 0x09U, 0x06U }, { 0x0CU, 0x03U }, { 0x09U, 0x03U }
};
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
const uint32_t VERUM_ASCON_round_constants[12U] = {
    0x000000F0UL, 0x000000E1UL, 0x000000D2UL, 0x000000C3UL,
    0x000000B4UL, 0x000000A5UL, 0x00000096UL, 0x00000087UL,
    0x00000078UL, 0x00000069UL, 0x0000005AUL, 0x0000004BUL
};
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
/**
 * @internal
 * @brief         π: (𝐿, 𝐻) → (𝐸, 𝑂), in place.
 * @param[in,out] word Entry: { 𝐿, 𝐻 } little-endian halves. Return: { 𝐸, 𝑂 }.
 * @optimization  [OPT-A_14] Delta swap t = (x ^ (x >> n)) & m; x ^= t ^ (t << n) exchanges
 *                bit groups in 3+3 ops. Stages n = 1, 2, 4, 8 sort each half into
 *                [odd16 | even16]; the final merge packs both halves' even bits into 𝐸 and
 *                odd bits into 𝑂 preserving bit order (𝐸 bit k = S bit 2k, 𝑂 bit k = S bit 2k+1).
 */
void VERUM_ASCON_interleave(uint32_t word[2U])
{
    uint32_t delta = (word[0U] ^ (word[0U] >> 1U)) & 0x22222222UL;
    word[0U] = word[0U] ^ delta ^ (delta << 1U);
    delta = (word[0U] ^ (word[0U] >> 2U)) & 0x0C0C0C0CUL;
    word[0U] = word[0U] ^ delta ^ (delta << 2U);
    delta = (word[0U] ^ (word[0U] >> 4U)) & 0x00F000F0UL;
    word[0U] = word[0U] ^ delta ^ (delta << 4U);
    delta = (word[0U] ^ (word[0U] >> 8U)) & 0x0000FF00UL;
    word[0U] = word[0U] ^ delta ^ (delta << 8U);

    delta = (word[1U] ^ (word[1U] >> 1U)) & 0x22222222UL;
    word[1U] = word[1U] ^ delta ^ (delta << 1U);
    delta = (word[1U] ^ (word[1U] >> 2U)) & 0x0C0C0C0CUL;
    word[1U] = word[1U] ^ delta ^ (delta << 2U);
    delta = (word[1U] ^ (word[1U] >> 4U)) & 0x00F000F0UL;
    word[1U] = word[1U] ^ delta ^ (delta << 4U);
    delta = (word[1U] ^ (word[1U] >> 8U)) & 0x0000FF00UL;
    word[1U] = word[1U] ^ delta ^ (delta << 8U);

    delta = (word[0U] & 0x0000FFFFUL) | (word[1U] << 16U);
    word[1U] = (word[0U] >> 16U) | (word[1U] & 0xFFFF0000UL);
    word[0U] = delta;
}

/**
 * @internal
 * @brief         π⁻¹: (𝐸, 𝑂) → (𝐿, 𝐻), in place.
 * @param[in,out] word Entry: { 𝐸, 𝑂 }. Return: { 𝐿, 𝐻 } little-endian halves.
 * @optimization  [OPT-A_14] 16-bit split, then π's self-inverse delta swaps in reverse
 *                order (n = 8, 4, 2, 1).
 */
void VERUM_ASCON_deinterleave(uint32_t word[2U])
{
    uint32_t delta = (word[0U] & 0x0000FFFFUL) | (word[1U] << 16U);
    word[1U] = (word[0U] >> 16U) | (word[1U] & 0xFFFF0000UL);
    word[0U] = delta;

    delta = (word[0U] ^ (word[0U] >> 8U)) & 0x0000FF00UL;
    word[0U] = word[0U] ^ delta ^ (delta << 8U);
    delta = (word[0U] ^ (word[0U] >> 4U)) & 0x00F000F0UL;
    word[0U] = word[0U] ^ delta ^ (delta << 4U);
    delta = (word[0U] ^ (word[0U] >> 2U)) & 0x0C0C0C0CUL;
    word[0U] = word[0U] ^ delta ^ (delta << 2U);
    delta = (word[0U] ^ (word[0U] >> 1U)) & 0x22222222UL;
    word[0U] = word[0U] ^ delta ^ (delta << 1U);

    delta = (word[1U] ^ (word[1U] >> 8U)) & 0x0000FF00UL;
    word[1U] = word[1U] ^ delta ^ (delta << 8U);
    delta = (word[1U] ^ (word[1U] >> 4U)) & 0x00F000F0UL;
    word[1U] = word[1U] ^ delta ^ (delta << 4U);
    delta = (word[1U] ^ (word[1U] >> 2U)) & 0x0C0C0C0CUL;
    word[1U] = word[1U] ^ delta ^ (delta << 2U);
    delta = (word[1U] ^ (word[1U] >> 1U)) & 0x22222222UL;
    word[1U] = word[1U] ^ delta ^ (delta << 1U);
}
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

/**
 * @internal
 * @ref           NIST SP 800-232 Sections 3.2 and 3.3
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         𝑝𝐶 Constant-Addition Layer; 𝑝𝑆 Substitution Layer
 * @param[in,out] state          320-bit state as ten 32-bit words.
 * @param[out]    holder         320-bit scratch buffer receiving post-S-box words.
 * @param[in]     round_constant Round constant (interleaved pair or 32-bit word).
 * @optimization  [OPT-A_3] p_C folded into the S2 ^= S1 pre-mix, saving a separate
 *                read-modify-write on state[4U] and state[5U].
 *                [OPT-A_4] Bit-sliced S-box on 32-bit words with NOT-AND (~x & y) and ~x,
 *                mapping directly to single-cycle NOT-AND (BIC/ANDN) and NOT, removing
 *                12 immediate XORs per round.
 */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
#ifndef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
VERUM_ATTR_INLINE static inline
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
void VERUM_ASCON_permute_substitution_layer(uint32_t state[10U],
                                                   uint32_t holder[10U],
                                                   const uint8_t round_constant[2U])
{
    state[0U] = state[0U] ^ state[8U];
    state[1U] = state[1U] ^ state[9U];

    state[4U] = state[4U] ^ state[2U] ^ (uint32_t) round_constant[0U];
    state[5U] = state[5U] ^ state[3U] ^ (uint32_t) round_constant[1U];

    state[8U] = state[8U] ^ state[6U];
    state[9U] = state[9U] ^ state[7U];

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
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
#ifndef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
VERUM_ATTR_INLINE static inline
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
void VERUM_ASCON_permute_substitution_layer(uint32_t state[10U],
                                                   uint32_t holder[10U],
                                                   const uint32_t round_constant)
{
    state[0U] = state[0U] ^ state[8U];
    state[1U] = state[1U] ^ state[9U];

    state[4U] = state[4U] ^ state[2U] ^ round_constant;
    state[5U] = state[5U] ^ state[3U];

    state[8U] = state[8U] ^ state[6U];
    state[9U] = state[9U] ^ state[7U];

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
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

/**
 * @internal
 * @ref          NIST SP 800-232 Section 3.4
 * @see          https://doi.org/10.6028/NIST.SP.800-232
 * @brief        𝑝𝐿 Linear Diffusion Layer: Σ𝑤(S𝑤) = S𝑤 ⊕ (S𝑤 ⋙ 𝑟1) ⊕ (S𝑤 ⋙ 𝑟2)
 * @param[out]   state  320-bit state receiving diffused words.
 * @param[in]    holder 320-bit scratch buffer holding post-substitution words.
 * @optimization [OPT-A_1] When bit-interleaved: converts 20 cross-register funnel shifts into
 *               19 single-register RORs, fusing into XOR (EOR Rd, Rn, Rm, ROR #k).
 *               When direct halves: explicit 64-bit cross-register rotations.
 */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
#ifndef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
VERUM_ATTR_INLINE static inline
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
void VERUM_ASCON_permute_linear_diffusion_layer(uint32_t state[10U],
                                                       const uint32_t holder[10U])
{
    state[0U] = holder[0U] ^ ((holder[1U] >>  9U) | (holder[1U] << 23U)) ^ ((holder[0U] >> 14U) | (holder[0U] << 18U));
    state[1U] = holder[1U] ^ ((holder[0U] >> 10U) | (holder[0U] << 22U)) ^ ((holder[1U] >> 14U) | (holder[1U] << 18U));

    state[2U] = holder[2U] ^ ((holder[3U] >> 30U) | (holder[3U] <<  2U)) ^ ((holder[3U] >> 19U) | (holder[3U] << 13U));
    state[3U] = holder[3U] ^ ((holder[2U] >> 31U) | (holder[2U] <<  1U)) ^ ((holder[2U] >> 20U) | (holder[2U] << 12U));

    state[4U] = holder[4U] ^ holder[5U] ^ ((holder[4U] >>  3U) | (holder[4U] << 29U));
    state[5U] = holder[5U] ^ ((holder[4U] >>  1U) | (holder[4U] << 31U)) ^ ((holder[5U] >>  3U) | (holder[5U] << 29U));

    state[6U] = holder[6U] ^ ((holder[6U] >>  5U) | (holder[6U] << 27U)) ^ ((holder[7U] >>  8U) | (holder[7U] << 24U));
    state[7U] = holder[7U] ^ ((holder[7U] >>  5U) | (holder[7U] << 27U)) ^ ((holder[6U] >>  9U) | (holder[6U] << 23U));

    state[8U] = holder[8U] ^ ((holder[9U] >>  3U) | (holder[9U] << 29U)) ^ ((holder[9U] >> 20U) | (holder[9U] << 12U));
    state[9U] = holder[9U] ^ ((holder[8U] >>  4U) | (holder[8U] << 28U)) ^ ((holder[8U] >> 21U) | (holder[8U] << 11U));
}
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
#ifndef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
VERUM_ATTR_INLINE static inline
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
void VERUM_ASCON_permute_linear_diffusion_layer(uint32_t state[10U],
                                                       const uint32_t holder[10U])
{
    state[0U] = holder[0U] ^ ((holder[0U] >> 19U) | (holder[1U] << 13U)) ^ ((holder[0U] >> 28U) | (holder[1U] << 4U));
    state[1U] = holder[1U] ^ ((holder[1U] >> 19U) | (holder[0U] << 13U)) ^ ((holder[1U] >> 28U) | (holder[0U] << 4U));

    state[2U] = holder[2U] ^ ((holder[2U] << 3U) | (holder[3U] >> 29U)) ^ ((holder[2U] << 25U) | (holder[3U] >> 7U));
    state[3U] = holder[3U] ^ ((holder[3U] << 3U) | (holder[2U] >> 29U)) ^ ((holder[3U] << 25U) | (holder[2U] >> 7U));

    state[4U] = holder[4U] ^ ((holder[4U] >>  1U) | (holder[5U] << 31U)) ^ ((holder[4U] >>  6U) | (holder[5U] << 26U));
    state[5U] = holder[5U] ^ ((holder[5U] >>  1U) | (holder[4U] << 31U)) ^ ((holder[5U] >>  6U) | (holder[4U] << 26U));

    state[6U] = holder[6U] ^ ((holder[6U] >> 10U) | (holder[7U] << 22U)) ^ ((holder[6U] >> 17U) | (holder[7U] << 15U));
    state[7U] = holder[7U] ^ ((holder[7U] >> 10U) | (holder[6U] << 22U)) ^ ((holder[7U] >> 17U) | (holder[6U] << 15U));

    state[8U] = holder[8U] ^ ((holder[8U] >>  7U) | (holder[9U] << 25U)) ^ ((holder[8U] << 23U) | (holder[9U] >> 9U));
    state[9U] = holder[9U] ^ ((holder[9U] >>  7U) | (holder[8U] << 25U)) ^ ((holder[9U] << 23U) | (holder[8U] >> 9U));
}
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

/**
 * @internal
 * @ref           NIST SP 800-232 Sections 3.2, 3.3, and 3.4
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         𝑝𝐿 Linear Diffusion Layer; 𝑝𝐶 Constant-Addition Layer; 𝑝𝑆 Substitution Layer
 * @param[out]    state          320-bit state buffer.
 * @param[in,out] holder         320-bit scratch buffer updated across merged rounds.
 * @param[in]     round_constant Round constant (interleaved pair or 32-bit word).
 * @optimization  [OPT-A_5] Fuses p_L of round i-1 with p_C and p_S of round i, diffusing
 *                S4 and S2 ahead of S0 and S3 so the S-box pre-mix (S0 ^= S4,
 *                S2 ^= S1 ^ C[i], S4 ^= S3) folds into the diffusion stores,
 *                eliminating inter-round state loads and stores.
 *                [OPT-A_1] Interleaved or direct-halves p_L; [OPT-A_3] p_C fold; [OPT-A_4] NOT-AND S-box.
 */
#ifdef VERUM_ASCON_BIT_INTERLEAVING_DEF
#ifndef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
VERUM_ATTR_INLINE static inline
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
void VERUM_ASCON_permute_merged(uint32_t state[10U],
                                       uint32_t holder[10U],
                                       const uint8_t round_constant[2U])
{
    state[8U] = holder[8U] ^ ((holder[9U] >>  3U) | (holder[9U] << 29U)) ^ ((holder[9U] >> 20U) | (holder[9U] << 12U));
    state[9U] = holder[9U] ^ ((holder[8U] >>  4U) | (holder[8U] << 28U)) ^ ((holder[8U] >> 21U) | (holder[8U] << 11U));

    state[0U] = (holder[0U] ^ ((holder[1U] >>  9U) | (holder[1U] << 23U)) ^ ((holder[0U] >> 14U) | (holder[0U] << 18U))) ^ state[8U];
    state[1U] = (holder[1U] ^ ((holder[0U] >> 10U) | (holder[0U] << 22U)) ^ ((holder[1U] >> 14U) | (holder[1U] << 18U))) ^ state[9U];

    state[2U] = holder[2U] ^ ((holder[3U] >> 30U) | (holder[3U] <<  2U)) ^ ((holder[3U] >> 19U) | (holder[3U] << 13U));
    state[3U] = holder[3U] ^ ((holder[2U] >> 31U) | (holder[2U] <<  1U)) ^ ((holder[2U] >> 20U) | (holder[2U] << 12U));

    state[4U] = (holder[4U] ^ holder[5U] ^ ((holder[4U] >>  3U) | (holder[4U] << 29U))) ^ (state[2U] ^ (uint32_t) round_constant[0U]);
    state[5U] = (holder[5U] ^ ((holder[4U] >>  1U) | (holder[4U] << 31U)) ^ ((holder[5U] >>  3U) | (holder[5U] << 29U))) ^ (state[3U] ^ (uint32_t) round_constant[1U]);

    state[6U] = holder[6U] ^ ((holder[6U] >>  5U) | (holder[6U] << 27U)) ^ ((holder[7U] >>  8U) | (holder[7U] << 24U));
    state[7U] = holder[7U] ^ ((holder[7U] >>  5U) | (holder[7U] << 27U)) ^ ((holder[6U] >>  9U) | (holder[6U] << 23U));

    state[8U] = state[8U] ^ state[6U];
    state[9U] = state[9U] ^ state[7U];

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
#else /* VERUM_ASCON_BIT_INTERLEAVING_DEF */
#ifndef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
VERUM_ATTR_INLINE static inline
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
void VERUM_ASCON_permute_merged(uint32_t state[10U],
                                       uint32_t holder[10U],
                                       const uint32_t round_constant)
{
    state[8U] = holder[8U] ^ ((holder[8U] >>  7U) | (holder[9U] << 25U)) ^ ((holder[8U] << 23U) | (holder[9U] >> 9U));
    state[9U] = holder[9U] ^ ((holder[9U] >>  7U) | (holder[8U] << 25U)) ^ ((holder[9U] << 23U) | (holder[8U] >> 9U));

    state[0U] = (holder[0U] ^ ((holder[0U] >> 19U) | (holder[1U] << 13U)) ^ ((holder[0U] >> 28U) | (holder[1U] << 4U))) ^ state[8U];
    state[1U] = (holder[1U] ^ ((holder[1U] >> 19U) | (holder[0U] << 13U)) ^ ((holder[1U] >> 28U) | (holder[0U] << 4U))) ^ state[9U];

    state[2U] = holder[2U] ^ ((holder[2U] << 3U) | (holder[3U] >> 29U)) ^ ((holder[2U] << 25U) | (holder[3U] >> 7U));
    state[3U] = holder[3U] ^ ((holder[3U] << 3U) | (holder[2U] >> 29U)) ^ ((holder[3U] << 25U) | (holder[2U] >> 7U));

    state[4U] = (holder[4U] ^ ((holder[4U] >>  1U) | (holder[5U] << 31U)) ^ ((holder[4U] >>  6U) | (holder[5U] << 26U))) ^ (state[2U] ^ round_constant);
    state[5U] = (holder[5U] ^ ((holder[5U] >>  1U) | (holder[4U] << 31U)) ^ ((holder[5U] >>  6U) | (holder[4U] << 26U))) ^ state[3U];

    state[6U] = holder[6U] ^ ((holder[6U] >> 10U) | (holder[7U] << 22U)) ^ ((holder[6U] >> 17U) | (holder[7U] << 15U));
    state[7U] = holder[7U] ^ ((holder[7U] >> 10U) | (holder[6U] << 22U)) ^ ((holder[7U] >> 17U) | (holder[6U] << 15U));

    state[8U] = state[8U] ^ state[6U];
    state[9U] = state[9U] ^ state[7U];

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
#endif /* VERUM_ASCON_BIT_INTERLEAVING_DEF */

#ifndef VERUM_ASCON_LOOP_UNROLL_MERGED_DEF
/**
 * @internal
 * @ref           NIST SP 800-232 Section 3
 * @see           https://doi.org/10.6028/NIST.SP.800-232
 * @brief         Permutes the 320-bit ASCON state from @p round_index through round 11.
 * @param[in,out] state       320-bit state as ten 32-bit words.
 * @param[out]    holder      320-bit scratch buffer for intermediate post-S-box values.
 * @param[in]     round_index Starting round index (0 for Ascon-p[12], 4 for Ascon-p[8]).
 * @optimization  [OPT-A_6] Noinline and shared across p[12] and p[8]; peels the initial
 *                p_C+p_S and final p_L outside the loop so the body executes only fused
 *                p_L+p_C+p_S rounds, minimizing .text footprint and I-cache pressure.
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
#endif /* VERUM_ASCON_LOOP_UNROLL_MERGED_DEF */
